//! NRI's runtime side, as much as a plugin needs to register: for tests that run where there is no runtime (D168).

use std::collections::HashMap;
use std::io;
use std::pin::pin;
use std::time::Duration;

use prost::Message as _;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};
use zerocopy::IntoBytes as _;

use crate::api::{self, ConfigureRequest, Empty, SynchronizeRequest};
use crate::mux::{ConnId, Connections, Mux};
use crate::ttrpc::{self, Call, PLUGIN_SERVICE, RUNTIME_SERVICE, code};
use crate::{Answer, MAX_PAYLOAD, create, frame};

/// What a runtime tells the plugin in `Configure`.
#[derive(Clone, Debug)]
pub struct Runtime {
    /// `runtime_name`, such as `containerd` or `cri-o`.
    pub name: String,
    /// `runtime_version`.
    pub version: String,
    /// `NRI_version`, empty for none.
    pub nri_version: String,
    /// `request_timeout`.
    pub request_timeout: Duration,
}

/// Why the runtime side ended before the plugin closed the socket.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

impl Runtime {
    /// Plays the runtime on a socket a plugin connected to, as NRI v0.12.3 does: it waits for the plugin's
    /// registration, configures it, answers the registration and synchronizes it with no pod and no container
    /// (`pkg/adaptation/plugin.go:436-459`), then returns once the plugin closes the socket.
    ///
    /// # Errors
    ///
    /// When the plugin breaks the protocol, or refuses a call.
    pub async fn serve<R, W>(&self, reader: R, writer: W) -> Result<(), Error>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let (mux, connections) = Mux::new(reader, writer);
        let session = async {
            self.register_on(connections).await?;
            // Held until the plugin closes the socket, which ends the multiplexer.
            std::future::pending::<Result<(), Error>>().await
        };
        tokio::select! {
            ended = mux.run() => ended.map_err(|e| Error(e.to_string())),
            ended = session => ended,
        }
    }

    /// Registers the plugin on `trunk` as [`Self::serve`] does, then leaves the trunk to the caller, who writes the
    /// plugin's calls with [`call`] and reads its answers with [`answer`].
    ///
    /// # Errors
    ///
    /// When the plugin breaks the protocol, or refuses a call.
    pub async fn register<T: AsyncRead + AsyncWrite + Unpin>(
        &self,
        trunk: &mut T,
    ) -> Result<(), Error> {
        let (reader, writer) = tokio::io::split(trunk);
        let (mux, connections) = Mux::new(reader, writer);
        let mut run = pin!(mux.run());
        tokio::select! {
            ended = run.as_mut() => return Err(Error(format!("the trunk ended: {ended:?}"))),
            registered = self.register_on(connections) => registered?,
        }
        // Once more, so that the registration's answer leaves the multiplexer: nothing else is written.
        let _ = tokio::time::timeout(Duration::ZERO, run).await;
        Ok(())
    }

    async fn register_on(&self, connections: Connections) -> Result<(), Error> {
        let mut plugin = connections.plugin_service;
        let mut registration = connections.runtime_service;
        let mut buf = Vec::new();
        let register = ttrpc::read_request(&mut registration, &mut buf)
            .await
            .map_err(|e| Error(format!("the registration: {e}")))?;
        if !matches!(&register.call, Call::Other { service, method } if service == RUNTIME_SERVICE && method == "RegisterPlugin")
        {
            return Err(Error(format!("not a registration: {:?}", register.call)));
        }
        let timeout = self.request_timeout;
        let configure = ConfigureRequest {
            runtime_name: self.name.clone(),
            runtime_version: self.version.clone(),
            registration_timeout: millis(crate::REGISTRATION_TIMEOUT),
            request_timeout: millis(timeout),
            nri_version: self.nri_version.clone(),
        };
        ttrpc::call(
            &mut plugin,
            1,
            (PLUGIN_SERVICE, "Configure"),
            &configure,
            timeout,
        )
        .await
        .map_err(|e| Error(format!("Configure: {e}")))?;
        ttrpc::respond(
            &mut registration,
            &mut buf,
            register.stream,
            Ok(Empty {}.encode_to_vec()),
        )
        .await
        .map_err(|e| Error(format!("the registration's answer: {e}")))?;
        let synchronize = SynchronizeRequest::default();
        ttrpc::call(
            &mut plugin,
            3,
            (PLUGIN_SERVICE, "Synchronize"),
            &synchronize,
            timeout,
        )
        .await
        .map_err(|e| Error(format!("Synchronize: {e}")))?;
        Ok(())
    }
}

/// The trunk's bytes of a call of the plugin service's `method` on `stream`, whose request is the protobuf `payload`
/// and which the runtime waits `timeout` for: one frame, as the runtime writes it.
///
/// # Panics
///
/// When the call is over [`MAX_PAYLOAD`].
#[must_use]
pub fn call(stream: u32, method: &str, payload: &[u8], timeout: Duration) -> Vec<u8> {
    let message = ttrpc::request_message(stream, method, payload, timeout)
        .expect("a call within ttrpc's maximum");
    let length = u32::try_from(message.len())
        .ok()
        .filter(|&length| length <= MAX_PAYLOAD)
        .expect("a call within a frame's maximum");
    let mut frame = frame::Header::new(ConnId::PluginService.id(), length)
        .as_bytes()
        .to_vec();
    frame.extend_from_slice(&message);
    frame
}

/// Reads the plugin's answer to the next call from `trunk`, through `buf`, which is kept between calls.
///
/// # Errors
///
/// When the trunk fails, or carries what is no answer to a `CreateContainer`.
pub async fn answer<R: AsyncRead + Unpin>(trunk: &mut R, buf: &mut Vec<u8>) -> io::Result<Answer> {
    buf.clear();
    loop {
        let mut header = frame::Header::default();
        trunk.read_exact(header.as_mut_bytes()).await?;
        let length = header
            .length()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let start = buf.len();
        buf.resize(start + length, 0);
        trunk
            .read_exact(buf.get_mut(start..).unwrap_or_default())
            .await?;
        if header.conn() != ConnId::PluginService.id() {
            buf.truncate(start);
            continue;
        }
        let Some(response) = ttrpc::response_status(buf) else {
            continue;
        };
        let status = response?;
        return match status.code {
            code::OK => Ok(Answer::Allow),
            code::FAILED_PRECONDITION => Ok(Answer::Reject(status.message)),
            code => Err(io::Error::other(format!("code {code}: {}", status.message))),
        };
    }
}

/// Whether `read` holds the fields of `decoded` it reads: what prost decoded of the same `CreateContainerRequest`.
#[must_use]
pub fn agrees(read: &create::Request<'_>, decoded: &api::CreateContainerRequest) -> bool {
    fn same(annotations: create::Annotations<'_>, decoded: &HashMap<String, String>) -> bool {
        let read: HashMap<&str, &str> = annotations.iter().collect();
        read.len() == decoded.len()
            && decoded
                .iter()
                .all(|(key, value)| annotations.get(key) == Some(value.as_str()))
    }
    let pods = match (read.pod, &decoded.pod) {
        (None, None) => true,
        (Some(pod), Some(decoded)) => {
            pod.name == decoded.name
                && pod.namespace == decoded.namespace
                && pod.runtime_handler == decoded.runtime_handler
                && same(pod.annotations, &decoded.annotations)
        }
        _ => false,
    };
    let containers = match (read.container, &decoded.container) {
        (None, None) => true,
        (Some(container), Some(decoded)) => {
            container.id == decoded.id
                && container.name == decoded.name
                && same(container.annotations, &decoded.annotations)
                && container.image == create::Container::from(decoded).image
        }
        _ => false,
    };
    pods && containers
}

fn millis(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use std::future::ready;

    use tokio::time::Instant;

    use super::*;
    use crate::api::{Container, CreateContainerRequest, PodSandbox};
    use crate::{Configuration, Handler};

    /// Allows the container named `allowed`, and rejects every other.
    struct Allowing;

    impl Handler for Allowing {
        fn configure(&self, _: &Configuration) {}

        fn synchronize(&self, _: Vec<PodSandbox>, _: Vec<Container>) {}

        fn create_container(
            &self,
            request: &create::Request<'_>,
            _: Instant,
        ) -> impl Future<Output = Answer> + Send {
            ready(self.overloaded(request))
        }

        fn overloaded(&self, request: &create::Request<'_>) -> Answer {
            match request.container {
                Some(container) if container.name == "allowed" => Answer::Allow,
                _ => Answer::Reject("not allowed".to_owned()),
            }
        }
    }

    fn create(name: &str) -> Vec<u8> {
        let container = Container {
            name: name.to_owned(),
            ..Container::default()
        };
        CreateContainerRequest {
            pod: None,
            container: Some(container),
        }
        .encode_to_vec()
    }

    #[tokio::test]
    async fn a_registered_trunk_carries_calls_and_their_answers() {
        let runtime = Runtime {
            name: "containerd".to_owned(),
            version: "2.4.2".to_owned(),
            nri_version: "v0.12.3".to_owned(),
            request_timeout: Duration::from_secs(2),
        };
        let (mut trunk, plugin) = tokio::io::duplex(1 << 16);
        let (reader, writer) = tokio::io::split(plugin);
        let plugin = tokio::spawn(async move {
            crate::serve(reader, writer, &Allowing, Duration::from_secs(5)).await
        });
        runtime
            .register(&mut trunk)
            .await
            .expect("the plugin registers");
        let mut buf = Vec::new();
        let calls = [
            (11, "CreateContainer", create("allowed")),
            (13, "CreateContainer", create("other")),
            (15, "UpdateContainer", Vec::new()),
        ];
        let mut answers = Vec::new();
        for (stream, method, payload) in calls {
            let call = call(stream, method, &payload, Duration::from_secs(2));
            tokio::io::AsyncWriteExt::write_all(&mut trunk, &call)
                .await
                .expect("the call");
            let answer = tokio::time::timeout(Duration::from_secs(5), answer(&mut trunk, &mut buf));
            answers.push(
                answer
                    .await
                    .expect("an answer in time")
                    .map_err(|err| err.to_string()),
            );
        }
        assert_eq!(
            answers,
            [
                Ok(Answer::Allow),
                Ok(Answer::Reject("not allowed".to_owned())),
                Err(format!("code 12: method {PLUGIN_SERVICE}/UpdateContainer")),
            ]
        );
        plugin.abort();
    }
}
