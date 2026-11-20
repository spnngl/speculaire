//! NRI's runtime side, as much as a plugin needs to register: for tests that run where there is no runtime (D168).

use std::time::Duration;

use prost::Message as _;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::api::{ConfigureRequest, Empty, SynchronizeRequest};
use crate::mux::Mux;
use crate::ttrpc::{self, Call, PLUGIN_SERVICE, RUNTIME_SERVICE};

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
        let mut plugin = connections.plugin_service;
        let mut registration = connections.runtime_service;
        let session = async {
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
            // Held until the plugin closes the socket, which ends the multiplexer.
            std::future::pending::<Result<(), Error>>().await
        };
        tokio::select! {
            ended = mux.run() => ended.map_err(|e| Error(e.to_string())),
            ended = session => ended,
        }
    }
}

fn millis(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}
