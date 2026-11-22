//! NRI's plugin protocol (D9, D166): registers, is configured, collects the runtime's state and answers each
//! CreateContainer through a [`Handler`], which the runtime waits for.

// The protocol is ported from containerd/nri v0.12.3 `pkg/stub/stub.go:397-467` (start), `:604-623` (register),
// `:658-715` (Configure), `:717-766` (Synchronize) and `:768-774` (Shutdown).

use std::future::Future;
use std::mem;
use std::pin::pin;
use std::time::Duration;

use futures_util::future::{self, Either};
use futures_util::stream::{FuturesUnordered, StreamExt};
use prost::Message as _;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

use crate::api::{
    ConfigureRequest, ConfigureResponse, Container, CreateContainerResponse, Empty, PodSandbox,
    RegisterPluginRequest, SynchronizeRequest, SynchronizeResponse,
};
use crate::create;
use crate::mux::{Connection, Connections, Mux, MuxError};
use crate::ttrpc::{self, Call, CallError, Request, RequestError, Status, code};
use crate::version::{self, InferError};

/// The name the plugin registers under, which `required_plugins` names (D9).
pub const NAME: &str = "speculaire";

/// The plugin's index: the runtime calls plugins in ascending index order and names this one `50-speculaire` (D9).
pub const INDEX: &str = "50";

/// The most CreateContainer requests answered at once; past it, a request gets [`Handler::overloaded`] at once.
pub const MAX_IN_FLIGHT: usize = 256;

/// How long the plugin waits for its registration, as NRI's stub does by default (`pkg/api/timeouts.go:24`).
pub const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the runtime waits for an answer until Configure says (`DefaultPluginRequestTimeout`,
/// `pkg/api/timeouts.go:27`).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// The NRI version whose protocol this crate speaks, which the plugin registers with.
const NRI_VERSION: &str = "v0.12.3";

/// The events the plugin subscribes to: CreateContainer alone, bit `CREATE_CONTAINER - 1` (`api.proto:377`).
const EVENTS: i32 = 1 << (4 - 1);

/// What the runtime tells the plugin of itself at Configure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Configuration {
    /// The runtime's name: `containerd` or `cri-o` (D64).
    pub runtime_name: String,
    /// The runtime's version.
    pub runtime_version: String,
    /// The NRI version the runtime links.
    pub nri_version: NriVersion,
    /// How long the runtime waits for a plugin to register.
    pub registration_timeout: Duration,
    /// How long the runtime waits for each answer.
    pub request_timeout: Duration,
}

/// The NRI version a runtime links (D15, D64).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NriVersion {
    /// As the runtime announced it.
    Announced(String),
    /// Inferred from the runtime's name and version, as NRI does, since the runtime announced none.
    Inferred(&'static str),
    /// Neither announced nor inferred: what the runtime announced (empty, [`version::UNKNOWN`] or
    /// [`version::DEVEL`]), and why inference failed.
    Unknown {
        /// What the runtime announced.
        announced: String,
        /// Why inference failed.
        error: InferError,
    },
}

/// A handler's answer to a CreateContainer request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The container may be created.
    Allow,
    /// The container must not be created, for the reason the runtime reports.
    Reject(String),
}

/// What the plugin calls on the runtime's requests. It knows no runtime: [`Configuration`] names it.
pub trait Handler: Sync {
    /// The runtime configured the plugin; called before any other method, once per session.
    fn configure(&self, configuration: &Configuration);

    /// Every pod and container the runtime had when the plugin registered, each once, collected from every
    /// Synchronize request. It returns quickly: the plugin reads no other request meanwhile.
    fn synchronize(&self, pods: Vec<PodSandbox>, containers: Vec<Container>);

    /// The answer to a CreateContainer request, which the runtime stops waiting for at `deadline`. Past it, the
    /// future is dropped and the runtime gets `DEADLINE_EXCEEDED`.
    fn create_container(
        &self,
        request: &create::Request<'_>,
        deadline: Instant,
    ) -> impl Future<Output = Answer> + Send;

    /// The answer to a CreateContainer request when the handler has it without waiting; none hands the request to
    /// [`Self::create_container`]. Answered here, a request costs neither a task nor a copy (D189).
    fn answer_now(&self, _request: &create::Request<'_>) -> Option<Answer> {
        None
    }

    /// The answer, given at once, to a CreateContainer request past [`MAX_IN_FLIGHT`] requests answered at once.
    fn overloaded(&self, request: &create::Request<'_>) -> Answer;
}

/// Why a session ended.
#[derive(Debug, thiserror::Error)]
pub enum End {
    /// The runtime sent Shutdown, then closed the socket.
    #[error("the runtime shut down")]
    Shutdown,
    /// The runtime closed the socket without Shutdown.
    #[error("the runtime closed the connection")]
    Closed,
    /// The socket failed, or the runtime broke the multiplexer's framing.
    #[error("the connection was lost: {0}")]
    Lost(#[from] MuxError),
    /// The registration failed.
    #[error("registration failed: {0}")]
    Registration(#[from] RegistrationError),
    /// The runtime sent a ttrpc message over [`ttrpc::MAX_MESSAGE`], which its ttrpc never sends.
    #[error(
        "the runtime sent a ttrpc message of {length} bytes, over the maximum of {}",
        ttrpc::MAX_MESSAGE
    )]
    Oversize {
        /// The length the message's header claims.
        length: u32,
    },
}

/// Why the registration failed.
#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    /// The runtime did not answer within the registration timeout.
    #[error("no answer within {0:?}")]
    Timeout(Duration),
    /// The runtime refused the plugin.
    #[error("refused with code {code}: {message}")]
    Refused {
        /// The gRPC status code.
        code: i32,
        /// The runtime's reason.
        message: String,
    },
}

/// Plays the plugin on the socket read by `reader` and written by `writer` until the session ends.
///
/// It registers within `registration_timeout` while it serves the runtime, since the runtime may configure the plugin
/// before it answers the registration. It answers CreateContainer requests concurrently, at most [`MAX_IN_FLIGHT`] at
/// once.
pub async fn serve<R, W, H>(
    reader: R,
    writer: W,
    handler: &H,
    registration_timeout: Duration,
) -> End
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    H: Handler,
{
    let (mux, connections) = Mux::new(reader, writer);
    let mut run = pin!(mux.run());
    let mut session = pin!(session(connections, handler, registration_timeout));
    match future::select(run.as_mut(), session.as_mut()).await {
        Either::Left((Err(err), _)) => End::Lost(err),
        // The trunk ended: the session reads the end of its connection next, and says whether Shutdown came first.
        Either::Left((Ok(()), _)) => trunk_end(session.await, Ok(())),
        Either::Right((Stop::Trunk { shutdown }, _)) => {
            trunk_end(Stop::Trunk { shutdown }, run.await)
        }
        Either::Right((Stop::Failed(end), _)) => end,
    }
}

fn trunk_end(stop: Stop, run: Result<(), MuxError>) -> End {
    match (stop, run) {
        (_, Err(err)) => End::Lost(err),
        (Stop::Failed(end), Ok(())) => end,
        (Stop::Trunk { shutdown: true }, Ok(())) => End::Shutdown,
        (Stop::Trunk { shutdown: false }, Ok(())) => End::Closed,
    }
}

/// Why a session stopped before the multiplexer.
enum Stop {
    /// The plugin's connection ended or failed, which the multiplexer explains; after Shutdown or not.
    Trunk { shutdown: bool },
    /// The session ended for a reason of its own.
    Failed(End),
}

async fn session<H: Handler>(
    connections: Connections,
    handler: &H,
    registration_timeout: Duration,
) -> Stop {
    let Connections {
        plugin_service,
        runtime_service,
    } = connections;
    let mut serving = pin!(serve_requests(plugin_service, handler));
    match future::select(
        pin!(register(runtime_service, registration_timeout)),
        serving.as_mut(),
    )
    .await
    {
        // A connection fails only once the trunk ends, which the plugin's service reads next and the multiplexer
        // explains.
        Either::Left((Registered::Yes | Registered::TrunkEnded, _)) => serving.await,
        Either::Left((Registered::No(err), _)) => Stop::Failed(End::Registration(err)),
        Either::Right((stop, _)) => stop,
    }
}

/// How the registration went.
enum Registered {
    Yes,
    No(RegistrationError),
    /// The connection failed before the answer.
    TrunkEnded,
}

/// Registers the plugin, then drops the runtime's service: the plugin calls nothing else.
async fn register(mut runtime_service: Connection, timeout: Duration) -> Registered {
    let request = RegisterPluginRequest {
        plugin_name: NAME.to_owned(),
        plugin_idx: INDEX.to_owned(),
        nri_version: NRI_VERSION.to_owned(),
    };
    let method = (ttrpc::RUNTIME_SERVICE, "RegisterPlugin");
    let answer = ttrpc::call(&mut runtime_service, 1, method, &request, timeout);
    match tokio::time::timeout(timeout, answer).await {
        Err(_) => Registered::No(RegistrationError::Timeout(timeout)),
        Ok(Ok(_)) => Registered::Yes,
        Ok(Err(CallError::Status(Status { code, message }))) => {
            Registered::No(RegistrationError::Refused { code, message })
        }
        Ok(Err(CallError::Io(_))) => Registered::TrunkEnded,
    }
}

/// The session's state between requests.
struct Session {
    /// How long the runtime waits for an answer when its request does not say.
    request_timeout: Duration,
    /// The Synchronize requests' pods and containers until the last.
    pods: Vec<PodSandbox>,
    containers: Vec<Container>,
    shutdown: bool,
}

/// What the plugin's service waited for: an answer to write, or the next request read.
enum Event<'a> {
    Answered((u32, Reply)),
    Read(Result<Request<'a>, RequestError>),
}

/// Serves NRI's plugin service until the connection ends or a request cannot be read.
async fn serve_requests<H: Handler>(plugin_service: Connection, handler: &H) -> Stop {
    let (reader, mut writer) = tokio::io::split(plugin_service);
    // Cancel safe: a message read halfway is kept while an answer is written.
    let mut requests = ttrpc::Reader::new(reader);
    let mut in_flight = FuturesUnordered::new();
    let mut buf = Vec::new();
    let mut session = Session {
        request_timeout: REQUEST_TIMEOUT,
        pods: Vec::new(),
        containers: Vec::new(),
        shutdown: false,
    };
    loop {
        let event = tokio::select! {
            biased;
            Some(answered) = in_flight.next(), if !in_flight.is_empty() => Event::Answered(answered),
            read = requests.next() => Event::Read(read),
        };
        let (stream, answer) = match event {
            Event::Answered(answered) => answered,
            Event::Read(Err(RequestError::Io(_))) => {
                return Stop::Trunk {
                    shutdown: session.shutdown,
                };
            }
            Event::Read(Err(RequestError::Oversize { length })) => {
                return Stop::Failed(End::Oversize { length });
            }
            Event::Read(Err(RequestError::Decode { stream, source })) => {
                (stream, Err(unmarshal(source)))
            }
            Event::Read(Ok(Request {
                stream,
                timeout,
                call,
            })) => match call {
                Call::CreateContainer(payload) => match create::Request::read(payload) {
                    Err(err) => (stream, Err(unmarshal(err))),
                    Ok(request) => match handler.answer_now(&request) {
                        Some(answer) => (stream, reply(answer)),
                        None if in_flight.len() >= MAX_IN_FLIGHT => {
                            (stream, reply(handler.overloaded(&request)))
                        }
                        None => {
                            let deadline =
                                Instant::now() + timeout.unwrap_or(session.request_timeout);
                            // The request outlives the message it was read from.
                            let payload = payload.to_vec();
                            in_flight.push(async move {
                                let request = create::Request::read(&payload)
                                    .expect("the request read above");
                                let answer = tokio::time::timeout_at(
                                    deadline,
                                    handler.create_container(&request, deadline),
                                );
                                (
                                    stream,
                                    answer
                                        .await
                                        .map_or_else(|_| Err(deadline_exceeded()), reply),
                                )
                            });
                            continue;
                        }
                    },
                },
                Call::Configure(request) => (stream, Ok(session.configure(request, handler))),
                Call::Synchronize(request) => (stream, Ok(session.synchronize(request, handler))),
                Call::Shutdown => {
                    session.shutdown = true;
                    (stream, Ok(Empty {}.encode_to_vec()))
                }
                Call::Other { service, method } => (
                    stream,
                    Err(ttrpc::status(
                        code::UNIMPLEMENTED,
                        format!("method {service}/{method}"),
                    )),
                ),
            },
        };
        if ttrpc::respond(&mut writer, &mut buf, stream, answer)
            .await
            .is_err()
        {
            return Stop::Trunk {
                shutdown: session.shutdown,
            };
        }
    }
}

/// The refusal of a request that does not decode, in ttrpc's words (v1.2.7 `server.go:458`).
fn unmarshal(err: impl std::fmt::Display) -> Status {
    ttrpc::status(
        code::INVALID_ARGUMENT,
        format!("unmarshal request error: {err}"),
    )
}

/// A call's answer: a response's protobuf or a refusal.
type Reply = Result<Vec<u8>, Status>;

impl Session {
    /// Records the configuration, hands it to `handler` and subscribes to CreateContainer alone.
    fn configure<H: Handler>(&mut self, request: ConfigureRequest, handler: &H) -> Vec<u8> {
        let configuration = configuration(request);
        self.request_timeout = configuration.request_timeout;
        handler.configure(&configuration);
        ConfigureResponse { events: EVENTS }.encode_to_vec()
    }

    /// Collects one part of the runtime's state, and hands the whole to `handler` with the last.
    fn synchronize<H: Handler>(&mut self, request: SynchronizeRequest, handler: &H) -> Vec<u8> {
        self.pods.extend(request.pods);
        self.containers.extend(request.containers);
        if !request.more {
            handler.synchronize(mem::take(&mut self.pods), mem::take(&mut self.containers));
        }
        // NRI closes a plugin whose answer to a split request is not the request's `more`, or carries updates
        // (`pkg/adaptation/plugin.go:536-542`).
        SynchronizeResponse { more: request.more }.encode_to_vec()
    }
}

/// The refusal of a request its handler did not answer by its deadline.
fn deadline_exceeded() -> Status {
    ttrpc::status(
        code::DEADLINE_EXCEEDED,
        "no answer by the request's deadline",
    )
}

/// A CreateContainer answer as ttrpc carries it: a rejection is the call's error, which the runtime reports.
fn reply(answer: Answer) -> Reply {
    match answer {
        Answer::Allow => Ok(CreateContainerResponse {}.encode_to_vec()),
        Answer::Reject(reason) => Err(ttrpc::status(code::FAILED_PRECONDITION, reason)),
    }
}

/// Configure's request read: the runtime's NRI version inferred when unannounced, as NRI's stub does
/// (`pkg/stub/stub.go:671-680`).
fn configuration(request: ConfigureRequest) -> Configuration {
    let ConfigureRequest {
        runtime_name,
        runtime_version,
        registration_timeout,
        request_timeout,
        nri_version,
    } = request;
    let nri_version = match nri_version.as_str() {
        "" | version::UNKNOWN | version::DEVEL => {
            match version::infer(&runtime_name, &runtime_version) {
                Ok(inferred) => NriVersion::Inferred(inferred),
                Err(error) => NriVersion::Unknown {
                    announced: nri_version,
                    error,
                },
            }
        }
        _ => NriVersion::Announced(nri_version),
    };
    let millis = |millis: i64| Duration::from_millis(u64::try_from(millis).unwrap_or(0));
    Configuration {
        runtime_name,
        runtime_version,
        nri_version,
        registration_timeout: millis(registration_timeout),
        request_timeout: millis(request_timeout),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::io::AsyncWriteExt;
    use tokio::task::JoinHandle;

    use super::*;
    use crate::api::CreateContainerRequest;
    use crate::ttrpc::proto::Response;

    const SECOND: Duration = Duration::from_secs(1);

    /// Records what it is given, and answers by container name: `now` at once with a rejection, `hold` never, `slow`
    /// after a second, `reject` with a rejection, any other with Allow.
    #[derive(Debug, Default)]
    struct Recorder {
        configured: Mutex<Vec<Configuration>>,
        synchronized: Mutex<Vec<(Vec<PodSandbox>, Vec<Container>)>>,
        /// Each CreateContainer's deadline, from when the handler was called.
        deadlines: Mutex<Vec<Duration>>,
    }

    impl Handler for Recorder {
        fn configure(&self, configuration: &Configuration) {
            self.configured.lock().unwrap().push(configuration.clone());
        }

        fn synchronize(&self, pods: Vec<PodSandbox>, containers: Vec<Container>) {
            self.synchronized.lock().unwrap().push((pods, containers));
        }

        fn create_container(
            &self,
            request: &create::Request<'_>,
            deadline: Instant,
        ) -> impl Future<Output = Answer> + Send {
            self.deadlines
                .lock()
                .unwrap()
                .push(deadline - Instant::now());
            let name = request
                .container
                .map(|c| c.name.to_owned())
                .unwrap_or_default();
            async move {
                match name.as_str() {
                    "hold" => future::pending().await,
                    "slow" => {
                        tokio::time::sleep(SECOND).await;
                        Answer::Allow
                    }
                    "reject" => Answer::Reject("rejected".to_owned()),
                    _ => Answer::Allow,
                }
            }
        }

        fn answer_now(&self, request: &create::Request<'_>) -> Option<Answer> {
            let now = request.container.is_some_and(|c| c.name == "now");
            now.then(|| Answer::Reject("at once".to_owned()))
        }

        fn overloaded(&self, _: &create::Request<'_>) -> Answer {
            Answer::Reject("overloaded".to_owned())
        }
    }

    /// The runtime's side of a session with [`serve`], over an in-memory socket.
    struct Runtime {
        plugin_service: Connection,
        registration: Connection,
        buf: Vec<u8>,
        stream: u32,
        mux: JoinHandle<Result<(), MuxError>>,
        end: JoinHandle<End>,
    }

    impl Runtime {
        fn start(handler: &Arc<Recorder>, registration_timeout: Duration) -> Self {
            let (plugin, runtime) = tokio::io::duplex(1 << 16);
            let (reader, writer) = tokio::io::split(plugin);
            let handler = Arc::clone(handler);
            let end = tokio::spawn(async move {
                serve(reader, writer, &*handler, registration_timeout).await
            });
            let (reader, writer) = tokio::io::split(runtime);
            let (mux, connections) = Mux::new(reader, writer);
            Self {
                plugin_service: connections.plugin_service,
                registration: connections.runtime_service,
                buf: Vec::new(),
                stream: 1,
                mux: tokio::spawn(mux.run()),
                end,
            }
        }

        /// A runtime that has registered the plugin.
        async fn registered(handler: &Arc<Recorder>) -> Self {
            let mut runtime = Self::start(handler, REGISTRATION_TIMEOUT);
            runtime.register(Ok(())).await;
            runtime
        }

        async fn register(&mut self, answer: Result<(), Status>) {
            let mut requests = ttrpc::Reader::new(&mut self.registration);
            let request = requests.next().await.unwrap();
            assert_eq!(
                request.call,
                Call::Other {
                    service: ttrpc::RUNTIME_SERVICE,
                    method: "RegisterPlugin"
                }
            );
            let stream = request.stream;
            drop(requests);
            let answer = answer.map(|()| Empty {}.encode_to_vec());
            ttrpc::respond(&mut self.registration, &mut self.buf, stream, answer)
                .await
                .unwrap();
        }

        /// Sends a request for `method` and returns its stream; `timeout` zero leaves the plugin's default.
        async fn send(
            &mut self,
            method: &str,
            request: &impl prost::Message,
            timeout: Duration,
        ) -> u32 {
            let stream = self.stream;
            self.stream += 2;
            let method = (ttrpc::PLUGIN_SERVICE, method);
            ttrpc::write_request(
                &mut self.plugin_service,
                &mut self.buf,
                stream,
                method,
                request,
                timeout,
            )
            .await
            .unwrap();
            stream
        }

        async fn answer(&mut self) -> (u32, Response) {
            ttrpc::read_response(&mut self.plugin_service, &mut self.buf)
                .await
                .unwrap()
        }

        /// Calls `method` and returns its answer's status code and message.
        async fn call(
            &mut self,
            method: &str,
            request: &impl prost::Message,
        ) -> (i32, String, Vec<u8>) {
            let stream = self.send(method, request, Duration::ZERO).await;
            let (answered, response) = self.answer().await;
            assert_eq!(answered, stream);
            let status = response.status.unwrap();
            (status.code, status.message, response.payload)
        }

        /// Closes the socket and returns how the plugin's session ended.
        async fn close(self) -> End {
            self.mux.abort();
            self.end.await.unwrap()
        }
    }

    fn create(name: &str) -> CreateContainerRequest {
        CreateContainerRequest {
            pod: Some(PodSandbox::default()),
            container: Some(Container {
                name: name.to_owned(),
                ..Container::default()
            }),
        }
    }

    fn pod(id: &str) -> PodSandbox {
        PodSandbox {
            id: id.to_owned(),
            ..PodSandbox::default()
        }
    }

    fn container(id: &str) -> Container {
        Container {
            id: id.to_owned(),
            ..Container::default()
        }
    }

    #[tokio::test]
    async fn a_session_is_configured_synchronized_asked_and_shut_down() {
        let recorder = Arc::new(Recorder::default());
        let mut runtime = Runtime::registered(&recorder).await;
        let configure = ConfigureRequest {
            runtime_name: "cri-o".to_owned(),
            runtime_version: "v1.35.10".to_owned(),
            registration_timeout: 5000,
            request_timeout: 1500,
            nri_version: String::new(),
        };
        let (code, _, payload) = runtime.call("Configure", &configure).await;
        assert_eq!(code, code::OK);
        assert_eq!(
            ConfigureResponse::decode(payload.as_slice())
                .unwrap()
                .events,
            8
        );
        let parts = [
            SynchronizeRequest {
                pods: vec![pod("a")],
                containers: vec![container("1")],
                more: true,
            },
            SynchronizeRequest {
                pods: vec![pod("b")],
                containers: vec![],
                more: true,
            },
            SynchronizeRequest {
                pods: vec![],
                containers: vec![container("2")],
                more: false,
            },
        ];
        for part in &parts {
            let (code, _, payload) = runtime.call("Synchronize", part).await;
            assert_eq!(code, code::OK);
            let response = SynchronizeResponse::decode(payload.as_slice()).unwrap();
            assert_eq!(response.more, part.more);
            assert_eq!(recorder.synchronized.lock().unwrap().is_empty(), part.more);
        }
        let (code, message, _) = runtime.call("CreateContainer", &create("reject")).await;
        assert_eq!(
            (code, message.as_str()),
            (code::FAILED_PRECONDITION, "rejected")
        );
        let (code, _, _) = runtime.call("CreateContainer", &create("nginx")).await;
        assert_eq!(code, code::OK);
        let (code, message, _) = runtime.call("UpdateContainer", &Empty {}).await;
        assert_eq!(code, code::UNIMPLEMENTED, "{message}");
        let (code, _, _) = runtime.call("Shutdown", &Empty {}).await;
        assert_eq!(code, code::OK);
        assert!(matches!(runtime.close().await, End::Shutdown));

        assert_eq!(
            *recorder.configured.lock().unwrap(),
            [Configuration {
                runtime_name: "cri-o".to_owned(),
                runtime_version: "v1.35.10".to_owned(),
                nri_version: NriVersion::Inferred("v0.11.0"),
                registration_timeout: Duration::from_secs(5),
                request_timeout: Duration::from_millis(1500),
            }]
        );
        assert_eq!(
            *recorder.synchronized.lock().unwrap(),
            [(
                vec![pod("a"), pod("b")],
                vec![container("1"), container("2")]
            )]
        );
        let deadlines = recorder.deadlines.lock().unwrap();
        assert!(
            deadlines
                .iter()
                .all(|d| *d <= Duration::from_millis(1500) && *d > SECOND),
            "{deadlines:?}"
        );
    }

    #[test]
    fn configure_infers_the_nri_version_only_when_unannounced() {
        let read = |name: &str, version: &str, nri: &str| {
            configuration(ConfigureRequest {
                runtime_name: name.to_owned(),
                runtime_version: version.to_owned(),
                registration_timeout: -1,
                request_timeout: 2000,
                nri_version: nri.to_owned(),
            })
        };
        let announced = read("containerd", "v2.4.2", "v0.12.3");
        assert_eq!(
            announced.nri_version,
            NriVersion::Announced("v0.12.3".to_owned())
        );
        assert_eq!(announced.registration_timeout, Duration::ZERO);
        assert_eq!(announced.request_timeout, Duration::from_secs(2));
        for nri in ["", version::UNKNOWN, version::DEVEL] {
            assert_eq!(
                read("containerd", "v2.4.2", nri).nri_version,
                NriVersion::Inferred("v0.11.0")
            );
            assert_eq!(
                read("docker", "v1", nri).nri_version,
                NriVersion::Unknown {
                    announced: nri.to_owned(),
                    error: InferError::UnknownRuntime("docker".to_owned())
                }
            );
        }
    }

    #[tokio::test]
    async fn a_request_sent_after_a_slow_one_is_answered_first() {
        let recorder = Arc::new(Recorder::default());
        let mut runtime = Runtime::registered(&recorder).await;
        let slow = runtime
            .send("CreateContainer", &create("slow"), 5 * SECOND)
            .await;
        let sent = Instant::now();
        let fast = runtime
            .send("CreateContainer", &create("nginx"), 5 * SECOND)
            .await;
        assert_eq!(runtime.answer().await.0, fast);
        assert!(
            sent.elapsed() < Duration::from_millis(50),
            "{:?}",
            sent.elapsed()
        );
        assert_eq!(runtime.answer().await.0, slow);
        assert!(
            sent.elapsed() >= Duration::from_millis(900),
            "{:?}",
            sent.elapsed()
        );
        assert!(matches!(runtime.close().await, End::Closed));
    }

    #[tokio::test]
    async fn past_max_in_flight_a_request_is_overloaded_and_past_its_deadline_refused() {
        let recorder = Arc::new(Recorder::default());
        let mut runtime = Runtime::registered(&recorder).await;
        for _ in 0..MAX_IN_FLIGHT {
            runtime
                .send("CreateContainer", &create("hold"), 60 * SECOND)
                .await;
        }
        let sent = Instant::now();
        let over = runtime
            .send("CreateContainer", &create("hold"), 60 * SECOND)
            .await;
        let (answered, response) = runtime.answer().await;
        assert!(
            sent.elapsed() < Duration::from_millis(50),
            "{:?}",
            sent.elapsed()
        );
        assert_eq!(answered, over);
        assert_eq!(
            response.status.unwrap(),
            ttrpc::status(code::FAILED_PRECONDITION, "overloaded")
        );
        let now = runtime
            .send("CreateContainer", &create("now"), 60 * SECOND)
            .await;
        let (answered, response) = runtime.answer().await;
        assert_eq!(answered, now, "an answer at once needs no room");
        assert_eq!(
            response.status.unwrap(),
            ttrpc::status(code::FAILED_PRECONDITION, "at once")
        );
        assert_eq!(recorder.deadlines.lock().unwrap().len(), MAX_IN_FLIGHT);

        let mut runtime = Runtime::registered(&recorder).await;
        let held = runtime
            .send(
                "CreateContainer",
                &create("hold"),
                Duration::from_millis(100),
            )
            .await;
        let (answered, response) = runtime.answer().await;
        assert_eq!(answered, held);
        assert_eq!(response.status.unwrap().code, code::DEADLINE_EXCEEDED);
    }

    #[tokio::test]
    async fn a_request_that_does_not_decode_is_refused_and_the_session_goes_on() {
        let recorder = Arc::new(Recorder::default());
        let mut runtime = Runtime::registered(&recorder).await;
        // Field 2 as a number, where ConfigureRequest has a string and CreateContainerRequest a message.
        let wrong = ConfigureResponse { events: 5 };
        let (code, _, _) = runtime.call("Configure", &wrong).await;
        assert_eq!(code, code::INVALID_ARGUMENT);
        let (code, _, _) = runtime.call("CreateContainer", &wrong).await;
        assert_eq!(code, code::INVALID_ARGUMENT);
        let (code, _, _) = runtime.call("CreateContainer", &create("nginx")).await;
        assert_eq!(code, code::OK);
    }

    #[tokio::test]
    async fn a_refused_or_unanswered_registration_ends_the_session() {
        let recorder = Arc::new(Recorder::default());
        let mut runtime = Runtime::start(&recorder, REGISTRATION_TIMEOUT);
        runtime
            .register(Err(ttrpc::status(code::FAILED_PRECONDITION, "no")))
            .await;
        let end = runtime.end.await.unwrap();
        assert!(
            matches!(&end, End::Registration(RegistrationError::Refused { code: 9, message }) if message == "no"),
            "{end}"
        );

        let timeout = Duration::from_millis(50);
        let runtime = Runtime::start(&recorder, timeout);
        let started = Instant::now();
        let end = runtime.end.await.unwrap();
        assert!(
            matches!(end, End::Registration(RegistrationError::Timeout(t)) if t == timeout),
            "{end}"
        );
        assert!(started.elapsed() >= timeout);
    }

    #[tokio::test]
    async fn a_socket_closed_before_the_registration_is_answered_ends_the_session_as_closed() {
        let recorder = Arc::new(Recorder::default());
        let runtime = Runtime::start(&recorder, REGISTRATION_TIMEOUT);
        let end = runtime.close().await;
        assert!(matches!(end, End::Closed), "{end}");
    }

    #[tokio::test]
    async fn an_oversized_message_ends_the_session() {
        let recorder = Arc::new(Recorder::default());
        let mut runtime = Runtime::registered(&recorder).await;
        let length = ttrpc::MAX_MESSAGE + 1;
        let mut header = length.to_be_bytes().to_vec();
        header.extend([0, 0, 0, 1, 1, 0]);
        runtime.plugin_service.write_all(&header).await.unwrap();
        let end = runtime.end.await.unwrap();
        assert!(
            matches!(end, End::Oversize { length: l } if l == length),
            "{end}"
        );
    }

    #[tokio::test]
    async fn a_broken_trunk_ends_the_session_as_lost() {
        let (plugin, mut runtime) = tokio::io::duplex(1 << 16);
        let (reader, writer) = tokio::io::split(plugin);
        let recorder = Recorder::default();
        let end = async { serve(reader, writer, &recorder, REGISTRATION_TIMEOUT).await };
        let oversize = async {
            let mut frame = 1_u32.to_be_bytes().to_vec();
            frame.extend((crate::MAX_PAYLOAD + 1).to_be_bytes());
            runtime.write_all(&frame).await.unwrap();
        };
        let (end, ()) = tokio::join!(end, oversize);
        assert!(matches!(end, End::Lost(MuxError::Oversize(_))), "{end}");
    }
}
