//! ttrpc's unary calls, as NRI makes them (D166): a 10-byte header, then a protobuf `Request` or `Response`.

// Ported from containerd/ttrpc v1.2.7 `channel.go:30-155` (the header, `messageLengthMax`), `server.go:340-470` (a
// request read, its response written) and `services.go:95-160` (a request's payload dispatched by method).

use std::io;
use std::time::Duration;

use prost::Message as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zerocopy::big_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::api::{ConfigureRequest, Empty, SynchronizeRequest};

#[expect(unreachable_pub, reason = "generated: prost makes every message `pub`")]
pub(crate) mod proto {
    include!(concat!(env!("OUT_DIR"), "/ttrpc.rs"));
}

pub(crate) use proto::Status;

/// The largest message ttrpc sends or reads, its header excluded (`messageLengthMax`, `channel.go:31`).
pub const MAX_MESSAGE: u32 = 4 << 20;

/// The service NRI's runtime calls, its name as ttrpc carries it.
pub(crate) const PLUGIN_SERVICE: &str = "nri.pkg.api.v1alpha1.Plugin";

/// The service NRI's plugin calls.
pub(crate) const RUNTIME_SERVICE: &str = "nri.pkg.api.v1alpha1.Runtime";

/// The gRPC status codes this crate answers with (`google.golang.org/grpc/codes`).
pub(crate) mod code {
    pub(crate) const OK: i32 = 0;
    pub(crate) const INVALID_ARGUMENT: i32 = 3;
    pub(crate) const DEADLINE_EXCEEDED: i32 = 4;
    pub(crate) const FAILED_PRECONDITION: i32 = 9;
    pub(crate) const UNIMPLEMENTED: i32 = 12;
}

/// A message's header, read into in place (D107).
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Header {
    length: U32,
    stream: U32,
    kind: u8,
    flags: u8,
}

/// The kinds of message a unary call uses; ttrpc's streams add a third, which this crate skips.
const REQUEST: u8 = 1;
const RESPONSE: u8 = 2;

/// A call of NRI's plugin service, read from the runtime.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    /// The ttrpc stream to answer on.
    pub stream: u32,
    /// How long the runtime waits for the answer, when it says.
    pub timeout: Option<Duration>,
    /// The method called and its request.
    pub call: Call,
}

/// A method of NRI's plugin service and its request.
#[derive(Debug, Clone, PartialEq)]
pub enum Call {
    /// The runtime describes itself and asks which events the plugin wants.
    Configure(ConfigureRequest),
    /// One part of the pods and containers that exist.
    Synchronize(SynchronizeRequest),
    /// A container is about to be created: the `CreateContainerRequest`, left for [`crate::create::Request::read`].
    CreateContainer(Vec<u8>),
    /// The runtime is shutting down.
    Shutdown,
    /// A method this crate does not implement.
    Other {
        /// The service named.
        service: String,
        /// The method named.
        method: String,
    },
}

/// Why no request was read.
#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    /// The connection failed or ended inside a message.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// A message over [`MAX_MESSAGE`], which no peer sends.
    #[error("a ttrpc message of {length} bytes, over the maximum of {MAX_MESSAGE}")]
    Oversize {
        /// The length its header claims.
        length: u32,
    },
    /// A request that is not protobuf, or not that of the method named; its stream is still answered.
    #[error("stream {stream}: {source}")]
    Decode {
        /// The stream it came on.
        stream: u32,
        /// What protobuf refused.
        source: prost::DecodeError,
    },
}

/// Why a call to the runtime has no answer.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CallError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("code {}: {}", .0.code, .0.message)]
    Status(Status),
}

/// The next request of NRI's plugin service, read into `body`, which is kept between calls (D107). Responses and
/// stream data are skipped.
///
/// # Errors
///
/// When the connection ends or fails, a message is over [`MAX_MESSAGE`], or a request does not decode.
pub async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
    body: &mut Vec<u8>,
) -> Result<Request, RequestError> {
    loop {
        let header = read_message(reader, body).await?;
        if header.kind != REQUEST {
            continue;
        }
        let stream = header.stream.get();
        return decode_request(stream, body)
            .map_err(|source| RequestError::Decode { stream, source });
    }
}

fn decode_request(stream: u32, body: &[u8]) -> Result<Request, prost::DecodeError> {
    let proto::Request {
        service,
        method,
        payload,
        timeout_nano,
    } = proto::Request::decode(body)?;
    let call = if service == PLUGIN_SERVICE {
        match method.as_str() {
            "Configure" => Some(Call::Configure(ConfigureRequest::decode(&*payload)?)),
            "Synchronize" => Some(Call::Synchronize(SynchronizeRequest::decode(&*payload)?)),
            "CreateContainer" => Some(Call::CreateContainer(payload)),
            "Shutdown" => Empty::decode(&*payload).map(|Empty {}| Some(Call::Shutdown))?,
            _ => None,
        }
    } else {
        None
    };
    Ok(Request {
        stream,
        timeout: u64::try_from(timeout_nano)
            .ok()
            .filter(|&nanos| nanos > 0)
            .map(Duration::from_nanos),
        call: call.unwrap_or(Call::Other { service, method }),
    })
}

/// Reads the next message's header, and its body into `body`.
async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    body: &mut Vec<u8>,
) -> Result<Header, RequestError> {
    let mut header = Header::default();
    reader.read_exact(header.as_mut_bytes()).await?;
    let length = header.length.get();
    if length > MAX_MESSAGE {
        return Err(RequestError::Oversize { length });
    }
    body.clear();
    body.resize(
        usize::try_from(length).expect("a length of at most MAX_MESSAGE fits in usize"),
        0,
    );
    reader.read_exact(body).await?;
    Ok(header)
}

/// Writes `message` with its header through `buf`, which is kept between calls (D107).
async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    buf: &mut Vec<u8>,
    stream: u32,
    kind: u8,
    message: &impl prost::Message,
) -> io::Result<()> {
    encode_message(buf, stream, kind, message)?;
    writer.write_all(buf).await
}

/// Puts `message` with its header in `buf`, in place of what it held.
fn encode_message(
    buf: &mut Vec<u8>,
    stream: u32,
    kind: u8,
    message: &impl prost::Message,
) -> io::Result<()> {
    let length = u32::try_from(message.encoded_len())
        .ok()
        .filter(|&length| length <= MAX_MESSAGE)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "a ttrpc message over 4 MiB"))?;
    let header = Header {
        length: U32::new(length),
        stream: U32::new(stream),
        kind,
        flags: 0,
    };
    buf.clear();
    buf.extend_from_slice(header.as_bytes());
    message.encode(buf).expect("a Vec grows to fit the message");
    Ok(())
}

/// The message of a call of the plugin service's `method` on `stream`, whose request is the protobuf `payload`.
#[cfg(any(test, feature = "testing"))]
pub(crate) fn request_message(
    stream: u32,
    method: &str,
    payload: &[u8],
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let request = proto::Request {
        service: PLUGIN_SERVICE.to_owned(),
        method: method.to_owned(),
        payload: payload.to_vec(),
        timeout_nano: i64::try_from(timeout.as_nanos()).unwrap_or(i64::MAX),
    };
    let mut buf = Vec::new();
    encode_message(&mut buf, stream, REQUEST, &request)?;
    Ok(buf)
}

/// The status of the response `message` holds; none until it holds a whole message.
///
/// # Errors
///
/// When the message is not a response.
#[cfg(any(test, feature = "testing"))]
pub(crate) fn response_status(message: &[u8]) -> Option<io::Result<Status>> {
    let (header, body) = Header::read_from_prefix(message).ok()?;
    let body = body.get(..usize::try_from(header.length.get()).ok()?)?;
    let response = match header.kind {
        RESPONSE => proto::Response::decode(body)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err)),
        kind => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("a message of kind {kind}, not a response"),
        )),
    };
    Some(response.map(|response| response.status.unwrap_or_default()))
}

/// Answers the request on `stream`: `Ok` carries the response's protobuf, `Err` the status that replaces it.
pub(crate) async fn respond<W: AsyncWrite + Unpin>(
    writer: &mut W,
    buf: &mut Vec<u8>,
    stream: u32,
    answer: Result<Vec<u8>, Status>,
) -> io::Result<()> {
    let (status, payload) = match answer {
        Ok(payload) => (Status::default(), payload),
        Err(status) => (status, Vec::new()),
    };
    let response = proto::Response {
        status: Some(status),
        payload,
    };
    write_message(writer, buf, stream, RESPONSE, &response).await
}

/// Calls `service`'s `method` on `stream`, telling the peer it waits `timeout`, and reads the answer's protobuf.
pub(crate) async fn call<C: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut C,
    stream: u32,
    (service, method): (&str, &str),
    request: &impl prost::Message,
    timeout: Duration,
) -> Result<Vec<u8>, CallError> {
    let mut buf = Vec::new();
    write_request(conn, &mut buf, stream, (service, method), request, timeout).await?;
    loop {
        let (answered, response) = read_response(conn, &mut buf).await?;
        if answered != stream {
            continue;
        }
        return match response.status {
            Some(status) if status.code != code::OK => Err(CallError::Status(status)),
            _ => Ok(response.payload),
        };
    }
}

/// Writes a request for `service`'s `method` on `stream`.
pub(crate) async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    buf: &mut Vec<u8>,
    stream: u32,
    (service, method): (&str, &str),
    request: &impl prost::Message,
    timeout: Duration,
) -> io::Result<()> {
    let request = proto::Request {
        service: service.to_owned(),
        method: method.to_owned(),
        payload: request.encode_to_vec(),
        timeout_nano: i64::try_from(timeout.as_nanos()).unwrap_or(i64::MAX),
    };
    write_message(writer, buf, stream, REQUEST, &request).await
}

/// Reads the next response and the stream it answers, skipping other messages.
pub(crate) async fn read_response<R: AsyncRead + Unpin>(
    reader: &mut R,
    body: &mut Vec<u8>,
) -> io::Result<(u32, proto::Response)> {
    loop {
        let header = match read_message(reader, body).await {
            Ok(header) => header,
            Err(RequestError::Io(err)) => return Err(err),
            Err(err) => return Err(io::Error::new(io::ErrorKind::InvalidData, err)),
        };
        if header.kind == RESPONSE {
            let response = proto::Response::decode(body.as_slice())
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            return Ok((header.stream.get(), response));
        }
    }
}

/// The status of a refused call.
pub(crate) fn status(code: i32, message: impl Into<String>) -> Status {
    Status {
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{Container, CreateContainerRequest};

    #[tokio::test]
    async fn a_request_round_trips_and_other_messages_are_skipped() {
        let mut wire = Vec::new();
        let mut buf = Vec::new();
        respond(&mut wire, &mut buf, 7, Ok(Vec::new()))
            .await
            .unwrap();
        let request = CreateContainerRequest {
            pod: None,
            container: Some(Container {
                name: "app".to_owned(),
                ..Container::default()
            }),
        };
        let timeout = Duration::from_millis(1500);
        write_request(
            &mut wire,
            &mut buf,
            3,
            (PLUGIN_SERVICE, "CreateContainer"),
            &request,
            timeout,
        )
        .await
        .unwrap();
        write_request(
            &mut wire,
            &mut buf,
            5,
            ("other", "Method"),
            &Empty {},
            Duration::ZERO,
        )
        .await
        .unwrap();
        let mut reader = wire.as_slice();
        let read = read_request(&mut reader, &mut buf).await.unwrap();
        assert_eq!(
            read,
            Request {
                stream: 3,
                timeout: Some(timeout),
                call: Call::CreateContainer(request.encode_to_vec()),
            }
        );
        let other = read_request(&mut reader, &mut buf).await.unwrap();
        assert_eq!(other.timeout, None);
        assert_eq!(
            other.call,
            Call::Other {
                service: "other".to_owned(),
                method: "Method".to_owned()
            }
        );
        let end = read_request(&mut reader, &mut buf).await.unwrap_err();
        assert!(matches!(end, RequestError::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof));
    }

    #[tokio::test]
    async fn a_message_one_byte_over_the_maximum_is_refused_before_its_body() {
        let header = Header {
            length: U32::new(MAX_MESSAGE + 1),
            stream: U32::new(1),
            kind: REQUEST,
            flags: 0,
        };
        let mut reader = header.as_bytes();
        let err = read_request(&mut reader, &mut Vec::new())
            .await
            .unwrap_err();
        assert!(matches!(err, RequestError::Oversize { length } if length == MAX_MESSAGE + 1));
        // One of the maximum is read, and skipped as a response.
        let mut wire = Header {
            length: U32::new(MAX_MESSAGE),
            stream: U32::new(1),
            kind: RESPONSE,
            flags: 0,
        }
        .as_bytes()
        .to_vec();
        wire.resize(wire.len() + (4 << 20), 0);
        let end = read_request(&mut wire.as_slice(), &mut Vec::new())
            .await
            .unwrap_err();
        assert!(matches!(end, RequestError::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof));
        let mut buf = Vec::new();
        let big = proto::Response {
            status: None,
            payload: vec![0; 4 << 20],
        };
        let err = write_message(&mut Vec::new(), &mut buf, 1, RESPONSE, &big)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn a_request_that_is_not_its_methods_is_refused_with_its_stream() {
        let mut wire = Vec::new();
        let mut buf = Vec::new();
        // Field 2 as a number, where ConfigureRequest has a string.
        let wrong = crate::api::ConfigureResponse { events: 5 };
        write_request(
            &mut wire,
            &mut buf,
            9,
            (PLUGIN_SERVICE, "Configure"),
            &wrong,
            Duration::ZERO,
        )
        .await
        .unwrap();
        let err = read_request(&mut wire.as_slice(), &mut buf)
            .await
            .unwrap_err();
        assert!(
            matches!(err, RequestError::Decode { stream: 9, .. }),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_call_reads_its_own_answer_and_its_status() {
        let mut buf = Vec::new();
        let mut answers = Vec::new();
        respond(&mut answers, &mut buf, 3, Ok(vec![1]))
            .await
            .unwrap();
        respond(
            &mut answers,
            &mut buf,
            1,
            Err(status(code::FAILED_PRECONDITION, "no")),
        )
        .await
        .unwrap();
        let mut conn = tokio_test_io(answers);
        let err = call(&mut conn, 1, ("s", "m"), &Empty {}, Duration::ZERO)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, CallError::Status(s) if s.message == "no"),
            "{err}"
        );
        let err = call(&mut conn, 1, ("s", "m"), &Empty {}, Duration::ZERO)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, CallError::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof),
            "{err}"
        );
    }

    /// A connection that reads `incoming` and swallows what is written.
    fn tokio_test_io(incoming: Vec<u8>) -> impl AsyncRead + AsyncWrite + Unpin {
        tokio::io::join(io::Cursor::new(incoming), tokio::io::sink())
    }
}
