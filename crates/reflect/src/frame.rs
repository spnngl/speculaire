//! The reflector API's frames (D105): a 4-byte big-endian length, then that many bytes of one protobuf message.

use std::io;
use std::marker::PhantomData;
use std::time::Duration;

use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use zerocopy::IntoBytes as _;
use zerocopy::big_endian::U32;

/// The ALPN protocol of a connection to a reflector: this framing, with the messages of `proto/`.
pub const ALPN: &[u8] = b"speculaire-reflect/1";

/// The size of a frame's message at most (D97).
pub const LIMIT: usize = 4 << 20;

/// How often an agent pings each reflector it is connected to.
pub const PING: Duration = Duration::from_secs(30);

/// How long either side reads nothing before it closes the connection: a ping's period, and 10 s for its answer.
pub const SILENCE: Duration = Duration::from_secs(40);

/// The largest read buffer a [`Reader`] keeps between frames: a lookup, its answer and a small delta fit, while a
/// `Snapshot` chunk of 25 digests (D104), 1.8 KB, is read into a buffer dropped after it.
const KEEP: usize = 1 << 10;

/// Why a frame could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The connection failed, or ended inside a frame.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The message is larger than the limit.
    #[error("a message of {size} bytes, over the limit of {limit}")]
    Size {
        /// The message's size.
        size: usize,
        /// The limit it is over.
        limit: usize,
    },
    /// The message does not decode.
    #[error("a message that does not decode: {0}")]
    Decode(#[from] prost::DecodeError),
}

/// Reads the frames of `M` off a connection into one buffer, reused from frame to frame (D107). Its state survives a
/// dropped [`Reader::next`]: it is cancel-safe.
#[derive(Debug)]
pub struct Reader<M> {
    limit: usize,
    state: State,
    /// At least the current frame's body; kept for the next frame unless it grew over [`KEEP`].
    buffer: Vec<u8>,
    message: PhantomData<fn() -> M>,
}

#[derive(Debug)]
enum State {
    /// The length, `filled` bytes of it read.
    Head { length: U32, filled: usize },
    /// The message, `size` bytes, `filled` bytes of it read into the buffer.
    Body { size: usize, filled: usize },
}

impl State {
    const START: Self = Self::Head {
        length: U32::ZERO,
        filled: 0,
    };
}

impl<M: Message + Default> Reader<M> {
    /// A reader that refuses a message of more than `limit` bytes before it allocates for it.
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self {
            limit,
            state: State::START,
            buffer: Vec::new(),
            message: PhantomData,
        }
    }

    /// The next message; `None` when the connection ends between two frames.
    ///
    /// # Errors
    ///
    /// When reading fails, the connection ends inside a frame, or the message is over the limit or does not decode.
    /// The reader is then of no further use.
    pub async fn next<R: AsyncRead + Unpin>(
        &mut self,
        io: &mut R,
    ) -> Result<Option<M>, FrameError> {
        loop {
            match &mut self.state {
                State::Head { length, filled } => {
                    let bytes = length.as_mut_bytes();
                    let unread = bytes.get_mut(*filled..).unwrap_or_default();
                    let read = io.read(unread).await?;
                    if read == 0 {
                        return if *filled == 0 {
                            Ok(None)
                        } else {
                            Err(io::Error::from(io::ErrorKind::UnexpectedEof).into())
                        };
                    }
                    *filled += read;
                    if *filled == bytes.len() {
                        let size = usize::try_from(length.get()).unwrap_or(usize::MAX);
                        if size > self.limit {
                            return Err(FrameError::Size {
                                size,
                                limit: self.limit,
                            });
                        }
                        // Exact: the buffer stays the largest frame's size, not the next power of two.
                        self.buffer
                            .reserve_exact(size.saturating_sub(self.buffer.len()));
                        self.buffer.resize(size.max(self.buffer.len()), 0);
                        self.state = State::Body { size, filled: 0 };
                    }
                }
                State::Body { size, filled } if *filled < *size => {
                    let unread = self.buffer.get_mut(*filled..*size).unwrap_or_default();
                    let read = io.read(unread).await?;
                    if read == 0 {
                        return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
                    }
                    *filled += read;
                }
                State::Body { size, .. } => {
                    let message = M::decode(self.buffer.get(..*size).unwrap_or_default());
                    self.state = State::START;
                    if self.buffer.len() > KEEP {
                        // One outsized frame does not pin its size for the connection's life.
                        self.buffer = Vec::new();
                    }
                    return Ok(Some(message?));
                }
            }
        }
    }
}

/// Writes `message` as one frame and flushes it, unless it is over `limit` bytes.
///
/// # Errors
///
/// When the message is over the limit, or writing fails.
pub async fn write<M: Message, W: AsyncWrite + Unpin>(
    io: &mut W,
    message: &M,
    limit: usize,
) -> Result<(), FrameError> {
    let size = message.encoded_len();
    let length = u32::try_from(size)
        .ok()
        .filter(|_| size <= limit)
        .map(U32::new)
        .ok_or(FrameError::Size { size, limit })?;
    let mut frame = Vec::with_capacity(size.saturating_add(size_of::<U32>()));
    frame.extend_from_slice(length.as_bytes());
    message.encode_raw(&mut frame);
    io.write_all(&frame).await?;
    io.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    use super::*;
    use crate::proto::{self, agent_message};

    fn ping() -> proto::AgentMessage {
        proto::AgentMessage {
            message: Some(agent_message::Message::Ping(proto::Ping {})),
        }
    }

    /// The frames of `bytes`, read with a limit of `limit`, and how the reading ended.
    fn read(bytes: &[u8], limit: usize) -> (Vec<proto::AgentMessage>, Result<(), FrameError>) {
        read_with(&mut Reader::new(limit), bytes)
    }

    /// The frames of `bytes`, read by `reader`, and how the reading ended.
    fn read_with(
        reader: &mut Reader<proto::AgentMessage>,
        bytes: &[u8],
    ) -> (Vec<proto::AgentMessage>, Result<(), FrameError>) {
        let mut io = bytes;
        let mut messages = Vec::new();
        loop {
            // A slice never waits.
            let Poll::Ready(next) =
                pin!(reader.next(&mut io)).poll(&mut Context::from_waker(Waker::noop()))
            else {
                unreachable!("a slice is always ready");
            };
            match next {
                Ok(Some(message)) => messages.push(message),
                Ok(None) => return (messages, Ok(())),
                Err(err) => return (messages, Err(err)),
            }
        }
    }

    async fn written(message: &proto::AgentMessage, limit: usize) -> Result<Vec<u8>, FrameError> {
        let mut bytes = Vec::new();
        write(&mut bytes, message, limit).await?;
        Ok(bytes)
    }

    #[tokio::test]
    async fn frames_read_back_as_written_and_the_end_between_frames_is_clean() {
        let lookup = proto::AgentMessage {
            message: Some(agent_message::Message::Lookup(proto::LookupRequest {
                digest: "sha256:00".to_owned(),
                id: 7,
            })),
        };
        let mut bytes = written(&ping(), LIMIT).await.unwrap();
        assert_eq!(bytes, [0, 0, 0, 2, 0x32, 0]);
        bytes.extend(written(&lookup, LIMIT).await.unwrap());
        let (messages, end) = read(&bytes, LIMIT);
        assert_eq!(messages, [ping(), lookup]);
        end.unwrap();
    }

    /// A lookup whose frame's body is `size` bytes.
    fn lookup_of(size: usize) -> proto::AgentMessage {
        // The digest's 2-byte length, and 4 bytes of tags and lengths around it, at the sizes used here.
        let lookup = proto::AgentMessage {
            message: Some(agent_message::Message::Lookup(proto::LookupRequest {
                digest: "0".repeat(size - 6),
                id: 0,
            })),
        };
        assert_eq!(lookup.encoded_len(), size);
        lookup
    }

    #[tokio::test]
    async fn the_buffer_grows_to_the_largest_frame_and_is_dropped_past_keep() {
        let mut reader = Reader::new(LIMIT);
        let mut frames = written(&lookup_of(500), LIMIT).await.unwrap();
        frames.extend(written(&lookup_of(700), LIMIT).await.unwrap());
        frames.extend(written(&ping(), LIMIT).await.unwrap());
        let (messages, end) = read_with(&mut reader, &frames);
        end.unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(reader.buffer.capacity(), 700);

        let (_, end) = read_with(
            &mut reader,
            &written(&lookup_of(KEEP), LIMIT).await.unwrap(),
        );
        end.unwrap();
        assert_eq!(reader.buffer.capacity(), KEEP);

        let (messages, end) = read_with(
            &mut reader,
            &written(&lookup_of(KEEP + 1), LIMIT).await.unwrap(),
        );
        end.unwrap();
        assert_eq!(messages, [lookup_of(KEEP + 1)]);
        assert_eq!(reader.buffer.capacity(), 0);
    }

    #[test]
    fn a_frame_cut_short_is_an_unexpected_end() {
        for bytes in [&[0, 0][..], &[0, 0, 0, 2, 0x32]] {
            let (messages, end) = read(bytes, LIMIT);
            assert_eq!(messages, []);
            assert!(
                matches!(end, Err(FrameError::Io(err)) if err.kind() == io::ErrorKind::UnexpectedEof),
                "{bytes:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_message_over_the_limit_is_refused_by_its_length_alone() {
        // A length of 4 GiB - 1 and no body: refused before any allocation for it.
        let (_, end) = read(&[0xff, 0xff, 0xff, 0xff], LIMIT);
        assert!(
            matches!(
                end,
                Err(FrameError::Size {
                    size: 0xffff_ffff,
                    limit: LIMIT
                })
            ),
            "{end:?}"
        );
        let (messages, end) = read(&[0, 0, 0, 2, 0x32, 0, 0, 0, 0, 3], 2);
        assert_eq!(messages, [ping()]);
        assert!(
            matches!(end, Err(FrameError::Size { size: 3, limit: 2 })),
            "{end:?}"
        );
        assert!(matches!(
            written(&ping(), 1).await,
            Err(FrameError::Size { size: 2, limit: 1 })
        ));
    }

    #[test]
    fn a_body_that_does_not_decode_is_an_error() {
        let (_, end) = read(&[0, 0, 0, 1, 0xff], LIMIT);
        assert!(matches!(end, Err(FrameError::Decode(_))), "{end:?}");
    }
}
