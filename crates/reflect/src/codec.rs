//! The reflector API's codec: prost's, with each message sent as soon as it is encoded (D104).
//!
//! tonic's own batches the messages a stream has ready, up to 32 KiB, so a snapshot's chunks go out in full 16 KiB
//! HTTP/2 frames. The receiver's buffer grows to take a frame and the rest of a message, and keeps that size for the
//! stream's life: about 64 KiB on each of the reflector's streams. A message to itself keeps it at one message.

use std::marker::PhantomData;

use tonic::codec::{BufferSettings, Codec};
use tonic_prost::{ProstDecoder, ProstEncoder};

/// The receive buffer, which two `Snapshot` chunks of sha256 digests fit, and one of sha512 (`SNAPSHOT_CHUNK`).
const RECEIVE: usize = 4 << 10;
/// The send buffer, which each stream keeps from its start: what the reflector sends is small, and a chunk grows it.
const SEND: usize = 1024;

/// The codec `build.rs` names for the generated server and client.
#[derive(Debug)]
pub(crate) struct Unbatched<T, U>(PhantomData<(T, U)>);

impl<T, U> Default for Unbatched<T, U> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T, U> Codec for Unbatched<T, U>
where
    T: prost::Message + Send + 'static,
    U: prost::Message + Default + Send + 'static,
{
    type Encode = T;
    type Decode = U;
    type Encoder = ProstEncoder<T>;
    type Decoder = ProstDecoder<U>;

    fn encoder(&mut self) -> Self::Encoder {
        // A yield threshold of 0 sends each message on its own.
        ProstEncoder::new(BufferSettings::new(SEND, 0))
    }

    fn decoder(&mut self) -> Self::Decoder {
        ProstDecoder::new(BufferSettings::new(RECEIVE, 0))
    }
}

#[cfg(test)]
mod tests {
    use prost::Message as _;
    use tonic::codec::{BufferSettings, Codec as _, Decoder as _, Encoder as _};

    use super::{RECEIVE, SEND, Unbatched};
    use crate::proto::{self, agent_message};

    /// A chunk of `SNAPSHOT_CHUNK` digests of `algorithm`, framed as gRPC sends it.
    fn framed_chunk(algorithm: &str, hex: usize) -> usize {
        let digest = format!("{algorithm}:{}", "a".repeat(hex));
        let chunk = proto::AgentMessage {
            message: Some(agent_message::Message::Snapshot(proto::Snapshot {
                digests: vec![digest; crate::SNAPSHOT_CHUNK],
                last: false,
                seq: u64::MAX,
            })),
        };
        // gRPC's frame header: a compression flag and a 4-byte length.
        5 + chunk.encoded_len()
    }

    #[test]
    fn the_receive_buffer_fits_two_sha256_chunks_and_one_sha512() {
        assert!(2 * framed_chunk("sha256", 64) <= RECEIVE);
        assert!(framed_chunk("sha512", 128) <= RECEIVE);
    }

    #[test]
    fn the_codec_sends_each_message_alone_from_its_own_buffers() {
        // `BufferSettings` shows its fields only through `Debug`.
        let settings = |settings: BufferSettings| format!("{settings:?}");
        let mut codec = Unbatched::<proto::AgentMessage, proto::ReflectorMessage>::default();
        assert_eq!(
            settings(codec.encoder().buffer_settings()),
            settings(BufferSettings::new(SEND, 0))
        );
        assert_eq!(
            settings(codec.decoder().buffer_settings()),
            settings(BufferSettings::new(RECEIVE, 0))
        );
    }
}
