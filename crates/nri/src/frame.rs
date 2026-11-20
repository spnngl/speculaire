//! The trunk's frames (D9): an 8-byte header, the ConnID then the payload's length, both big-endian, then the payload.

use zerocopy::big_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// The largest payload of a frame: a ttrpc message's 10-byte header and its 4 MiB limit (`maxPayloadSize`,
/// `pkg/net/multiplex/mux.go:142` and `ttrpc.go:27-28` at v0.12.5).
pub const MAX_PAYLOAD: u32 = 10 + (4 << 20);

/// The size of a [`Header`].
pub(crate) const HEADER: usize = size_of::<Header>();

/// A frame's header as the trunk carries it, read into in place (D107).
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct Header {
    conn: U32,
    length: U32,
}

/// A frame whose payload is over [`MAX_PAYLOAD`]: no peer writes one, and the framing cannot skip it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("conn {conn}: a frame payload of {length} bytes, over the maximum of {MAX_PAYLOAD}")]
pub struct Oversize {
    /// The frame's ConnID.
    pub conn: u32,
    /// The payload length its header claims.
    pub length: u32,
}

impl Header {
    pub(crate) const fn new(conn: u32, length: u32) -> Self {
        Self {
            conn: U32::new(conn),
            length: U32::new(length),
        }
    }

    pub(crate) const fn conn(self) -> u32 {
        self.conn.get()
    }

    /// The payload's length, refused over [`MAX_PAYLOAD`] before anything is allocated for it.
    pub(crate) fn length(self) -> Result<usize, Oversize> {
        let length = self.length.get();
        if length > MAX_PAYLOAD {
            return Err(Oversize {
                conn: self.conn(),
                length,
            });
        }
        Ok(usize::try_from(length).expect("a length of at most MAX_PAYLOAD fits in usize"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_reads_big_endian_and_refuses_one_byte_over_the_maximum() {
        let header = Header::read_from_bytes(&[0, 0, 0, 2, 0, 0x40, 0, 0x0a]).unwrap();
        assert_eq!(header.conn(), 2);
        assert_eq!(header.length(), Ok((4 << 20) + 10));
        let over = Header::read_from_bytes(&[0, 0, 0, 2, 0, 0x40, 0, 0x0b]).unwrap();
        assert!(over.length().is_err());
        assert_eq!(
            Header::new(1, MAX_PAYLOAD + 1).length(),
            Err(Oversize {
                conn: 1,
                length: MAX_PAYLOAD + 1
            })
        );
        assert_eq!(Header::new(1, 0).as_bytes(), [0, 0, 0, 1, 0, 0, 0, 0]);
    }
}

/// Kani's proof of the decoder (D163): `just kani`.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// For every 8 bytes, the header reads them big-endian, and a length it yields is at most [`MAX_PAYLOAD`].
    #[kani::proof]
    fn every_header_decodes_within_the_maximum() {
        let bytes: [u8; HEADER] = kani::any();
        let header: Header = zerocopy::transmute!(bytes);
        let [c0, c1, c2, c3, l0, l1, l2, l3] = bytes;
        assert_eq!(header.conn(), u32::from_be_bytes([c0, c1, c2, c3]));
        let claimed = u32::from_be_bytes([l0, l1, l2, l3]);
        match header.length() {
            Ok(length) => {
                assert!(claimed <= MAX_PAYLOAD);
                assert_eq!(u32::try_from(length), Ok(claimed));
            }
            Err(Oversize { conn, length }) => {
                assert!(length > MAX_PAYLOAD);
                assert_eq!((conn, length), (header.conn(), claimed));
            }
        }
    }
}
