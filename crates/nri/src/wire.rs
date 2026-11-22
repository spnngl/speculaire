//! Protobuf's wire format read in place: each field of a message, its bytes borrowed (D189).
//!
//! It reads what prost reads, and refuses what prost refuses on the fields its caller reads: a varint over 10 bytes or
//! 64 bits, a key over 32 bits, field number 0 or wire type 6 or 7, a length past the message's end. Groups, which
//! proto3 never writes, are refused rather than skipped.

/// Why a message does not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The message ends inside a field.
    #[error("the message ends inside a field")]
    Truncated,
    /// A varint over 10 bytes, or over 64 bits.
    #[error("invalid varint")]
    Varint,
    /// A key over 32 bits, or of field number 0.
    #[error("invalid key")]
    Key,
    /// A field of wire type 3, 4, 6 or 7: a group, or none.
    #[error("field {field}: wire type {wire_type}, which proto3 never writes")]
    Unread {
        /// Its field number.
        field: u32,
        /// Its wire type.
        wire_type: u8,
    },
    /// A field read with another wire type than its own.
    #[error("field {field}: wire type {wire_type}, not that of its type")]
    WireType {
        /// Its field number.
        field: u32,
        /// The wire type it came with.
        wire_type: u8,
    },
    /// A string that is not UTF-8.
    #[error("field {field}: a string that is not UTF-8")]
    Utf8 {
        /// Its field number.
        field: u32,
    },
}

/// A field's value, as its wire type carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Value<'a> {
    /// Wire type 0.
    Varint(u64),
    /// Wire type 1.
    Fixed64(u64),
    /// Wire type 2: a string, bytes, a message or a packed repeated field.
    Bytes(&'a [u8]),
    /// Wire type 5.
    Fixed32(u32),
}

impl<'a> Value<'a> {
    /// The value of field `field` as a string.
    pub(crate) fn string(self, field: u32) -> Result<&'a str, Error> {
        str::from_utf8(self.bytes(field)?).map_err(|_| Error::Utf8 { field })
    }

    /// The value of field `field` as an integer of wire type 0, as written.
    pub(crate) fn varint(self, field: u32) -> Result<u64, Error> {
        match self {
            Self::Varint(value) => Ok(value),
            other => Err(Error::WireType {
                field,
                wire_type: other.wire_type(),
            }),
        }
    }

    /// The value of field `field` as bytes or a message.
    pub(crate) fn bytes(self, field: u32) -> Result<&'a [u8], Error> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            other => Err(Error::WireType {
                field,
                wire_type: other.wire_type(),
            }),
        }
    }

    fn wire_type(self) -> u8 {
        match self {
            Self::Varint(_) => 0,
            Self::Fixed64(_) => 1,
            Self::Bytes(_) => 2,
            Self::Fixed32(_) => 5,
        }
    }
}

/// The fields of a message, in the order written; an error ends them.
#[derive(Debug, Clone)]
pub(crate) struct Fields<'a> {
    rest: &'a [u8],
}

/// The fields of `message`.
pub(crate) fn fields(message: &[u8]) -> Fields<'_> {
    Fields { rest: message }
}

impl<'a> Iterator for Fields<'a> {
    type Item = Result<(u32, Value<'a>), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let field = self.field();
        if field.is_err() {
            self.rest = &[];
        }
        Some(field)
    }
}

impl<'a> Fields<'a> {
    fn field(&mut self) -> Result<(u32, Value<'a>), Error> {
        let key = u32::try_from(self.varint()?).map_err(|_| Error::Key)?;
        let field = key >> 3;
        if field == 0 {
            return Err(Error::Key);
        }
        let value = match key & 7 {
            0 => Value::Varint(self.varint()?),
            1 => Value::Fixed64(u64::from_le_bytes(self.take()?)),
            2 => {
                let length = usize::try_from(self.varint()?).map_err(|_| Error::Truncated)?;
                let (bytes, rest) = self.rest.split_at_checked(length).ok_or(Error::Truncated)?;
                self.rest = rest;
                Value::Bytes(bytes)
            }
            5 => Value::Fixed32(u32::from_le_bytes(self.take()?)),
            wire_type => {
                return Err(Error::Unread {
                    field,
                    wire_type: u8::try_from(wire_type).expect("three bits fit in u8"),
                });
            }
        };
        Ok((field, value))
    }

    /// A varint: 7 bits a byte, least significant first, the last byte's high bit clear (prost's `decode_varint`).
    fn varint(&mut self) -> Result<u64, Error> {
        let mut value = 0;
        for shift in (0..64).step_by(7) {
            let (&byte, rest) = self.rest.split_first().ok_or(Error::Truncated)?;
            self.rest = rest;
            // The tenth byte holds bit 63 alone.
            if shift == 63 && byte > 1 {
                return Err(Error::Varint);
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte < 0x80 {
                return Ok(value);
            }
        }
        Err(Error::Varint)
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let (bytes, rest) = self.rest.split_first_chunk().ok_or(Error::Truncated)?;
        self.rest = rest;
        Ok(*bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(message: &[u8]) -> Result<Vec<(u32, Value<'_>)>, Error> {
        fields(message).collect()
    }

    #[test]
    fn each_wire_type_reads_its_value() {
        let message = [
            0x08, 0x96, 0x01, // 1: varint 150
            0x11, 1, 0, 0, 0, 0, 0, 0, 0, // 2: fixed64 1
            0x1a, 2, b'h', b'i', // 3: bytes "hi"
            0x25, 2, 0, 0, 0, // 4: fixed32 2
        ];
        assert_eq!(
            read(&message),
            Ok(vec![
                (1, Value::Varint(150)),
                (2, Value::Fixed64(1)),
                (3, Value::Bytes(b"hi")),
                (4, Value::Fixed32(2)),
            ])
        );
    }

    #[test]
    fn varints_read_as_prost_reads_them() {
        for value in [0, 1, 127, 128, 300, u64::from(u32::MAX), u64::MAX] {
            let mut message = vec![0x08];
            prost::encoding::encode_varint(value, &mut message);
            assert_eq!(
                read(&message),
                Ok(vec![(1, Value::Varint(value))]),
                "{value}"
            );
        }
        // Eleven bytes, and a tenth byte over bit 63: prost refuses both.
        let long = [
            0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
        ];
        assert_eq!(read(&long), Err(Error::Varint));
        let wide = [
            0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02,
        ];
        assert_eq!(read(&wide), Err(Error::Varint));
    }

    #[test]
    fn keys_and_lengths_out_of_bounds_end_the_fields() {
        assert_eq!(read(&[0x00, 0x01]), Err(Error::Key));
        assert_eq!(read(&[0x80, 0x80, 0x80, 0x80, 0x10]), Err(Error::Key));
        assert_eq!(
            read(&[0x0b]),
            Err(Error::Unread {
                field: 1,
                wire_type: 3
            })
        );
        assert_eq!(
            read(&[0x0e]),
            Err(Error::Unread {
                field: 1,
                wire_type: 6
            })
        );
        assert_eq!(read(&[0x0a, 3, b'a']), Err(Error::Truncated));
        assert_eq!(read(&[0x09, 1, 2]), Err(Error::Truncated));
        assert_eq!(read(&[0x08]), Err(Error::Truncated));
        let mut fields = fields(&[0x00, 0x08, 0x01]);
        assert_eq!(fields.next(), Some(Err(Error::Key)));
        assert_eq!(fields.next(), None);
    }

    #[test]
    fn a_value_of_another_type_is_refused() {
        for (value, wire_type) in [
            (Value::Varint(1), 0),
            (Value::Fixed64(1), 1),
            (Value::Fixed32(1), 5),
        ] {
            assert_eq!(
                value.string(4),
                Err(Error::WireType {
                    field: 4,
                    wire_type
                })
            );
        }
        assert_eq!(
            Value::Bytes(&[0xff]).string(3),
            Err(Error::Utf8 { field: 3 })
        );
        assert_eq!(Value::Bytes(b"ok").string(3), Ok("ok"));
    }
}
