//! What an agent sends on an `Announce` stream, parsed from its protobuf at the boundary (D2, D97).

use std::net::SocketAddr;

use speculaire_oci::reference::Digest;

use crate::metrics::Reason;
use crate::proto::{self, agent_message};

/// One message of an `Announce` stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Announcement {
    /// The first message: who the agent is and where its peers reach it.
    Hello(Hello),
    /// A chunk of every digest the agent holds.
    Snapshot(Snapshot),
    /// A change since the snapshot.
    Delta(Delta),
}

/// The first message of a stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    /// The protocol version the agent speaks.
    pub version: u32,
    /// The node the agent says it runs on: the reflector refuses any but the TLS peer's.
    pub node: String,
    /// Where its peers reach the agent's peer API.
    pub peer: SocketAddr,
}

/// A chunk of every digest the agent holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// The digests of the chunk.
    pub digests: Vec<Digest>,
    /// Whether this chunk ends the snapshot, which then replaces what the reflector held for the agent.
    pub last: bool,
    /// The sequence number of the first [`Delta`] after the snapshot.
    pub seq: u64,
}

/// A change since the snapshot, numbered from its `seq` without gaps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delta {
    /// The sequence number.
    pub seq: u64,
    /// Digests the agent now holds; applied after `removed`.
    pub added: Vec<Digest>,
    /// Digests the agent no longer holds.
    pub removed: Vec<Digest>,
}

/// Why a message cannot be parsed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Malformed {
    /// The message holds none of its variants.
    #[error("an empty message")]
    Empty,
    /// The peer address is not `ip:port`.
    #[error("peer address {0:?} is not an IP address with a port")]
    Address(String),
    /// A string is not a digest.
    #[error("{0:?} is not a digest")]
    Digest(String),
}

impl Malformed {
    /// The reason the reflector counts.
    #[must_use]
    pub const fn reason(&self) -> Reason {
        match self {
            Self::Address(_) => Reason::Address,
            Self::Empty | Self::Digest(_) => Reason::Malformed,
        }
    }
}

impl TryFrom<proto::AgentMessage> for Announcement {
    type Error = Malformed;

    fn try_from(message: proto::AgentMessage) -> Result<Self, Malformed> {
        Ok(match message.message.ok_or(Malformed::Empty)? {
            agent_message::Message::Hello(hello) => Self::Hello(Hello {
                version: hello.protocol_version,
                peer: hello
                    .peer_address
                    .parse()
                    .map_err(|_| Malformed::Address(hello.peer_address))?,
                node: hello.node,
            }),
            agent_message::Message::Snapshot(snapshot) => Self::Snapshot(Snapshot {
                digests: digests(snapshot.digests)?,
                last: snapshot.last,
                seq: snapshot.seq,
            }),
            agent_message::Message::Delta(delta) => Self::Delta(Delta {
                seq: delta.seq,
                added: digests(delta.added)?,
                removed: digests(delta.removed)?,
            }),
        })
    }
}

impl From<Announcement> for proto::AgentMessage {
    fn from(announcement: Announcement) -> Self {
        let texts = |digests: Vec<Digest>| digests.iter().map(ToString::to_string).collect();
        let message = match announcement {
            Announcement::Hello(hello) => agent_message::Message::Hello(proto::Hello {
                protocol_version: hello.version,
                node: hello.node,
                peer_address: hello.peer.to_string(),
            }),
            Announcement::Snapshot(snapshot) => agent_message::Message::Snapshot(proto::Snapshot {
                digests: texts(snapshot.digests),
                last: snapshot.last,
                seq: snapshot.seq,
            }),
            Announcement::Delta(delta) => agent_message::Message::Delta(proto::Delta {
                seq: delta.seq,
                added: texts(delta.added),
                removed: texts(delta.removed),
            }),
        };
        Self {
            message: Some(message),
        }
    }
}

/// Parses a digest an agent sent.
///
/// # Errors
///
/// When `text` is not `<algorithm>:<encoded>` with an algorithm the OCI image spec registers.
pub fn digest(text: String) -> Result<Digest, Malformed> {
    Digest::parse(&text).map_err(|_| Malformed::Digest(text))
}

fn digests(texts: Vec<String>) -> Result<Vec<Digest>, Malformed> {
    texts.into_iter().map(digest).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn hello(address: &str) -> proto::AgentMessage {
        proto::AgentMessage {
            message: Some(agent_message::Message::Hello(proto::Hello {
                protocol_version: 1,
                node: "a".to_owned(),
                peer_address: address.to_owned(),
            })),
        }
    }

    #[test]
    fn a_peer_address_is_an_ip_literal_with_a_port() {
        for address in ["10.0.0.1:7484", "[fd00::1]:7484"] {
            let parsed = Announcement::try_from(hello(address)).unwrap();
            assert_eq!(proto::AgentMessage::from(parsed), hello(address));
        }
        for address in ["10.0.0.1", "node-a:7484", "fd00::1:7484", ""] {
            let refused = Announcement::try_from(hello(address)).unwrap_err();
            assert_eq!(refused.reason(), Reason::Address, "{address}");
        }
    }

    #[test]
    fn every_string_of_a_delta_is_a_digest() {
        let delta = |removed: &str| proto::AgentMessage {
            message: Some(agent_message::Message::Delta(proto::Delta {
                seq: 3,
                added: vec![DIGEST.to_owned()],
                removed: vec![removed.to_owned()],
            })),
        };
        let digest = Digest::parse(DIGEST).unwrap();
        let parsed = Announcement::try_from(delta(DIGEST)).unwrap();
        assert_eq!(
            parsed,
            Announcement::Delta(Delta {
                seq: 3,
                added: vec![digest.clone()],
                removed: vec![digest],
            })
        );
        assert_eq!(proto::AgentMessage::from(parsed), delta(DIGEST));
        let refused = Announcement::try_from(delta("sha256:short")).unwrap_err();
        assert_eq!(refused, Malformed::Digest("sha256:short".to_owned()));
        assert_eq!(refused.reason(), Reason::Malformed);
    }

    #[test]
    fn a_snapshot_chunk_of_sha512_digests_fits_a_message() {
        use prost::Message as _;
        let digest = format!("sha512:{}", "a".repeat(128));
        let chunk = proto::AgentMessage {
            message: Some(agent_message::Message::Snapshot(proto::Snapshot {
                digests: vec![digest; crate::SNAPSHOT_CHUNK],
                last: false,
                seq: u64::MAX,
            })),
        };
        assert!(chunk.encoded_len() < crate::Limits::default().message / 2);
    }

    #[test]
    fn a_message_without_a_variant_is_malformed() {
        let empty = proto::AgentMessage { message: None };
        assert_eq!(Announcement::try_from(empty), Err(Malformed::Empty));
    }
}
