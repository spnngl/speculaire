//! What an agent sends, parsed from its protobuf at the boundary (D2, D97, D105).

use std::net::SocketAddr;

use speculaire_oci::reference::Digest;

use crate::metrics::Reason;
use crate::proto::{self, agent_message};

/// One message of an agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// What the agent holds.
    Announcement(Announcement),
    /// Who else holds a digest.
    Lookup(Lookup),
    /// The reflectors, as `reflector.members` lists them.
    Members,
    /// A sign of life, answered with one.
    Ping,
}

/// A digest to look up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lookup {
    /// The number the answer carries back, chosen by the agent.
    pub id: u64,
    /// The digest.
    pub digest: Digest,
}

/// What an agent announces on its connection to a member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Announcement {
    /// The first announcement: who the agent is and where its peers reach it.
    Hello(Hello),
    /// A chunk of every digest the agent holds.
    Snapshot(Snapshot),
    /// A change since the snapshot.
    Delta(Delta),
}

/// The first announcement of a connection.
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

impl TryFrom<proto::AgentMessage> for Request {
    type Error = Malformed;

    fn try_from(message: proto::AgentMessage) -> Result<Self, Malformed> {
        Ok(match message.message.ok_or(Malformed::Empty)? {
            agent_message::Message::Hello(hello) => {
                Self::Announcement(Announcement::Hello(Hello {
                    version: hello.protocol_version,
                    peer: hello
                        .peer_address
                        .parse()
                        .map_err(|_| Malformed::Address(hello.peer_address))?,
                    node: hello.node,
                }))
            }
            agent_message::Message::Snapshot(snapshot) => {
                Self::Announcement(Announcement::Snapshot(Snapshot {
                    digests: digests(snapshot.digests)?,
                    last: snapshot.last,
                    seq: snapshot.seq,
                }))
            }
            agent_message::Message::Delta(delta) => {
                Self::Announcement(Announcement::Delta(Delta {
                    seq: delta.seq,
                    added: digests(delta.added)?,
                    removed: digests(delta.removed)?,
                }))
            }
            agent_message::Message::Lookup(lookup) => Self::Lookup(Lookup {
                id: lookup.id,
                digest: digest(lookup.digest)?,
            }),
            agent_message::Message::Members(proto::MembersRequest {}) => Self::Members,
            agent_message::Message::Ping(proto::Ping {}) => Self::Ping,
        })
    }
}

impl From<Request> for proto::AgentMessage {
    fn from(request: Request) -> Self {
        let texts = |digests: Vec<Digest>| digests.iter().map(ToString::to_string).collect();
        let message = match request {
            Request::Announcement(Announcement::Hello(hello)) => {
                agent_message::Message::Hello(proto::Hello {
                    protocol_version: hello.version,
                    node: hello.node,
                    peer_address: hello.peer.to_string(),
                })
            }
            Request::Announcement(Announcement::Snapshot(snapshot)) => {
                agent_message::Message::Snapshot(proto::Snapshot {
                    digests: texts(snapshot.digests),
                    last: snapshot.last,
                    seq: snapshot.seq,
                })
            }
            Request::Announcement(Announcement::Delta(delta)) => {
                agent_message::Message::Delta(proto::Delta {
                    seq: delta.seq,
                    added: texts(delta.added),
                    removed: texts(delta.removed),
                })
            }
            Request::Lookup(lookup) => agent_message::Message::Lookup(proto::LookupRequest {
                digest: lookup.digest.to_string(),
                id: lookup.id,
            }),
            Request::Members => agent_message::Message::Members(proto::MembersRequest {}),
            Request::Ping => agent_message::Message::Ping(proto::Ping {}),
        };
        Self {
            message: Some(message),
        }
    }
}

/// A digest an agent sent: `<algorithm>:<encoded>`, with an algorithm the OCI image spec registers.
fn digest(text: String) -> Result<Digest, Malformed> {
    Digest::parse(&text).map_err(|_| Malformed::Digest(text))
}

fn digests(texts: Vec<String>) -> Result<Vec<Digest>, Malformed> {
    texts.into_iter().map(digest).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn message(message: agent_message::Message) -> proto::AgentMessage {
        proto::AgentMessage {
            message: Some(message),
        }
    }

    fn hello(address: &str) -> proto::AgentMessage {
        message(agent_message::Message::Hello(proto::Hello {
            protocol_version: 1,
            node: "a".to_owned(),
            peer_address: address.to_owned(),
        }))
    }

    #[test]
    fn a_peer_address_is_an_ip_literal_with_a_port() {
        for address in ["10.0.0.1:7484", "[fd00::1]:7484"] {
            let parsed = Request::try_from(hello(address)).unwrap();
            assert_eq!(proto::AgentMessage::from(parsed), hello(address));
        }
        for address in ["10.0.0.1", "node-a:7484", "fd00::1:7484", ""] {
            let refused = Request::try_from(hello(address)).unwrap_err();
            assert_eq!(refused.reason(), Reason::Address, "{address}");
        }
    }

    #[test]
    fn every_string_of_a_delta_and_a_lookup_is_a_digest() {
        let delta = |removed: &str| {
            message(agent_message::Message::Delta(proto::Delta {
                seq: 3,
                added: vec![DIGEST.to_owned()],
                removed: vec![removed.to_owned()],
            }))
        };
        let digest = Digest::parse(DIGEST).unwrap();
        let parsed = Request::try_from(delta(DIGEST)).unwrap();
        assert_eq!(
            parsed,
            Request::Announcement(Announcement::Delta(Delta {
                seq: 3,
                added: vec![digest.clone()],
                removed: vec![digest.clone()],
            }))
        );
        assert_eq!(proto::AgentMessage::from(parsed), delta(DIGEST));
        let refused = Request::try_from(delta("sha256:short")).unwrap_err();
        assert_eq!(refused, Malformed::Digest("sha256:short".to_owned()));
        assert_eq!(refused.reason(), Reason::Malformed);
        let lookup = |digest: &str| {
            message(agent_message::Message::Lookup(proto::LookupRequest {
                digest: digest.to_owned(),
                id: 9,
            }))
        };
        let parsed = Request::try_from(lookup(DIGEST)).unwrap();
        assert_eq!(parsed, Request::Lookup(Lookup { id: 9, digest }));
        assert_eq!(proto::AgentMessage::from(parsed), lookup(DIGEST));
        let refused = Request::try_from(lookup("latest")).unwrap_err();
        assert_eq!(refused.reason(), Reason::Malformed);
    }

    #[test]
    fn a_message_without_a_variant_is_malformed() {
        let empty = proto::AgentMessage { message: None };
        assert_eq!(Request::try_from(empty), Err(Malformed::Empty));
    }
}
