//! The reflector API as a node reaches it (D2, D97): `Members` and `Lookup` over gRPC with curl, which every node
//! image has.

use std::net::{IpAddr, SocketAddr};

use crate::registry::fail;
use crate::upstream::Digest;
use crate::{Cluster, Failure, IpFamily};

/// kubelet's client certificate and key, in one file (D16).
pub const KUBELET: &str = "/var/lib/kubelet/pki/kubelet-client-current.pem";

/// What a reflector answered to `Members`.
#[derive(Debug)]
pub struct Answer {
    /// The node of the certificate it presented: the `<name>` of `CN=system:node:<name>`.
    pub node: String,
    /// That certificate's serial number, as curl prints it.
    pub serial: String,
    /// The response's protobuf with every unprintable byte as a space: the members' names and addresses show.
    pub members: String,
}

/// A node a reflector returned for a digest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Holder {
    /// Its node name.
    pub node: String,
    /// The peer address it announced, `ip:port` as it sent it.
    pub address: String,
}

impl Cluster {
    /// The IP `reflector.members` and the peer addresses use for `node`: IPv6 on a dual-stack cluster (D94).
    ///
    /// # Errors
    ///
    /// When `kubectl` fails, or it lists no such node.
    pub fn family_address(&self, node: &str) -> Result<IpAddr, Failure> {
        let found = self
            .nodes()?
            .into_iter()
            .find(|n| n.name == node)
            .ok_or_else(|| fail("find a node", &format!("no node {node}")))?;
        let address = match (self.family, found.ipv6) {
            (IpFamily::Dual, Some(ipv6)) => ipv6,
            _ => found.address,
        };
        address
            .parse()
            .map_err(|e| fail("parse a node's address", &format!("{address:?}: {e}")))
    }

    /// Calls `Lookup` of `digest` from `node` on the reflector at `address`, with kubelet's certificate, and returns
    /// the holders, sorted.
    ///
    /// # Errors
    ///
    /// When curl fails, the call ends with a gRPC status other than `OK`, or the answer does not parse.
    pub fn lookup(
        &self,
        node: &str,
        address: SocketAddr,
        digest: &Digest,
    ) -> Result<Vec<Holder>, Failure> {
        // The `LookupRequest`: a gRPC frame of no flags and length 73, then field 1 (tag 0x0a) of length 71 (`G`).
        let script = format!(
            r#"set -e; body=$(mktemp); headers=$(mktemp); trap 'rm -f "$body" "$headers"' EXIT
printf '\000\000\000\000\111\012\107%s' '{digest}' | curl -sSg --http2 -k --max-time 5 --cert {KUBELET} \
  -H 'content-type: application/grpc' -H 'te: trailers' --data-binary @- -o "$body" -D "$headers" \
  https://{address}/speculaire.reflect.v1.Reflector/Lookup
grep -q 'grpc-status: 0' "$headers" || {{ cat "$headers" >&2; exit 1; }}
od -An -v -tx1 "$body" | tr -d ' \n'"#
        );
        let hex = self.exec(node, &["sh", "-c", &script])?;
        let command = format!("Lookup {digest} from {node} at {address}");
        let mut holders =
            holders(&hex).ok_or_else(|| fail(&command, &format!("unparsable answer {hex}")))?;
        holders.sort();
        Ok(holders)
    }

    /// Calls `Members` from `node` on the reflector at `address`, presenting `certificate` and the key in `key`, or in
    /// `certificate` when `None`.
    ///
    /// # Errors
    ///
    /// When curl fails, as when the reflector refuses the certificate, or the call ends with a gRPC status other
    /// than `OK`.
    pub fn members(
        &self,
        node: &str,
        address: SocketAddr,
        certificate: &str,
        key: Option<&str>,
    ) -> Result<Answer, Failure> {
        let key = key.map_or_else(String::new, |key| format!("--key {key}"));
        // The empty `MembersRequest`: a gRPC frame of no flags and length 0. `-g` keeps an IPv6 literal from curl's
        // URL globbing; `%{certs}` prints the server's certificate.
        let script = format!(
            r#"set -e; body=$(mktemp); headers=$(mktemp); trap 'rm -f "$body" "$headers"' EXIT
printf '\0\0\0\0\0' | curl -sSg --http2 -k --max-time 5 --cert {certificate} {key} \
  -H 'content-type: application/grpc' -H 'te: trailers' --data-binary @- -o "$body" -D "$headers" \
  -w '%{{certs}}' https://{address}/speculaire.reflect.v1.Reflector/Members
grep -q 'grpc-status: 0' "$headers" || {{ cat "$headers" >&2; exit 1; }}
echo; echo "Members: $(tr -c '[:print:]' ' ' <"$body")""#
        );
        let out = self.exec(node, &["sh", "-c", &script])?;
        let field = |prefix: &str| {
            out.lines()
                .find_map(|line| line.trim().strip_prefix(prefix))
                .map(|value| value.trim().to_owned())
                .ok_or_else(|| Failure {
                    command: format!("Members from {node} at {address}"),
                    detail: format!("no {prefix:?} in {out}"),
                })
        };
        let subject = field("Subject:")?;
        Ok(Answer {
            node: subject
                .rsplit_once("CN = system:node:")
                .map(|(_, name)| name.to_owned())
                .ok_or_else(|| Failure {
                    command: format!("Members from {node} at {address}"),
                    detail: format!("no node in the subject {subject:?}"),
                })?,
            serial: field("Serial Number:")?,
            members: field("Members:")?,
        })
    }
}

/// The holders of a `LookupResponse` in a gRPC frame, from its hex: `repeated Peer peers = 1`, each `Peer` of
/// `string node = 1` and `string address = 2` (`crates/reflect/proto`).
fn holders(hex: &str) -> Option<Vec<Holder>> {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect::<Option<_>>()?;
    fields(bytes.get(5..)?)?
        .into_iter()
        .filter(|(number, _)| *number == 1)
        .map(|(_, peer)| {
            let mut holder = Holder {
                node: String::new(),
                address: String::new(),
            };
            for (number, value) in fields(peer)? {
                let text = String::from_utf8(value.to_vec()).ok()?;
                match number {
                    1 => holder.node = text,
                    2 => holder.address = text,
                    _ => {}
                }
            }
            Some(holder)
        })
        .collect()
}

/// The length-delimited fields of a protobuf message, with their numbers; `None` at any other wire type.
fn fields(mut bytes: &[u8]) -> Option<Vec<(u64, &[u8])>> {
    let mut fields = Vec::new();
    while !bytes.is_empty() {
        let key = varint(&mut bytes)?;
        if key & 7 != 2 {
            return None;
        }
        let length = usize::try_from(varint(&mut bytes)?).ok()?;
        let (value, rest) = bytes.split_at_checked(length)?;
        fields.push((key >> 3, value));
        bytes = rest;
    }
    Some(fields)
}

fn varint(bytes: &mut &[u8]) -> Option<u64> {
    let mut value = 0_u64;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = bytes.split_first()?;
        *bytes = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lookup_answer_reads_as_its_holders() {
        // A frame header, then two peers, the second with an unknown field 3.
        let hex = concat!(
            "0000000025",
            "0a0f",
            "0a0161",
            "120a",
            "31302e302e302e313a31",
            "0a12",
            "0a0162",
            "120a",
            "5b3a3a315d3a37343831",
            "1a0178",
        );
        assert_eq!(
            holders(hex),
            Some(vec![
                Holder {
                    node: "a".to_owned(),
                    address: "10.0.0.1:1".to_owned()
                },
                Holder {
                    node: "b".to_owned(),
                    address: "[::1]:7481".to_owned()
                },
            ])
        );
        assert_eq!(holders("00000000000a"), None);
        assert_eq!(holders("0000000000"), Some(vec![]));
    }
}
