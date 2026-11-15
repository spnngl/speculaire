//! The reflector API as a node reaches it (D2, D97, D105): `Members` and `Lookup` as frames over TLS with
//! `openssl s_client`, which every node image has.

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};

use crate::registry::fail;
use crate::upstream::Digest;
use crate::{Cluster, Failure, IpFamily};

/// kubelet's client certificate and key, in one file (D16).
pub const KUBELET: &str = "/var/lib/kubelet/pki/kubelet-client-current.pem";

/// The `AgentMessage` of `Members`: field 5, an empty `MembersRequest`.
const MEMBERS: &[u8] = &[0x2a, 0x00];

/// What a reflector answered to `Members`.
#[derive(Debug)]
pub struct Answer {
    /// The node of the certificate it presented: the `<name>` of `CN=system:node:<name>`.
    pub node: String,
    /// That certificate's serial number, as `openssl x509 -serial` prints it.
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

/// How `node` reaches a reflector: its address, and the certificate it presents.
struct Call<'a> {
    node: &'a str,
    address: SocketAddr,
    certificate: &'a str,
    key: Option<&'a str>,
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

    /// Looks `digest` up from `node` on the reflector at `address`, with kubelet's certificate, and returns the
    /// holders, sorted.
    ///
    /// # Errors
    ///
    /// When the connection fails, or the answer is no lookup's.
    pub fn lookup(
        &self,
        node: &str,
        address: SocketAddr,
        digest: &Digest,
    ) -> Result<Vec<Holder>, Failure> {
        let command = format!("Lookup {digest} from {node} at {address}");
        // The `AgentMessage` of field 4, a `LookupRequest` of the digest in field 1 and the number 0, unwritten.
        let request = length_delimited(1, digest.to_string().as_bytes())
            .and_then(|request| length_delimited(4, &request))
            .ok_or_else(|| fail(&command, &"a digest of 128 bytes or more"))?;
        let call = Call {
            node,
            address,
            certificate: KUBELET,
            key: None,
        };
        let out = self.call(&call, &request, "")?;
        let mut holders =
            holders(&out).ok_or_else(|| fail(&command, &format!("unparsable answer {out}")))?;
        holders.sort();
        Ok(holders)
    }

    /// Calls `Members` from `node` on the reflector at `address`, presenting `certificate` and the key in `key`, or in
    /// `certificate` when `None`.
    ///
    /// The certificate comes from a second connection: through the balancer, both reach a reflector of the list.
    ///
    /// # Errors
    ///
    /// When the connection fails, as when the reflector refuses the certificate, or the answer is no `Members`'.
    pub fn members(
        &self,
        node: &str,
        address: SocketAddr,
        certificate: &str,
        key: Option<&str>,
    ) -> Result<Answer, Failure> {
        let call = Call {
            node,
            address,
            certificate,
            key,
        };
        let out = self.call(
            &call,
            MEMBERS,
            &format!(
                "openssl s_client -verify_quiet -alpn {ALPN} -connect {address} {} </dev/null 2>/dev/null \
                 | openssl x509 -noout -subject -serial",
                presented(&call)
            ),
        )?;
        let command = format!("Members from {node} at {address}");
        let field = |prefix: &str| {
            out.lines()
                .find_map(|line| line.trim().strip_prefix(prefix))
                .map(|value| value.trim().to_owned())
                .ok_or_else(|| fail(&command, &format!("no {prefix:?} in {out}")))
        };
        let subject = field("subject=")?;
        let response = out
            .lines()
            .next()
            .and_then(unhex)
            .and_then(|message| field_of(&message, 4))
            .ok_or_else(|| fail(&command, &format!("no `Members` answer in {out}")))?;
        Ok(Answer {
            node: subject
                .rsplit_once("CN=system:node:")
                .map(|(_, name)| name.to_owned())
                .ok_or_else(|| fail(&command, &format!("no node in the subject {subject:?}")))?,
            serial: field("serial=")?,
            members: response
                .iter()
                .map(|&byte| {
                    if byte.is_ascii_graphic() {
                        char::from(byte)
                    } else {
                        ' '
                    }
                })
                .collect(),
        })
    }

    /// Sends `request` as one frame on a connection of `call`, prints the message of the first frame back in hex on
    /// a line, then runs `after`.
    fn call(&self, call: &Call<'_>, request: &[u8], after: &str) -> Result<String, Failure> {
        let mut frame = String::new();
        let length =
            u32::try_from(request.len()).map_err(|_| fail("frame a request", &"over 4 GiB"))?;
        for byte in length.to_be_bytes().iter().chain(request) {
            write!(frame, "\\{byte:03o}").map_err(|e| fail("frame a request", &e.to_string()))?;
        }
        // Bash closes a coprocess's descriptors in subshells: `bytes` reads a copy. `dd bs=1` reads no byte past the
        // count, and `timeout` bounds a reflector that never answers.
        let script = format!(
            r#"set -euo pipefail; work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
coproc TLS {{ exec timeout 10 openssl s_client -quiet -no_ign_eof -verify_quiet -alpn {ALPN} \
  -connect {address} {presented} 2>"$work/err"; }}
pid=$TLS_PID; exec {{in}}>&"${{TLS[1]}}" {{out}}<&"${{TLS[0]}}" {{TLS[1]}}>&-
bytes() {{ dd bs=1 count="$1" status=none <&"$out" | od -An -v -tx1 | tr -d ' \n'; }}
printf '{frame}' >&"$in"
head=$(bytes 4)
[ ${{#head}} = 8 ] || {{ cat "$work/err" >&2; exit 1; }}
bytes $((16#$head)); echo
exec {{in}}>&-; wait "$pid" || true
{after}"#,
            address = call.address,
            presented = presented(call),
        );
        self.exec(call.node, &["bash", "-c", &script])
    }
}

/// The ALPN protocol of the reflector API (`speculaire_reflect::frame::ALPN`).
const ALPN: &str = "speculaire-reflect/1";

/// The `s_client` options that present `call`'s certificate.
fn presented(call: &Call<'_>) -> String {
    let key = call
        .key
        .map_or_else(String::new, |key| format!(" -key {key}"));
    format!("-cert {}{key}", call.certificate)
}

/// Field `number` of wire type 2 holding `value`, whose length must fit one byte of varint.
fn length_delimited(number: u8, value: &[u8]) -> Option<Vec<u8>> {
    let length = u8::try_from(value.len())
        .ok()
        .filter(|length| *length < 0x80)?;
    let mut field = vec![number << 3 | 2, length];
    field.extend_from_slice(value);
    Some(field)
}

/// The holders of a `ReflectorMessage` answering a lookup, from the hex on the first line of `out`: field 3, a
/// `LookupResponse` of `repeated Peer peers = 1`, each `Peer` of `string node = 1` and `string address = 2`
/// (`crates/reflect/proto`).
fn holders(out: &str) -> Option<Vec<Holder>> {
    let message = unhex(out.lines().next()?)?;
    fields(&field_of(&message, 3)?)?
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

/// The value of field `number` of `message`, whose fields are all length-delimited.
fn field_of(message: &[u8], number: u64) -> Option<Vec<u8>> {
    fields(message)?
        .into_iter()
        .find(|(n, _)| *n == number)
        .map(|(_, value)| value.to_vec())
}

/// The bytes of `hex`, two digits a byte, as `od -An -v -tx1 | tr -d ' \n'` writes them.
pub(crate) fn unhex(hex: &str) -> Option<Vec<u8>> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
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
        // A `ReflectorMessage` of field 3, then two peers, the second with an unknown field 3.
        let hex = concat!(
            "1a25",
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
        assert_eq!(holders("1a00"), Some(vec![]));
        // A refusal, of a varint reason, and a `Members` answer: no lookup's.
        assert_eq!(holders("32020803"), None);
        assert_eq!(holders("2200"), None);
    }

    #[test]
    fn a_lookup_request_holds_the_digest_in_a_lookup() {
        let lookup = length_delimited(1, b"d").and_then(|request| length_delimited(4, &request));
        assert_eq!(lookup, Some(vec![0x22, 3, 0x0a, 1, b'd']));
        assert_eq!(length_delimited(1, &[0; 0x80]), None);
    }
}
