//! The reflector API as a node reaches it (D2, D97): `Members` over gRPC with curl, which every node image has.

use std::net::SocketAddr;

use crate::{Cluster, Failure};

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

impl Cluster {
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
