//! The policy file (D11, D26, D142): YAML documents, each a `ClusterImagePolicy` of the subset the node verifies,
//! parsed into [`Policies`] or refused with the path of the first field it refuses.

use std::fmt;
use std::path::{Path, PathBuf};

use aws_lc_rs::digest::{Context, SHA256, digest};
use serde::Deserialize;
use speculaire_oci::reference::Reference;
use x509_parser::prelude::FromDer as _;
use x509_parser::x509::SubjectPublicKeyInfo;

use crate::glob::Glob;
use crate::pattern::Pattern;

/// The policies of a node, in file order.
#[derive(Clone, Debug, Default)]
pub struct Policies {
    policies: Vec<Policy>,
}

/// One `ClusterImagePolicy`: the images it covers and what they need to pass it.
#[derive(Clone, Debug)]
pub struct Policy {
    name: String,
    images: Vec<Glob>,
    authorities: Vec<Authority>,
    sbom: Sbom,
    /// The SHA-256 of the document's content, which neither key order, layout nor comments change.
    digest: [u8; 32],
}

/// A way to pass a policy: a signature by its signer, and every attestation it names, signed by that signer too.
#[derive(Clone, Debug)]
pub struct Authority {
    /// The authority's `name`, if the policy gives one.
    pub name: Option<String>,
    /// Who signs.
    pub signer: Signer,
    /// The attestations the image needs, each by its `predicateType`; all of them must pass (D11).
    pub attestations: Vec<Attestation>,
}

/// Who signs for an authority.
#[derive(Clone, Debug)]
pub enum Signer {
    /// A Fulcio certificate whose identity matches one of these; never empty in a parsed policy.
    Keyless {
        /// The accepted identities.
        identities: Vec<Identity>,
    },
    /// A key, written inline in the policy (`key.data`).
    Key {
        /// The key.
        public_key: PublicKey,
    },
}

/// A certificate identity: the OIDC issuer and the subject alternative name.
#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "RawIdentity")]
pub struct Identity {
    /// The OIDC issuer: `issuer` or `issuerRegExp`.
    pub issuer: Matcher,
    /// The SAN: `subject` or `subjectRegExp`.
    pub subject: Matcher,
}

/// What a certificate's issuer or SAN must be.
#[derive(Clone, Debug)]
pub enum Matcher {
    /// This text exactly.
    Exact(String),
    /// Text that the whole pattern matches (D136).
    Pattern(Pattern),
}

/// An attestation an authority requires.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Attestation {
    /// The attestation's name in the policy.
    pub name: String,
    /// The in-toto predicate type it needs, such as `https://slsa.dev/provenance/v1`.
    pub predicate_type: String,
}

/// Whether a policy requires an SBOM (D12), from the extension field `spec.sbom`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sbom {
    /// No `spec.sbom`.
    #[default]
    #[serde(skip)]
    NotRequired,
    /// `spec.sbom: required`.
    Required,
}

/// A public key in DER `SubjectPublicKeyInfo`, read from the PEM block of `key.data`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct PublicKey {
    der: Vec<u8>,
}

/// The hash of a set of policies, the policy part of a verdict's key (D20): the same for the same policies in any order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MatchHash([u8; 32]);

/// Why the policy file was refused.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The file exists but cannot be read.
    #[error("reading the policy file {}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// Why.
        source: std::io::Error,
    },
    /// The file is not a valid policy.
    #[error("the policy file {}", path.display())]
    Parse {
        /// The file.
        path: PathBuf,
        /// Why.
        source: ParseError,
    },
}

/// Why policy text was refused.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// The text is not YAML, or breaks a limit of the YAML parser.
    #[error("{0}")]
    Yaml(String),
    /// A document is not a policy this node can verify.
    #[error("document {document}, {path}: {message}")]
    Document {
        /// The document's number in the file, from 1.
        document: usize,
        /// The field refused, such as `spec.authorities[0].keyless.url`.
        path: String,
        /// Why.
        message: String,
    },
}

impl Policies {
    /// Reads the policy file at `path`. A missing file is no policy (D142).
    ///
    /// # Errors
    ///
    /// When the file exists but cannot be read, or [`Policies::parse`] refuses it.
    pub fn load(path: &Path) -> Result<Self, LoadError> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(source) => {
                return Err(LoadError::Read {
                    path: path.to_owned(),
                    source,
                });
            }
        };
        Self::parse(&text).map_err(|source| LoadError::Parse {
            path: path.to_owned(),
            source,
        })
    }

    /// Parses policy text: YAML documents, each a `ClusterImagePolicy` of `policy.sigstore.dev/v1beta1`.
    ///
    /// # Errors
    ///
    /// When the text is not YAML, or a document holds a field or a value outside D11's subset, or reuses a name.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let options = serde_saphyr::options! {
            duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
        };
        let documents: Vec<serde_json::Value> =
            serde_saphyr::from_multiple_with_options(text, options)
                .map_err(|e| ParseError::Yaml(e.without_snippet().to_string()))?;
        let mut policies: Vec<Policy> = Vec::with_capacity(documents.len());
        for (index, value) in documents.iter().enumerate() {
            let refused = |path: String, message: String| ParseError::Document {
                document: index + 1,
                path,
                message,
            };
            let document: Document = serde_path_to_error::deserialize(value)
                .map_err(|e| refused(e.path().to_string(), e.into_inner().to_string()))?;
            let name = document.metadata.name;
            if policies.iter().any(|policy| policy.name == name) {
                return Err(refused(
                    "metadata.name".to_owned(),
                    format!("`{name}` names an earlier policy too"),
                ));
            }
            policies.push(Policy {
                name,
                images: document
                    .spec
                    .images
                    .into_iter()
                    .map(|image| image.glob)
                    .collect(),
                authorities: document.spec.authorities,
                sbom: document.spec.sbom,
                // Maps print with sorted keys: serde_json's `preserve_order` is off.
                digest: sha256(value.to_string().as_bytes()),
            });
        }
        Ok(Self { policies })
    }

    /// The policies, in file order.
    pub fn iter(&self) -> impl Iterator<Item = &Policy> {
        self.policies.iter()
    }

    /// The policies that match `reference`: those with a glob that matches its name (D11). The image must pass all.
    pub fn matching(&self, reference: &Reference) -> impl Iterator<Item = &Policy> {
        let name = reference.name();
        self.policies
            .iter()
            .filter(move |policy| policy.images.iter().any(|glob| glob.is_match(&name)))
    }
}

impl Policy {
    /// The policy's `metadata.name`, unique in its file.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The globs of `spec.images`; never empty.
    #[must_use]
    pub fn images(&self) -> &[Glob] {
        &self.images
    }

    /// The authorities, of which one must pass (D11); never empty.
    #[must_use]
    pub fn authorities(&self) -> &[Authority] {
        &self.authorities
    }

    /// Whether the policy requires an SBOM.
    #[must_use]
    pub fn sbom(&self) -> Sbom {
        self.sbom
    }
}

impl Matcher {
    /// Whether `text` is what the matcher accepts, all of it.
    #[must_use]
    pub fn matches(&self, text: &str) -> bool {
        match self {
            Self::Exact(exact) => exact == text,
            Self::Pattern(pattern) => pattern.is_match(text),
        }
    }
}

impl PublicKey {
    /// The DER `SubjectPublicKeyInfo`.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }
}

impl TryFrom<String> for PublicKey {
    type Error = String;

    fn try_from(pem: String) -> Result<Self, Self::Error> {
        let (rest, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes())
            .map_err(|e| format!("not a PEM block: {e}"))?;
        if !rest.iter().all(u8::is_ascii_whitespace) {
            return Err("holds more than one PEM block".to_owned());
        }
        if block.label != "PUBLIC KEY" {
            return Err(format!("is a PEM `{}`, not a `PUBLIC KEY`", block.label));
        }
        match SubjectPublicKeyInfo::from_der(&block.contents) {
            Ok(([], _)) => Ok(Self {
                der: block.contents,
            }),
            Ok(_) => Err("has bytes after its SubjectPublicKeyInfo".to_owned()),
            Err(e) => Err(format!("is not a SubjectPublicKeyInfo: {e}")),
        }
    }
}

impl MatchHash {
    /// The hash of `policies`: the SHA-256 of their content digests, sorted.
    #[must_use]
    pub fn of<'a>(policies: impl IntoIterator<Item = &'a Policy>) -> Self {
        let mut digests: Vec<[u8; 32]> = policies.into_iter().map(|policy| policy.digest).collect();
        digests.sort_unstable();
        let mut context = Context::new(&SHA256);
        for digest in &digests {
            context.update(digest);
        }
        Self(to_array(&context.finish()))
    }

    /// The hash's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for MatchHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    to_array(&digest(&SHA256, bytes))
}

fn to_array(hashed: &aws_lc_rs::digest::Digest) -> [u8; 32] {
    hashed
        .as_ref()
        .try_into()
        .expect("a SHA-256 digest is 32 bytes")
}

/// A document of the file, as written.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Document {
    #[serde(rename = "apiVersion")]
    _api_version: ApiVersion,
    #[serde(rename = "kind")]
    _kind: Kind,
    metadata: Metadata,
    spec: Spec,
}

#[derive(Deserialize)]
enum ApiVersion {
    #[serde(rename = "policy.sigstore.dev/v1beta1")]
    V1beta1,
}

#[derive(Deserialize)]
enum Kind {
    ClusterImagePolicy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    #[serde(deserialize_with = "non_empty")]
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    #[serde(deserialize_with = "non_empty")]
    images: Vec<Image>,
    #[serde(deserialize_with = "non_empty")]
    authorities: Vec<Authority>,
    #[serde(default)]
    sbom: Sbom,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Image {
    glob: Glob,
}

impl<'de> Deserialize<'de> for Authority {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawAuthority::deserialize(deserializer)?;
        let signer = match (raw.key, raw.keyless) {
            (Some(key), None) => Signer::Key {
                public_key: key.data,
            },
            (None, Some(keyless)) => Signer::Keyless {
                identities: keyless.identities,
            },
            (Some(_), Some(_)) => {
                return Err(serde::de::Error::custom("set key or keyless, not both"));
            }
            (None, None) => return Err(serde::de::Error::custom("set key or keyless")),
        };
        Ok(Self {
            name: raw.name,
            signer,
            attestations: raw.attestations,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAuthority {
    name: Option<String>,
    key: Option<Key>,
    keyless: Option<Keyless>,
    #[serde(default)]
    attestations: Vec<Attestation>,
}

/// `key`: only `data`, a PEM block inline; `kms` and `secretRef` need a cluster (D142).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Key {
    data: PublicKey,
}

/// `keyless`: only `identities`; the node has one trust root (D26), so `url`, `ca-cert` and `trustRootRef` are refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Keyless {
    #[serde(deserialize_with = "non_empty")]
    identities: Vec<Identity>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawIdentity {
    issuer: Option<String>,
    issuer_reg_exp: Option<String>,
    subject: Option<String>,
    subject_reg_exp: Option<String>,
}

impl TryFrom<RawIdentity> for Identity {
    type Error = String;

    fn try_from(raw: RawIdentity) -> Result<Self, Self::Error> {
        Ok(Self {
            issuer: matcher("issuer", raw.issuer, raw.issuer_reg_exp)?,
            subject: matcher("subject", raw.subject, raw.subject_reg_exp)?,
        })
    }
}

/// One of `field` and `fieldRegExp`; an empty value is no value, as in Go's `omitempty`.
fn matcher(field: &str, exact: Option<String>, pattern: Option<String>) -> Result<Matcher, String> {
    let given = |value: Option<String>| value.filter(|value| !value.is_empty());
    match (given(exact), given(pattern)) {
        (Some(exact), None) => Ok(Matcher::Exact(exact)),
        (None, Some(pattern)) => Pattern::new(&pattern)
            .map(Matcher::Pattern)
            .map_err(|e| format!("{field}RegExp {e}")),
        (Some(_), Some(_)) => Err(format!("set {field} or {field}RegExp, not both")),
        (None, None) => Err(format!("set {field} or {field}RegExp")),
    }
}

/// A value that must not be empty: a name, or a list that needs at least one entry.
fn non_empty<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + IsEmpty,
{
    let value = T::deserialize(deserializer)?;
    if value.is_empty() {
        return Err(serde::de::Error::custom("must not be empty"));
    }
    Ok(value)
}

trait IsEmpty {
    fn is_empty(&self) -> bool;
}

impl IsEmpty for String {
    fn is_empty(&self) -> bool {
        str::is_empty(self)
    }
}

impl<T> IsEmpty for Vec<T> {
    fn is_empty(&self) -> bool {
        <[T]>::is_empty(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../../packaging/policy.yaml");

    /// A policy named `name` over `glob`, with `authority` as its one authority (indented as a list item) and `spec`
    /// added to its spec.
    fn policy(name: &str, glob: &str, authority: &str, spec: &str) -> String {
        format!(
            "apiVersion: policy.sigstore.dev/v1beta1\nkind: ClusterImagePolicy\nmetadata:\n  name: {name}\nspec:\n  \
             images:\n  - glob: \"{glob}\"\n  authorities:\n  - {authority}\n{spec}"
        )
    }

    const KEYLESS: &str = "keyless:\n      identities:\n      - issuer: https://issuer.example\n        \
                           subjectRegExp: https://github.com/myorg/.*";

    fn reference(text: &str) -> Reference {
        Reference::parse_docker_ref(text).unwrap()
    }

    fn names<'a>(policies: impl Iterator<Item = &'a Policy>) -> Vec<&'a str> {
        policies.map(Policy::name).collect()
    }

    #[test]
    fn the_example_parses_into_its_policies() {
        let policies = Policies::parse(EXAMPLE).unwrap();
        assert_eq!(names(policies.iter()), ["myorg-releases", "vendor-key"]);
        let [releases, vendor] = &policies.policies[..] else {
            panic!("two policies");
        };
        assert_eq!(releases.images()[0].to_string(), "ghcr.io/myorg/**");
        assert_eq!(releases.sbom(), Sbom::Required);
        assert_eq!(vendor.sbom(), Sbom::NotRequired);
        let Signer::Keyless { identities } = &releases.authorities()[0].signer else {
            panic!("keyless");
        };
        assert!(
            matches!(&identities[0].issuer, Matcher::Exact(issuer) if issuer == "https://token.actions.githubusercontent.com")
        );
        assert_eq!(
            releases.authorities()[0].attestations[0].predicate_type,
            "https://slsa.dev/provenance/v1"
        );
        let Signer::Key { public_key } = &vendor.authorities()[0].signer else {
            panic!("key");
        };
        assert_eq!(public_key.der().len(), 91, "a P-256 SubjectPublicKeyInfo");
        assert_eq!(
            names(policies.matching(&reference("ghcr.io/myorg/app/api:v1"))),
            ["myorg-releases"]
        );
        assert_eq!(
            names(policies.matching(&reference("nginx"))),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn a_subject_pattern_matches_the_whole_san() {
        let policies = Policies::parse(&policy("p", "**", KEYLESS, "")).unwrap();
        let Signer::Keyless { identities } = &policies.policies[0].authorities()[0].signer else {
            panic!("keyless");
        };
        let subject = &identities[0].subject;
        assert!(
            subject.matches(
                "https://github.com/myorg/app/.github/workflows/release.yml@refs/heads/main"
            )
        );
        assert!(!subject.matches("https://github.com/myorg-evil/x"));
        assert!(!subject.matches("https://evil.example/https://github.com/myorg/x"));
        assert!(identities[0].issuer.matches("https://issuer.example"));
        assert!(!identities[0].issuer.matches("https://issuer.example/"));
    }

    #[test]
    fn each_construct_outside_the_subset_is_refused_with_its_path() {
        let keyless = |extra: &str| format!("{KEYLESS}\n    {extra}");
        for (text, path) in [
            (
                policy("p", "**", KEYLESS, "").replace("v1beta1", "v1alpha1"),
                "document 1, apiVersion:",
            ),
            (
                policy("p", "**", KEYLESS, "")
                    .replace("kind: ClusterImagePolicy", "kind: ImagePolicy"),
                "document 1, kind:",
            ),
            (
                policy("p", "**", KEYLESS, "").replace("  name: p", "  name: p\n  namespace: n"),
                "metadata.namespace:",
            ),
            (
                policy(r#""""#, "**", KEYLESS, ""),
                "metadata.name: must not be empty",
            ),
            (policy("p", "**", KEYLESS, "  mode: warn"), "spec.mode:"),
            (
                policy("p", "**", KEYLESS, "  policy:\n    type: cue\n    data: x"),
                "spec.policy:",
            ),
            (
                policy("p", "**", KEYLESS, "  match:\n  - resource: pods"),
                "spec.match:",
            ),
            (policy("p", "**", KEYLESS, "  sbom: optional"), "spec.sbom:"),
            (
                policy("p", "ghcr.io/app:v1", KEYLESS, ""),
                "spec.images[0].glob:",
            ),
            (
                policy("p", "ghcr.io/**", KEYLESS, "")
                    .replace("images:\n  - glob: \"ghcr.io/**\"\n", "images: []\n"),
                "spec.images:",
            ),
            (
                policy(
                    "p",
                    "**",
                    "keyless:\n      url: https://fulcio.example\n      identities:\n      - issuer: i\n        subject: s",
                    "",
                ),
                "spec.authorities[0].keyless.url:",
            ),
            (
                policy("p", "**", "keyless:\n      ca-cert:\n        data: x", ""),
                "spec.authorities[0].keyless.ca-cert:",
            ),
            (
                policy("p", "**", "keyless:\n      trustRootRef: r", ""),
                "spec.authorities[0].keyless.trustRootRef:",
            ),
            (
                policy("p", "**", "keyless:\n      identities: []", ""),
                "spec.authorities[0].keyless.identities:",
            ),
            (
                policy(
                    "p",
                    "**",
                    &keyless("ctlog:\n      url: https://rekor.example"),
                    "",
                ),
                "spec.authorities[0].ctlog:",
            ),
            (
                policy(
                    "p",
                    "**",
                    &keyless("rfc3161timestamp:\n      trustRootRef: r"),
                    "",
                ),
                "spec.authorities[0].rfc3161timestamp:",
            ),
            (
                policy("p", "**", "static:\n      action: pass", ""),
                "spec.authorities[0].static:",
            ),
            (
                policy(
                    "p",
                    "**",
                    &keyless("source:\n    - oci: registry.example/sigs"),
                    "",
                ),
                "spec.authorities[0].source:",
            ),
            (
                policy(
                    "p",
                    "**",
                    &keyless(
                        "attestations:\n    - name: a\n      predicateType: t\n      policy:\n        type: rego",
                    ),
                    "",
                ),
                "spec.authorities[0].attestations[0].policy:",
            ),
            (
                policy("p", "**", "key:\n      kms: awskms:///k", ""),
                "spec.authorities[0].key.kms:",
            ),
            (
                policy("p", "**", "key:\n      secretRef:\n        name: k", ""),
                "spec.authorities[0].key.secretRef:",
            ),
            (
                policy("p", "**", "key:\n      data: not a key", ""),
                "spec.authorities[0].key.data:",
            ),
            (
                policy("p", "**", "name: a", ""),
                "spec.authorities[0]: set key or keyless",
            ),
            (
                EXAMPLE.replace(
                    "  - key:\n",
                    "  - keyless:\n      identities:\n      - issuer: i\n        subject: s\n    key:\n",
                ),
                "document 2, spec.authorities[0]: set key or keyless, not both",
            ),
            (
                policy(
                    "p",
                    "**",
                    &format!("key:\n      data: x\n    {KEYLESS}"),
                    "",
                ),
                "spec.authorities[0].key.data:",
            ),
            (
                policy(
                    "p",
                    "**",
                    "keyless:\n      identities:\n      - issuer: i\n        issuerRegExp: i\n        subject: s",
                    "",
                ),
                "spec.authorities[0].keyless.identities[0]: set issuer or issuerRegExp, not both",
            ),
            (
                policy(
                    "p",
                    "**",
                    "keyless:\n      identities:\n      - issuer: i",
                    "",
                ),
                "spec.authorities[0].keyless.identities[0]: set subject or subjectRegExp",
            ),
            (
                policy(
                    "p",
                    "**",
                    "keyless:\n      identities:\n      - issuer: i\n        subjectRegExp: a)|(.*",
                    "",
                ),
                "spec.authorities[0].keyless.identities[0]: subjectRegExp `a)|(.*`",
            ),
            (
                format!(
                    "{}---\n{}",
                    policy("p", "**", KEYLESS, ""),
                    policy("p", "**", KEYLESS, "")
                ),
                "document 2, metadata.name: `p` names an earlier policy too",
            ),
        ] {
            let refused = Policies::parse(&text).unwrap_err().to_string();
            assert!(
                refused.contains(path),
                "{refused}\ndoes not name {path}, in\n{text}"
            );
        }
    }

    #[test]
    fn text_that_is_not_yaml_or_has_a_key_twice_is_refused() {
        assert!(matches!(
            Policies::parse("spec: ["),
            Err(ParseError::Yaml(_))
        ));
        let twice = policy("p", "**", KEYLESS, "").replace("  name: p", "  name: p\n  name: q");
        assert!(matches!(Policies::parse(&twice), Err(ParseError::Yaml(_))));
    }

    #[test]
    fn an_image_matched_by_two_policies_gets_both() {
        let text = [
            policy("org", "ghcr.io/myorg/**", KEYLESS, ""),
            policy("app", "ghcr.io/*/app", KEYLESS, ""),
            policy("other", "ghcr.io/other/**", KEYLESS, ""),
        ]
        .join("---\n");
        let policies = Policies::parse(&text).unwrap();
        assert_eq!(
            names(policies.matching(&reference("ghcr.io/myorg/app:v1"))),
            ["org", "app"]
        );
        assert_eq!(
            names(policies.matching(&reference("ghcr.io/myorg/api"))),
            ["org"]
        );
    }

    #[test]
    fn the_match_hash_depends_on_the_policies_not_their_order_or_layout() {
        let (org, app) = (
            policy("org", "ghcr.io/myorg/**", KEYLESS, ""),
            policy("app", "ghcr.io/*/app", KEYLESS, ""),
        );
        let hash = |text: &str| {
            let policies = Policies::parse(text).unwrap();
            MatchHash::of(policies.matching(&reference("ghcr.io/myorg/app")))
        };
        let forward = hash(&format!("{org}---\n{app}"));
        assert_eq!(forward, hash(&format!("{app}---\n{org}")));
        // Another key order and layout, and comments.
        let reordered = format!(
            "# a comment\nkind: ClusterImagePolicy\napiVersion: policy.sigstore.dev/v1beta1\nmetadata: {{name: org}}\n\
             spec:\n  authorities:\n  - {KEYLESS}\n  images: [{{glob: \"ghcr.io/myorg/**\"}}]\n"
        );
        assert_eq!(forward, hash(&format!("{app}---\n{reordered}")));
        assert_ne!(
            forward,
            hash(&format!(
                "{org}---\n{}",
                app.replace("myorg/.*", "myorg/x.*")
            ))
        );
        assert_ne!(forward, hash(&org));
        assert_eq!(forward.to_string().len(), 64);
        assert_eq!(MatchHash::of([]).as_bytes(), &sha256(b""));
    }

    #[test]
    fn a_missing_file_is_no_policy_and_an_unreadable_one_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            Policies::load(&dir.path().join("policy.yaml"))
                .unwrap()
                .iter()
                .count(),
            0
        );
        assert!(matches!(
            Policies::load(dir.path()),
            Err(LoadError::Read { .. })
        ));
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, EXAMPLE).unwrap();
        assert_eq!(Policies::load(&path).unwrap().iter().count(), 2);
        std::fs::write(&path, "kind: x\n").unwrap();
        let refused = Policies::load(&path).unwrap_err().to_string();
        assert_eq!(refused, format!("the policy file {}", path.display()));
    }

    #[test]
    fn a_public_key_is_one_pem_spki_block() {
        let pem = EXAMPLE
            .split("data: |\n")
            .nth(1)
            .unwrap()
            .lines()
            .map(str::trim)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(PublicKey::try_from(pem.clone()).is_ok());
        assert!(
            PublicKey::try_from(format!("{pem}\n{pem}"))
                .unwrap_err()
                .contains("more than one")
        );
        let certificate = pem.replace("PUBLIC KEY", "CERTIFICATE");
        assert!(
            PublicKey::try_from(certificate)
                .unwrap_err()
                .contains("not a `PUBLIC KEY`")
        );
        // The last quantum of the key's base64, `Tg==`, one byte, becomes that byte and two zeros.
        assert!(pem.contains("Tg=="));
        assert!(
            PublicKey::try_from(pem.replace("Tg==", "TgAA"))
                .unwrap_err()
                .contains("bytes after")
        );
        assert!(
            PublicKey::try_from(
                "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n".to_owned()
            )
            .unwrap_err()
            .contains("not a SubjectPublicKeyInfo")
        );
    }
}
