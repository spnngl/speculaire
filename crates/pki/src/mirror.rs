//! The mirror's local CA, server certificate and client certificate (D14).
//!
//! `speculaire configure` generates them once. The agent's mirror serves with the server certificate and accepts only
//! clients that the CA signed; the runtime presents the client certificate (D14, D66). The CA's own key is dropped
//! after signing: when anything has to change, everything is generated again (D82).

use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use secrecy::{ExposeSecret, SecretString};
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::pem::parse_x509_pem;
use x509_parser::time::ASN1Time;

/// How long a certificate is valid: the key is root-only and local (D14), so a long life costs nothing.
pub const VALIDITY: Duration = days(3650);

/// How long before expiry a certificate counts as expired, for [`Mirror::check`]: `configure` renews it by then (D82).
pub const RENEW_BEFORE: Duration = days(30);

/// How far back a new certificate's validity starts, so that a node whose clock is a little behind accepts it.
const BACKDATE: Duration = Duration::from_hours(1);

const fn days(days: u64) -> Duration {
    Duration::from_hours(days * 24)
}

/// One of the four files of the mirror's directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Part {
    /// The CA certificate: `ca` of every `hosts.toml` entry, and what the mirror checks clients against.
    Ca,
    /// The mirror's own certificate, for the mirror's address.
    ServerCertificate,
    /// The key of the server certificate.
    ServerKey,
    /// The client certificate and its key in one PEM, as containerd's `client` reads it (D14).
    Client,
}

impl Part {
    /// All four, in the order `configure` writes them.
    pub const ALL: [Self; 4] = [
        Self::Ca,
        Self::ServerCertificate,
        Self::ServerKey,
        Self::Client,
    ];

    /// The file's name in the mirror's directory.
    #[must_use]
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::Ca => "ca.crt",
            Self::ServerCertificate => "server.crt",
            Self::ServerKey => "server.key",
            Self::Client => "client.pem",
        }
    }

    /// Whether the file holds a private key, and so is written readable by its owner only (D55).
    #[must_use]
    pub const fn is_secret(self) -> bool {
        matches!(self, Self::ServerKey | Self::Client)
    }
}

/// Why the files of the mirror's directory cannot be used as they are.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("{}: {reason}", part.file_name())]
pub struct Problem {
    /// The file.
    pub part: Part,
    /// What is wrong with it.
    pub reason: String,
}

impl Problem {
    fn new(part: Part, reason: impl Into<String>) -> Self {
        Self {
            part,
            reason: reason.into(),
        }
    }
}

/// Certificates could not be made.
#[derive(Debug, thiserror::Error)]
#[error("cannot generate the mirror certificates: {0}")]
pub struct GenerateError(#[from] rcgen::Error);

/// The mirror's CA and certificates.
#[derive(Clone, Debug)]
pub struct Mirror {
    ca: String,
    server_certificate: String,
    server_key: SecretString,
    client_certificate: String,
    client_key: SecretString,
}

impl Mirror {
    /// A new CA, a server certificate for `ip` signed by it, and a client certificate signed by it. They are valid
    /// from an hour before `now` for [`VALIDITY`].
    ///
    /// # Errors
    ///
    /// When the crypto provider cannot make a key or a signature.
    pub fn generate(ip: IpAddr, now: SystemTime) -> Result<Self, GenerateError> {
        let valid_from = OffsetDateTime::from(now - BACKDATE);
        let valid_to = OffsetDateTime::from(now + VALIDITY);
        let params = |name: &str, usage: ExtendedKeyUsagePurpose| {
            let mut params = CertificateParams::default();
            params.distinguished_name.push(DnType::CommonName, name);
            params.not_before = valid_from;
            params.not_after = valid_to;
            params.extended_key_usages = vec![usage];
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params
        };

        let ca_key = KeyPair::generate()?;
        let mut ca_params = params("speculaire mirror CA", ExtendedKeyUsagePurpose::Any);
        ca_params.extended_key_usages.clear();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = ca_params.self_signed(&ca_key)?;
        let issuer = Issuer::new(ca_params, &ca_key);

        let server_key = KeyPair::generate()?;
        let mut server_params = params("speculaire mirror", ExtendedKeyUsagePurpose::ServerAuth);
        server_params.subject_alt_names = vec![SanType::IpAddress(ip)];
        let server = server_params.signed_by(&server_key, &issuer)?;

        let client_key = KeyPair::generate()?;
        let client_params = params(
            "speculaire mirror client",
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        let client = client_params.signed_by(&client_key, &issuer)?;

        Ok(Self {
            ca: lf(&ca.pem()),
            server_certificate: lf(&server.pem()),
            server_key: SecretString::from(lf(&server_key.serialize_pem())),
            client_certificate: lf(&client.pem()),
            client_key: SecretString::from(lf(&client_key.serialize_pem())),
        })
    }

    /// The mirror from the contents of its four files, `client` being the combined PEM.
    ///
    /// # Errors
    ///
    /// When `client` is not one certificate and one private key, in that order.
    pub fn from_files(
        ca: String,
        server_certificate: String,
        server_key: SecretString,
        client: &SecretString,
    ) -> Result<Self, Problem> {
        let client = client.expose_secret();
        let split = client
            .find("-----BEGIN PRIVATE KEY-----")
            .filter(|at| client.starts_with("-----BEGIN CERTIFICATE-----") && *at > 0)
            .ok_or_else(|| {
                Problem::new(
                    Part::Client,
                    "expected a certificate followed by a private key",
                )
            })?;
        let (certificate, key) = client.split_at(split);
        Ok(Self {
            ca,
            server_certificate,
            server_key,
            client_certificate: certificate.to_owned(),
            client_key: SecretString::from(key.to_owned()),
        })
    }

    /// The CA certificate.
    #[must_use]
    pub fn ca(&self) -> &str {
        &self.ca
    }

    /// The server certificate.
    #[must_use]
    pub fn server_certificate(&self) -> &str {
        &self.server_certificate
    }

    /// The server key.
    #[must_use]
    pub fn server_key(&self) -> &SecretString {
        &self.server_key
    }

    /// The client certificate alone, for CRI-O's `client.cert`.
    #[must_use]
    pub fn client_certificate(&self) -> &str {
        &self.client_certificate
    }

    /// The client key alone, for CRI-O's `client.key`.
    #[must_use]
    pub fn client_key(&self) -> &SecretString {
        &self.client_key
    }

    /// The contents of a file of the mirror's directory.
    #[must_use]
    pub fn contents(&self, part: Part) -> SecretString {
        match part {
            Part::Ca => SecretString::from(self.ca.clone()),
            Part::ServerCertificate => SecretString::from(self.server_certificate.clone()),
            Part::ServerKey => self.server_key.clone(),
            Part::Client => SecretString::from(format!(
                "{}{}",
                self.client_certificate,
                self.client_key.expose_secret()
            )),
        }
    }

    /// Whether the files are the ones `configure` would make for `ip` at `now`: each certificate is valid for
    /// [`RENEW_BEFORE`] more, the server certificate names `ip`, the CA signed both certificates, and each key is its
    /// certificate's.
    ///
    /// # Errors
    ///
    /// The first file that is not.
    pub fn check(&self, ip: IpAddr, now: SystemTime) -> Result<(), Problem> {
        let ca = Parsed::new(Part::Ca, &self.ca)?;
        ca.valid_until(now)?;
        if !ca.certificate_or_problem()?.is_ca() {
            return Err(Problem::new(Part::Ca, "is not a CA certificate"));
        }
        let server = Parsed::new(Part::ServerCertificate, &self.server_certificate)?;
        server.valid_until(now)?;
        server.issued_by(&ca)?;
        server.names(ip)?;
        server.has_key(Part::ServerKey, &self.server_key)?;
        let client = Parsed::new(Part::Client, &self.client_certificate)?;
        client.valid_until(now)?;
        client.issued_by(&ca)?;
        client.has_key(Part::Client, &self.client_key)
    }
}

/// `rcgen` writes PEM with CRLF line endings; the files use LF.
fn lf(pem: &str) -> String {
    pem.replace("\r\n", "\n")
}

/// A certificate's DER, with the file it came from.
struct Parsed {
    part: Part,
    der: Vec<u8>,
}

impl Parsed {
    fn new(part: Part, pem: &str) -> Result<Self, Problem> {
        let (_, block) = parse_x509_pem(pem.as_bytes())
            .map_err(|e| Problem::new(part, format!("is not a PEM certificate: {e}")))?;
        let parsed = Self {
            part,
            der: block.contents,
        };
        parsed.certificate_or_problem()?;
        Ok(parsed)
    }

    fn certificate_or_problem(&self) -> Result<X509Certificate<'_>, Problem> {
        x509_parser::parse_x509_certificate(&self.der)
            .map(|(_, certificate)| certificate)
            .map_err(|e| Problem::new(self.part, format!("is not an X.509 certificate: {e}")))
    }

    /// Valid at `now` and still [`RENEW_BEFORE`] later.
    fn valid_until(&self, now: SystemTime) -> Result<(), Problem> {
        let certificate = self.certificate_or_problem()?;
        let at = |time: SystemTime| {
            time.duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|d| i64::try_from(d.as_secs()).ok())
                .and_then(|s| ASN1Time::from_timestamp(s).ok())
                .ok_or_else(|| Problem::new(self.part, "the clock is out of range"))
        };
        let validity = certificate.validity();
        if validity.is_valid_at(at(now)?) && validity.not_after >= at(now + RENEW_BEFORE)? {
            Ok(())
        } else {
            Err(Problem::new(
                self.part,
                format!(
                    "is not valid until {} days from now (it is valid {} to {})",
                    RENEW_BEFORE.as_secs() / 86_400,
                    validity.not_before,
                    validity.not_after
                ),
            ))
        }
    }

    fn issued_by(&self, ca: &Self) -> Result<(), Problem> {
        let certificate = self.certificate_or_problem()?;
        let ca = ca.certificate_or_problem()?;
        if certificate.issuer() != ca.subject() {
            return Err(Problem::new(
                self.part,
                format!("was issued by {}, not by the CA", certificate.issuer()),
            ));
        }
        certificate
            .verify_signature(Some(ca.public_key()))
            .map_err(|_| Problem::new(self.part, "is not signed by the CA"))
    }

    fn names(&self, ip: IpAddr) -> Result<(), Problem> {
        let certificate = self.certificate_or_problem()?;
        let wanted = match ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let named = certificate
            .subject_alternative_name()
            .ok()
            .flatten()
            .is_some_and(|san| {
                san.value
                    .general_names
                    .iter()
                    .any(|name| matches!(name, GeneralName::IPAddress(bytes) if *bytes == wanted))
            });
        if named {
            Ok(())
        } else {
            Err(Problem::new(self.part, format!("does not name {ip}")))
        }
    }

    fn has_key(&self, key_part: Part, key: &SecretString) -> Result<(), Problem> {
        let certificate = self.certificate_or_problem()?;
        let pair = KeyPair::from_pem(key.expose_secret())
            .map_err(|_| Problem::new(key_part, "is not a private key"))?;
        if certificate.public_key().subject_public_key.data.as_ref() == pair.public_key_raw() {
            Ok(())
        } else {
            Err(Problem::new(
                key_part,
                "is not the key of the certificate it goes with",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    fn now() -> SystemTime {
        SystemTime::now()
    }

    #[test]
    fn generated_certificates_pass_their_own_check() {
        let mirror = Mirror::generate(IP, now()).unwrap();
        mirror.check(IP, now()).unwrap();
        let again = Mirror::generate(IP, now()).unwrap();
        assert_ne!(mirror.ca(), again.ca(), "each run makes a CA of its own");
    }

    #[test]
    fn pem_uses_lf_and_the_client_file_is_certificate_then_key() {
        let mirror = Mirror::generate(IP, now()).unwrap();
        for text in [
            mirror.ca(),
            mirror.server_certificate(),
            mirror.client_certificate(),
            mirror.server_key().expose_secret(),
            mirror.client_key().expose_secret(),
        ] {
            assert!(!text.contains('\r') && text.ends_with("-----\n"), "{text}");
        }
        let client = mirror.contents(Part::Client);
        let rebuilt = Mirror::from_files(
            mirror.ca().to_owned(),
            mirror.server_certificate().to_owned(),
            mirror.server_key().clone(),
            &client,
        )
        .unwrap();
        assert_eq!(rebuilt.client_certificate(), mirror.client_certificate());
        assert_eq!(
            rebuilt.client_key().expose_secret(),
            mirror.client_key().expose_secret()
        );
        rebuilt.check(IP, now()).unwrap();
    }

    #[test]
    fn a_client_file_without_a_certificate_and_a_key_is_refused() {
        let mirror = Mirror::generate(IP, now()).unwrap();
        for text in [
            String::new(),
            mirror.client_certificate().to_owned(),
            mirror.client_key().expose_secret().to_owned(),
            format!(
                "{}{}",
                mirror.client_key().expose_secret(),
                mirror.client_certificate()
            ),
        ] {
            let problem = Mirror::from_files(
                mirror.ca().to_owned(),
                mirror.server_certificate().to_owned(),
                mirror.server_key().clone(),
                &SecretString::from(text),
            )
            .unwrap_err();
            assert_eq!(problem.part, Part::Client);
        }
    }

    #[test]
    fn another_address_is_a_problem_of_the_server_certificate() {
        let mirror = Mirror::generate(IP, now()).unwrap();
        let other = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let problem = mirror.check(other, now()).unwrap_err();
        assert_eq!(problem.part, Part::ServerCertificate);
        assert!(problem.reason.contains("127.0.0.2"), "{problem}");
        let v6 = Mirror::generate(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), now()).unwrap();
        v6.check(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), now())
            .unwrap();
        assert!(v6.check(IP, now()).is_err());
    }

    #[test]
    fn a_certificate_that_expires_within_the_renewal_margin_is_a_problem() {
        // Valid for ten years from 40 days ago, expiring in 3610 days: fine. From ten years ago: expired.
        let old = Mirror::generate(IP, now() - days(3640)).unwrap();
        let problem = old.check(IP, now()).unwrap_err();
        assert_eq!(problem.part, Part::Ca, "{problem}");
        let nearly = Mirror::generate(IP, now() - VALIDITY + days(10)).unwrap();
        let problem = nearly.check(IP, now()).unwrap_err();
        assert!(problem.reason.contains("30 days"), "{problem}");
        let fresh = Mirror::generate(IP, now() - days(300)).unwrap();
        fresh.check(IP, now()).unwrap();
    }

    #[test]
    fn a_certificate_of_another_ca_or_another_key_is_a_problem() {
        let mirror = Mirror::generate(IP, now()).unwrap();
        let other = Mirror::generate(IP, now()).unwrap();
        let foreign_ca = Mirror {
            ca: other.ca.clone(),
            ..mirror.clone()
        };
        // The same subject name, so only the signature tells them apart.
        let problem = foreign_ca.check(IP, now()).unwrap_err();
        assert_eq!(problem.part, Part::ServerCertificate);
        assert!(problem.reason.contains("signed"), "{problem}");
        let swapped_key = Mirror {
            server_key: other.server_key.clone(),
            ..mirror.clone()
        };
        let problem = swapped_key.check(IP, now()).unwrap_err();
        assert_eq!(problem.part, Part::ServerKey);
        let garbage_key = Mirror {
            client_key: SecretString::from("not a key"),
            ..mirror.clone()
        };
        assert_eq!(garbage_key.check(IP, now()).unwrap_err().part, Part::Client);
        let not_a_ca = Mirror {
            ca: mirror.server_certificate.clone(),
            ..mirror.clone()
        };
        assert_eq!(not_a_ca.check(IP, now()).unwrap_err().part, Part::Ca);
        let garbage = Mirror {
            server_certificate: "nonsense".to_owned(),
            ..mirror
        };
        assert_eq!(
            garbage.check(IP, now()).unwrap_err().part,
            Part::ServerCertificate
        );
    }

    #[test]
    fn keys_are_the_secret_parts() {
        let secret: Vec<_> = Part::ALL.iter().filter(|p| p.is_secret()).collect();
        assert_eq!(secret, [&Part::ServerKey, &Part::Client]);
        let mut names: Vec<_> = Part::ALL.iter().map(|p| p.file_name()).collect();
        names.sort_unstable();
        assert_eq!(names, ["ca.crt", "client.pem", "server.crt", "server.key"]);
    }
}
