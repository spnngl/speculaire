//! What each check of an image came to, part by part (D156): each policy, each of its authorities with the
//! attestations they require, and the SBOM it requires. The engine's verdict is what these come to, through
//! `Checked::outcome` and `Outcome::all`; `speculaire verify` prints them as a [`Report`].

use std::cmp::Ordering;
use std::fmt;

use serde::Serialize;
use speculaire_artifacts::discover::Error;
use speculaire_artifacts::{Artifact, Store};
use speculaire_oci::reference::Digest;

use crate::policy::{Authority, Policy, Sbom};
use crate::sbom::SbomResult;
use crate::signature::{AuthorityResult, Unmet, Unverifiable};
use crate::{Absent, Signatures, TrustRoot};

/// What a policy, or the policies of a key, came to.
#[derive(Debug)]
pub(crate) enum Outcome {
    /// Passed, with the identities that satisfied each authority.
    Pass(Vec<String>),
    Fail(String),
    Unverifiable(String),
}

impl Outcome {
    /// What the outcomes of policies that must each pass come to (D11): a failure counts before an unverifiable check.
    pub(crate) fn all(outcomes: impl IntoIterator<Item = Self>) -> Self {
        let mut signers = Vec::new();
        let mut unverifiable = None;
        for outcome in outcomes {
            match outcome {
                Self::Pass(passed) => signers.extend(passed),
                fail @ Self::Fail(_) => return fail,
                Self::Unverifiable(reason) => {
                    unverifiable.get_or_insert(reason);
                }
            }
        }
        unverifiable.map_or(Self::Pass(signers), Self::Unverifiable)
    }
}

/// The reason of the unverifiable verdict of an image whose discovery failed with `error`.
pub(crate) fn undiscovered(error: &Error) -> String {
    match error {
        Error::Unverifiable { reason, .. } => reason.to_string(),
        Error::Store(e) => format!("artifact store: {e}"),
    }
}

/// What one policy's checks came to over an image's artifacts.
pub(crate) struct Checked<'a> {
    policy: &'a Policy,
    authorities: Result<Vec<AuthorityResult>, Unverifiable>,
    /// None when the policy requires no SBOM, or when it went unchecked: no authority passed, or no trust root is held.
    sbom: Option<Result<SbomResult, Unverifiable>>,
}

impl<'a> Checked<'a> {
    /// Checks `policy` over `artifacts` of `target`, read from `store` and verified against `root`: its authorities,
    /// then the SBOM it requires once one passes (D145, D150).
    pub(crate) async fn new(
        signatures: &Signatures,
        store: &Store,
        target: &Digest,
        artifacts: &[Artifact],
        policy: &'a Policy,
        root: Result<&TrustRoot, &Absent>,
    ) -> Self {
        let authorities = signatures
            .check(store, target, artifacts, policy, root)
            .await;
        let passed = authorities
            .as_ref()
            .is_ok_and(|results| results.iter().any(Result::is_ok));
        // Without a trust root, the signature check is unverifiable already (D145).
        let sbom = match (policy.sbom(), root) {
            (Sbom::Required, Ok(root)) if passed => Some(
                signatures
                    .sbom(store, target, artifacts, policy, root)
                    .await,
            ),
            _ => None,
        };
        Self {
            policy,
            authorities,
            sbom,
        }
    }

    /// What the policy came to: one authority passes, and the SBOM it requires is there.
    pub(crate) fn outcome(&self) -> Outcome {
        let name = self.policy.name();
        let results = match &self.authorities {
            Ok(results) => results,
            Err(e) => return Outcome::Unverifiable(e.to_string()),
        };
        let signers: Vec<String> = results
            .iter()
            .filter_map(|result| result.as_ref().ok())
            .map(|signed| format!("{name}: {signed}"))
            .collect();
        if signers.is_empty() {
            // A policy has an authority at least, so it has an unmet one here.
            let unmet = results.iter().find_map(|result| result.as_ref().err());
            return Outcome::Fail(
                unmet.map_or_else(|| format!("policy {name}"), ToString::to_string),
            );
        }
        match &self.sbom {
            Some(Ok(Err(failure))) => Outcome::Fail(failure.to_string()),
            Some(Err(e)) => Outcome::Unverifiable(e.to_string()),
            Some(Ok(Ok(_))) | None => Outcome::Pass(signers),
        }
    }
}

/// What an image came to over the policies its name matches, and why, part by part (D156).
#[derive(Debug, Serialize)]
pub struct Report {
    image: String,
    verdict: Conclusion,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    policies: Vec<PolicyReport>,
}

/// What an image came to: a verdict, or no policy to check it against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Conclusion {
    Allow,
    Rejected,
    Unverifiable,
    /// No policy matches the image: the agent's `gate.unmatched` decides (D23).
    Unmatched,
}

/// What one check came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Pass,
    Fail,
    Unverifiable,
    /// An earlier check decided first.
    NotChecked,
}

/// What one check came to, and why.
#[derive(Debug, Serialize)]
struct Line {
    result: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct PolicyReport {
    name: String,
    #[serde(flatten)]
    line: Line,
    authorities: Vec<AuthorityReport>,
    /// None when the policy requires no SBOM.
    #[serde(skip_serializing_if = "Option::is_none")]
    sbom: Option<Line>,
}

#[derive(Debug, Serialize)]
struct AuthorityReport {
    /// Its name in the policy, or its place among the policy's authorities, from 1.
    name: String,
    #[serde(flatten)]
    line: Line,
    attestations: Vec<AttestationReport>,
}

#[derive(Debug, Serialize)]
struct AttestationReport {
    name: String,
    predicate_type: String,
    #[serde(flatten)]
    line: Line,
}

impl Report {
    /// No policy matches `image`.
    #[must_use]
    pub const fn unmatched(image: String) -> Self {
        Self {
            image,
            verdict: Conclusion::Unmatched,
            reason: None,
            policies: Vec::new(),
        }
    }

    /// Discovery of the artifacts of `image`, which `policies` match, failed with `error`: nothing was checked.
    #[must_use]
    pub fn undiscovered(image: String, policies: &[&Policy], error: &Error) -> Self {
        let reason = undiscovered(error);
        Self {
            image,
            verdict: Conclusion::Unverifiable,
            policies: policies
                .iter()
                .map(|policy| PolicyReport::unchecked(policy, &reason))
                .collect(),
            reason: Some(reason),
        }
    }

    /// Checks `artifacts` of `target`, read from `store`, against each of `policies`, which `image` matches and which
    /// must each pass, as the engine does (D11).
    pub async fn check(
        image: String,
        signatures: &Signatures,
        store: &Store,
        target: &Digest,
        artifacts: &[Artifact],
        policies: &[&Policy],
        root: Result<&TrustRoot, &Absent>,
    ) -> Self {
        if policies.is_empty() {
            return Self::unmatched(image);
        }
        let mut outcomes = Vec::with_capacity(policies.len());
        let mut reports = Vec::with_capacity(policies.len());
        for policy in policies {
            let checked = Checked::new(signatures, store, target, artifacts, policy, root).await;
            let outcome = checked.outcome();
            reports.push(PolicyReport::of(&checked, &outcome));
            outcomes.push(outcome);
        }
        let (verdict, reason) = match Outcome::all(outcomes) {
            Outcome::Pass(_) => (Conclusion::Allow, None),
            Outcome::Fail(reason) => (Conclusion::Rejected, Some(reason)),
            Outcome::Unverifiable(reason) => (Conclusion::Unverifiable, Some(reason)),
        };
        Self {
            image,
            verdict,
            reason,
            policies: reports,
        }
    }

    /// Whether the image is allowed.
    #[must_use]
    pub fn allowed(&self) -> bool {
        self.verdict == Conclusion::Allow
    }
}

impl PolicyReport {
    /// The report of `checked`, which came to `outcome`.
    fn of(checked: &Checked<'_>, outcome: &Outcome) -> Self {
        let policy = checked.policy;
        let results = checked.authorities.as_ref().ok();
        let authorities = policy
            .authorities()
            .iter()
            .enumerate()
            .map(|(index, authority)| {
                let result = results.and_then(|results| results.get(index));
                AuthorityReport::of(index, authority, result)
            })
            .collect();
        let sbom = (policy.sbom() == Sbom::Required).then(|| match &checked.sbom {
            None => Line::bare(Status::NotChecked),
            Some(Ok(Ok(listed))) => Line::new(
                Status::Pass,
                &format_args!("{} packages, signed by {}", listed.packages, listed.signed),
            ),
            Some(Ok(Err(failure))) => Line::new(Status::Fail, failure),
            Some(Err(e)) => Line::new(Status::Unverifiable, e),
        });
        let line = match outcome {
            Outcome::Pass(_) => Line::bare(Status::Pass),
            Outcome::Fail(reason) => Line::new(Status::Fail, reason),
            Outcome::Unverifiable(reason) => Line::new(Status::Unverifiable, reason),
        };
        Self {
            name: policy.name().to_owned(),
            line,
            authorities,
            sbom,
        }
    }

    /// The report of `policy` left unchecked, unverifiable for `reason`.
    fn unchecked(policy: &Policy, reason: &str) -> Self {
        Self {
            name: policy.name().to_owned(),
            line: Line::new(Status::Unverifiable, &reason),
            authorities: policy
                .authorities()
                .iter()
                .enumerate()
                .map(|(index, authority)| AuthorityReport::of(index, authority, None))
                .collect(),
            sbom: (policy.sbom() == Sbom::Required).then(|| Line::bare(Status::NotChecked)),
        }
    }
}

impl AuthorityReport {
    /// The report of the `index`th `authority`, whose result is `result`; none when it went unchecked.
    fn of(index: usize, authority: &Authority, result: Option<&AuthorityResult>) -> Self {
        let name = authority
            .name
            .clone()
            .unwrap_or_else(|| (index + 1).to_string());
        // The authority checks its attestations in order, and stops at the first that fails.
        let failed = match result {
            Some(Err(Unmet::Attestation { predicate_type, .. })) => authority
                .attestations
                .iter()
                .position(|attestation| &attestation.predicate_type == predicate_type),
            _ => None,
        };
        let attestations = authority
            .attestations
            .iter()
            .enumerate()
            .map(|(place, attestation)| AttestationReport {
                name: attestation.name.clone(),
                predicate_type: attestation.predicate_type.clone(),
                line: match (result, failed) {
                    (Some(Ok(_)), _) => Line::bare(Status::Pass),
                    (Some(Err(unmet)), Some(failed)) => match place.cmp(&failed) {
                        Ordering::Less => Line::bare(Status::Pass),
                        Ordering::Equal => Line::new(Status::Fail, unmet),
                        Ordering::Greater => Line::bare(Status::NotChecked),
                    },
                    _ => Line::bare(Status::NotChecked),
                },
            })
            .collect();
        let line = match result {
            None => Line::bare(Status::NotChecked),
            Some(Ok(signed)) => Line::new(Status::Pass, signed),
            Some(Err(unmet)) => Line::new(Status::Fail, unmet),
        };
        Self {
            name,
            line,
            attestations,
        }
    }
}

impl Line {
    fn new(result: Status, reason: &dyn fmt::Display) -> Self {
        Self {
            result,
            reason: Some(reason.to_string()),
        }
    }

    const fn bare(result: Status) -> Self {
        Self {
            result,
            reason: None,
        }
    }
}

/// The plain text `speculaire verify` prints: the verdict, then a line per policy, authority, attestation and SBOM.
impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let verdict = match self.verdict {
            Conclusion::Allow => "allow",
            Conclusion::Rejected => "rejected",
            Conclusion::Unverifiable => "unverifiable",
            Conclusion::Unmatched => "unmatched",
        };
        match &self.reason {
            Some(reason) => writeln!(f, "{verdict}: {reason}")?,
            None => writeln!(f, "{verdict}")?,
        }
        for policy in &self.policies {
            writeln!(f, "policy {}: {}", policy.name, policy.line)?;
            for authority in &policy.authorities {
                writeln!(f, "  authority {}: {}", authority.name, authority.line)?;
                for attestation in &authority.attestations {
                    writeln!(
                        f,
                        "    attestation {} ({}): {}",
                        attestation.name, attestation.predicate_type, attestation.line
                    )?;
                }
            }
            if let Some(sbom) = &policy.sbom {
                writeln!(f, "  sbom: {sbom}")?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for Line {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let result = match self.result {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::Unverifiable => "unverifiable",
            Status::NotChecked => "not checked",
        };
        match &self.reason {
            Some(reason) => write!(f, "{result}: {reason}"),
            None => f.write_str(result),
        }
    }
}

#[cfg(test)]
mod tests {
    use speculaire_artifacts::discover::Reason;
    use tokio::time::Instant;

    use super::*;
    use crate::Policies;
    use crate::signature::{Failure, Signed};

    /// One policy, `p`, whose one authority requires attestations `a`, `b` and `c`, and an SBOM.
    fn policies() -> Policies {
        let attestations: String = ["a", "b", "c"]
            .map(|name| format!("    - name: {name}\n      predicateType: https://{name}.test\n"))
            .concat();
        let policy = format!(
            "apiVersion: policy.sigstore.dev/v1beta1\nkind: ClusterImagePolicy\nmetadata:\n  name: p\nspec:\n  \
             images:\n  - glob: \"**\"\n  sbom: required\n  authorities:\n  - keyless:\n      identities:\n      - \
             issuer: https://issuer.test\n        subject: https://subject.test\n    attestations:\n{attestations}"
        );
        Policies::parse(&policy).expect("the test policy parses")
    }

    fn statuses(report: &AuthorityReport) -> Vec<Status> {
        report
            .attestations
            .iter()
            .map(|attestation| attestation.line.result)
            .collect()
    }

    #[test]
    fn the_attestations_before_the_one_that_fails_pass_and_those_after_go_unchecked() {
        let policies = policies();
        let authority = &policies.iter().next().expect("one policy").authorities()[0];
        let unmet = Err(Unmet::Attestation {
            predicate_type: "https://b.test".to_owned(),
            failure: Failure::Missing,
        });
        let report = AuthorityReport::of(0, authority, Some(&unmet));
        assert_eq!(
            statuses(&report),
            [Status::Pass, Status::Fail, Status::NotChecked]
        );
        assert_eq!(report.name, "1");
        assert_eq!(
            report.attestations[1].line.to_string(),
            "fail: attestation https://b.test missing (.att tags are not supported)"
        );

        let passed = AuthorityReport::of(1, authority, Some(&Ok(Signed::Key)));
        assert_eq!(statuses(&passed), [Status::Pass; 3]);
        assert_eq!(
            (passed.name.as_str(), passed.line.to_string()),
            ("2", "pass: a key".to_owned())
        );

        let unsigned = Err(Unmet::Signature(Failure::Missing));
        let report = AuthorityReport::of(0, authority, Some(&unsigned));
        assert_eq!(statuses(&report), [Status::NotChecked; 3]);
        assert_eq!(report.line.to_string(), "fail: no signature");
    }

    #[test]
    fn an_image_whose_discovery_failed_has_each_check_unchecked() {
        let policies = policies();
        let matched: Vec<&Policy> = policies.iter().collect();
        let error = Error::Unverifiable {
            reason: Reason::Unreachable,
            retry_at: Instant::now(),
        };
        let report =
            Report::undiscovered("registry.test/app@sha256:0".to_owned(), &matched, &error);
        assert!(!report.allowed());
        assert_eq!(
            report.to_string(),
            "unverifiable: artifacts unreachable\npolicy p: unverifiable: artifacts unreachable\n  authority 1: not \
             checked\n    attestation a (https://a.test): not checked\n    attestation b (https://b.test): not \
             checked\n    attestation c (https://c.test): not checked\n  sbom: not checked\n"
        );
        let json = serde_json::to_value(&report).expect("a report serializes");
        assert_eq!(json["verdict"], "unverifiable");
        assert_eq!(json["policies"][0]["sbom"]["result"], "not_checked");
    }

    #[test]
    fn an_image_no_policy_matches_is_unmatched_and_not_allowed() {
        let report = Report::unmatched("registry.test/app@sha256:0".to_owned());
        assert!(!report.allowed());
        assert_eq!(report.to_string(), "unmatched\n");
    }

    #[test]
    fn a_failure_counts_before_an_unverifiable_check_and_that_before_a_pass() {
        let pass = || Outcome::Pass(vec!["p: a key".to_owned()]);
        let fail = || Outcome::Fail("no signature".to_owned());
        let unverifiable = || Outcome::Unverifiable("trust root".to_owned());
        assert!(matches!(
            Outcome::all([pass(), unverifiable(), fail()]),
            Outcome::Fail(_)
        ));
        assert!(matches!(
            Outcome::all([pass(), unverifiable()]),
            Outcome::Unverifiable(_)
        ));
        assert!(
            matches!(Outcome::all([pass(), pass()]), Outcome::Pass(signers) if signers.len() == 2)
        );
    }
}
