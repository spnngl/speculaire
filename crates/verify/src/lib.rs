//! Verification of the images a node runs (D8, D11): the policy file, parsed into [`Policies`], the globs and identity
//! patterns it holds, the [`TrustRoot`] it checks against, and the [`Signatures`] check of each authority, with the
//! in-toto [`statement::Statement`]s its attestations sign and the SBOM it can require ([`sbom`]), and the [`Engine`]
//! that keeps a [`Verdict`] per image and policies (D20). It opens no connection: what it checks comes from the
//! artifact store, which discovery fills, and the TUF repository of a trust root is a transport the caller passes in.

pub mod engine;
pub mod glob;
pub mod legacy;
pub mod metrics;
pub mod pattern;
pub mod policy;
pub mod sbom;
pub mod signature;
pub mod statement;
pub mod trust;

pub use engine::{Engine, Key, Lookup, Verdict, Verdicts};
pub use glob::Glob;
pub use pattern::Pattern;
pub use policy::{MatchHash, Policies, Policy};
pub use signature::Signatures;
pub use trust::{Absent, Held, RootHash, TrustRoot};
