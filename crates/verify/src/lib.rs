//! Verification of the images a node runs (D8, D11): the policy file, parsed into [`Policies`], the globs and identity
//! patterns it holds, the [`TrustRoot`] it checks against, and the [`Signatures`] check of each authority, with the
//! in-toto [`statement::Statement`]s its attestations sign. It opens no connection: what it checks comes from the
//! artifact store, and the TUF repository of a trust root is a transport the caller passes in.

pub mod glob;
pub mod legacy;
pub mod pattern;
pub mod policy;
pub mod signature;
pub mod statement;
pub mod trust;

pub use glob::Glob;
pub use pattern::Pattern;
pub use policy::{MatchHash, Policies, Policy};
pub use signature::Signatures;
pub use trust::{Absent, RootHash, TrustRoot};
