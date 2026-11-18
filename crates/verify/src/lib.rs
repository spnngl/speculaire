//! Verification of the images a node runs (D8, D11): the policy file, parsed into [`Policies`], the globs and identity
//! patterns it holds, and the [`TrustRoot`] it checks against. It opens no connection: what it checks comes from the
//! artifact store, and the TUF repository of a trust root is a transport the caller passes in.

pub mod glob;
pub mod pattern;
pub mod policy;
pub mod trust;

pub use glob::Glob;
pub use pattern::Pattern;
pub use policy::{MatchHash, Policies, Policy};
pub use trust::{Absent, RootHash, TrustRoot};
