//! Verification of the images a node runs (D8, D11): the policy file, parsed into [`Policies`], and the globs and
//! identity patterns it holds. It opens no connection: what it checks comes from the artifact store.

pub mod glob;
pub mod pattern;
pub mod policy;

pub use glob::Glob;
pub use pattern::Pattern;
pub use policy::{MatchHash, Policies, Policy};
