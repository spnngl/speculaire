//! OCI image references and platforms, as containerd reads them (D81): a [`reference::Reference`] can only be made by
//! parsing, and a platform is matched as containerd's `platforms.Only` matches it. [`manifest::children`] reads what a
//! manifest points to (D88).

pub mod manifest;
pub mod platform;
pub mod reference;
