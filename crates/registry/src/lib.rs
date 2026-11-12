//! The upstream registry client (D17, D88): what the agent asks a registry on behalf of the runtime.
//!
//! An [`Endpoint`](speculaire_runtime::registries::Endpoint) says where a registry is and how to trust it, from the node's registry config (D89). [`Client::send`]
//! asks it for one thing and handles what a registry answers before the body: the Bearer token challenge, Basic
//! credentials and redirects. No header is ever logged, and every credential and token is a `SecretString` (D37).

pub mod challenge;
mod client;
mod connect;
mod token;

pub use client::{Client, Error, Request, Response};
