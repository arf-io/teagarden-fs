//! Service layer for TeaGarden.
//!
//! This crate holds the in-process services the `teagarden` CLI drives: volume
//! lifecycle (create, list, delete), open volume sessions with live keys,
//! Telegram authentication state, sharing, and system status. It wires the
//! lower-level `teagarden-*` crates (core, store, telegram, sharing) together
//! behind a structured error type with user-facing suggestions.
//!
//! There is no network server in this crate: the former axum REST server was
//! removed from the 1.0 scope.

#![deny(missing_docs)]

/// Structured service errors, their stable codes and suggestions, and the crate `Result` alias.
pub mod error;
/// Long-lived services the CLI delegates to (auth, volumes, sessions, sharing, system).
pub mod service;
/// Serializable request/response types shared across the services.
pub mod types;
