//! Telegram API backend for TeaGarden: uploads and downloads encrypted blocks
//! to a private Telegram channel and manages the associated session and group.
//!
//! The crate exposes a `BlockTransport` trait (in [`client`]) implemented by the
//! real grammers-backed client, an in-memory `mock` transport for tests (compiled
//! only under `cfg(test)` or the `test-util` feature, never in a product build),
//! and a [`multi`] transport that fans operations across several sessions.

#![deny(missing_docs)]

/// Bot-HTTP-API transport for parallel block uploads: uploads through the Bot HTTP
/// API, which does not need an MTProto access hash.
pub mod bot_api;
/// Real grammers-backed Telegram client and the `BlockTransport` trait.
pub mod client;
/// Error type and `Result` alias for the transport layer.
pub mod error;
mod session;
/// Fixed-high-water raw-topic polling and activity-aware cadence.
pub mod topic_poller;
/// Configuration, channel reference, and operation result/stat types.
pub mod types;

/// In-memory mock transport used for testing without hitting Telegram.
///
/// Test-only: compiled for this crate's own tests or when a dependent enables the
/// `test-util` feature from its `[dev-dependencies]`. No product build can reach it.
#[cfg(any(test, feature = "test-util"))]
pub mod mock;
/// Round-robin transport that distributes operations across multiple sessions.
pub mod multi;

pub use multi::MultiTransport;

/// Single-connection streaming part pipelines and durable source contract.
pub mod transfer;
