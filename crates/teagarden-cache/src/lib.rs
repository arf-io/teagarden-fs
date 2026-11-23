//! Local on-disk block cache for TeaGarden.
//!
//! Provides an encrypted, size-bounded LRU cache of file blocks so that data
//! already fetched from Telegram does not need to be re-downloaded on every
//! access. Blocks are keyed by their random ID and optionally encrypted at rest.

#![deny(missing_docs)]

/// Encrypted, size-bounded LRU block cache backed by the local filesystem.
pub mod block_cache;
/// Error and `Result` types for cache operations.
pub mod error;
