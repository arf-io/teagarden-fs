//! FUSE filesystem layer for TeaGarden.
//!
//! Bridges the FUSE kernel interface to the encrypted storage stack, translating
//! kernel filesystem callbacks into operations against the metadata store, block
//! store, and Telegram transport.

#![deny(missing_docs)]

/// Filesystem error type and errno mapping for FUSE replies.
pub mod error;
/// FUSE filesystem implementation backing an encrypted volume.
pub mod fs;
/// Open-file-handle table tracking per-handle state for FUSE operations.
pub mod handle;

mod spool;
