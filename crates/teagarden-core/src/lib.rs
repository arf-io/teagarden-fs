//! Core cryptographic filesystem primitives for TeaGarden.
//!
//! This crate is backend-agnostic: it defines the on-disk/on-wire formats and
//! the cryptographic machinery — key hierarchy, AEAD block formats, content-defined
//! chunking and deduplication, sentence/grammar reference encoding, filesystem
//! metadata (inodes and manifests), snapshots, policy enforcement, and per-volume
//! key/epoch management. It performs no Telegram or network I/O itself.

#![deny(missing_docs)]

/// Block layer: chunking, compression, dedup, AEAD block formats, and pointers.
pub mod block;
/// Cryptographic primitives: keys, AEAD, hashing, KDFs, and ML-KEM.
pub mod crypto;
/// Crate-wide error type and `Result` alias.
pub mod error;
/// Crash-safe, race-safe file replacement.
pub mod fsutil;
/// Filesystem metadata: inodes, file manifests, and related types.
pub mod metadata;
/// Volume policy definitions and enforcement engine.
pub mod policy;
/// Portable authenticated volume headers and encrypted file-version objects.
pub mod sdo;
/// Sentence/grammar reference encoding and wordlists.
pub mod sentence;
/// Snapshot entries and history.
pub mod snapshot;
/// Volume management: key/epoch lifecycle, lockout, and the volume manager.
pub mod volume;
