//! Encrypted SQLite metadata store for TeaGarden.
//!
//! This crate holds the per-volume metadata database. Logical table and column
//! names never appear on disk: every name is mapped through an [`opaque_schema`]
//! derived from the schema key, and the row payloads themselves are AEAD-encrypted
//! with the volume's metadata key. Each `*_store` module exposes a typed CRUD
//! façade over one logical table (inodes, blocks, manifests, snapshots, policies,
//! users, sharing, the manifest-history DAG, and volume config), plus
//! migrations, query rewriting, and crash-recovery journal replay.
//!
//! The schema version lives in SQLite's `user_version`
//! ([`migrations::SCHEMA_VERSION`]). Version 1 drops a legacy table, unused since
//! before 1.0.0, from databases created by older builds; see
//! [`migrations::initialize_database`].

#![deny(missing_docs)]

/// Reference-counted block records tracking encrypted blocks uploaded to Telegram.
pub mod block_store;
/// Manifest-history DAG edges (parent/child relations between manifest versions).
pub mod dag_store;
/// Encrypted inode (filesystem metadata) storage.
pub mod inode_store;
/// Crash-recovery: rebuild the metadata DB from a base snapshot plus a delta chain.
pub mod journal_recovery;
/// Opening an existing volume's metadata DB without creating one, and whether it must be rebuilt.
pub mod local_db;
/// Encrypted, versioned per-file manifest history storage.
pub mod manifest_store;
/// Database initialization: creates all tables under their opaque names.
pub mod migrations;
/// Mapping from logical table/column/index names to opaque, key-derived identifiers.
pub mod opaque_schema;
/// Encrypted mutability-policy storage.
pub mod policy_store;
/// Rewrites logical SQL statements to use opaque identifiers.
pub mod query_rewriter;
/// Logical table definitions for the metadata database.
pub mod schema;
/// Durable local hybrid-clock state for portable multi-computer versions.
pub mod sdo_clock_store;
/// Durable bounded-poll cursor for portable Telegram object history.
pub mod sdo_cursor_store;
/// Encrypted permanent file identities used by portable file versions.
pub mod sdo_identity_store;
/// Durable encrypted bytes for portable writes awaiting Telegram confirmation.
pub mod sdo_pending_store;
/// Local index of encrypted self-describing file versions.
pub mod sdo_version_store;
/// Encrypted storage for share records and invites.
pub mod sharing_store;
/// Encrypted snapshot-log storage.
pub mod snapshot_store;
/// Encrypted user-record storage.
pub mod user_store;
/// Encrypted volume-configuration storage.
pub mod volume_store;
