//! Multi-user (and multi-computer single-operator) volume sharing for TeaGarden.
//!
//! The real access-transfer artifact is the [`grant::SharedVolumeGrant`]: it
//! carries the owner's non-secret volume config plus the volume's 32-byte
//! hierarchy **root**, ML-KEM-wrapped to the recipient's public key. From the
//! root the recipient re-derives the entire key hierarchy and opens the volume
//! with no owner password — see `teagarden_core::volume::manager::open_volume_shared`.
//!
//! Because the recipient receives the volume root, sharing grants **full
//! cryptographic access**. `AccessLevel` (read-only / read-write / admin) is
//! recorded and enforced by the recipient's client (a read-only mount refuses
//! writes) but is **advisory, not a cryptographic barrier** — the holder of the
//! root could bypass it. A grant is likewise a bearer token that only key
//! rotation can revoke. The [`invite`] / roster types are local bookkeeping and
//! do not themselves grant or revoke cryptographic access.

#![deny(missing_docs)]

/// Access levels and per-user share records for a shared volume.
pub mod access;
/// Error type and `Result` alias for sharing operations.
pub mod error;
/// The shared-volume grant: the real recipient-encrypted access-transfer artifact.
pub mod grant;
/// Invite tokens that grant a user access to a volume.
pub mod invite;
/// ML-KEM-based wrapping and unwrapping of data keys for recipients.
pub mod key_exchange;
