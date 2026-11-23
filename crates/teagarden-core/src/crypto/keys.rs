use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 256-bit symmetric key with automatic zeroization on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; 32]);

impl SymmetricKey {
    /// Construct a key from raw 32-byte material.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw 32-byte key material.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SymmetricKey").field(&"[REDACTED]").finish()
    }
}

/// The complete key hierarchy derived from a root key.
/// All keys are derived via HKDF and zeroized on drop.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyHierarchy {
    /// Root key (derived from password via Argon2id)
    pub root: SymmetricKey,
    /// Data encryption key (file content blocks)
    pub data: SymmetricKey,
    /// Metadata encryption key (inode data, snapshots, policies, user records)
    pub meta: SymmetricKey,
    /// Schema obfuscation key (opaque table/column names)
    pub schema: SymmetricKey,
    /// Integrity hash key (BLAKE3 keyed mode)
    pub integrity: SymmetricKey,
    /// Key wrapping key (for sharing keys with other users)
    pub wrapping: SymmetricKey,
    /// Base key for block identity: `block_id = BLAKE3_keyed(HKDF(block_id, "epoch:N"), plaintext)`.
    /// See CABS spec §3.
    pub block_id: SymmetricKey,
    /// Base key reserved for grammar filename derivation.
    ///
    /// **UNUSED as of 1.0.0. Uploaded documents are named with a random
    /// UUID-v4, not a derived grammar filename.** `CryptFs::derive_block_identity`
    /// binds this key as `_fn_key` and calls `Uuid::new_v4()` instead. It is
    /// still derived so that a future grammar-filename design does not need a new
    /// label — it protects nothing today.
    ///
    /// The intended masking property is therefore **NOT shipped**: uploaded
    /// documents are opaque (random UUID name, empty MIME type), not disguised as
    /// other file types — see `docs/FORMAT.md` §1 (this label is listed as
    /// unused) and §3. A previous version of this comment specified
    /// `filename_seed = BLAKE3_keyed(HKDF(filename, "epoch:N"), block_id)` and
    /// cited "CABS spec §4"; that derivation is not performed anywhere and that
    /// section does not exist.
    pub filename: SymmetricKey,
    /// Manifest identity key: `manifest_id = BLAKE3_keyed(Kmanifest, canonical_manifest_bytes)`.
    /// Used to compute stable, volume-scoped manifest IDs for DAG history.
    pub manifest: SymmetricKey,
}

/// Epoch-scoped data key for domain separation between rotation epochs.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct EpochKey {
    /// Epoch number this key is scoped to.
    pub epoch: u32,
    /// Symmetric key material for this epoch.
    pub key: SymmetricKey,
}

/// HKDF domain separation labels (HKDF `info`) of the key hierarchy.
pub mod labels {
    /// HKDF label for the data encryption key.
    pub const DATA: &[u8] = b"teagarden.v1:data";
    /// HKDF label for the metadata encryption key.
    pub const META: &[u8] = b"teagarden.v1:meta";
    /// HKDF label for the schema obfuscation key.
    pub const SCHEMA: &[u8] = b"teagarden.v1:schema";
    /// HKDF label for the integrity (BLAKE3 keyed) hash key.
    pub const INTEGRITY: &[u8] = b"teagarden.v1:integrity";
    /// HKDF label for the key-wrapping key.
    pub const WRAPPING: &[u8] = b"teagarden.v1:wrapping";
    /// Base key for block identity derivation (see CABS spec §3).
    pub const BLOCK_ID: &[u8] = b"teagarden.v1:block-id";
    /// Base key reserved for grammar filename derivation. **Derived but unused
    /// in 1.0.0** — filenames are random UUID-v4. See `KeyHierarchy::filename`.
    pub const FILENAME: &[u8] = b"teagarden.v1:filename";
    /// Base key for manifest identity (DAG history — Phase 4).
    pub const MANIFEST: &[u8] = b"teagarden.v1:manifest-id";
}

/// Argon2id parameters for password-based key derivation.
///
/// Defaults are tuned for encrypted filesystem data-at-rest protection:
/// 256 MB memory, 4 iterations, 4 threads. This exceeds OWASP's 2023
/// recommendations and provides strong brute-force resistance at the
/// cost of ~1-2 second mount time on modern hardware.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB (default: 262144 = 256 MB)
    pub memory_kib: u32,
    /// Number of iterations (default: 4)
    pub iterations: u32,
    /// Degree of parallelism (default: 4)
    pub parallelism: u32,
    /// Output length in bytes (default: 32)
    pub output_len: usize,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_kib: 262144,
            iterations: 4,
            parallelism: 4,
            output_len: 32,
        }
    }
}

/// Upper bound on Argon2 memory cost accepted from a volume config: 4 GiB.
/// Matches the passphrase-slot bound (`teagarden-mfa` `Argon2Cost::validate`).
pub const ARGON2_MAX_MEMORY_KIB: u32 = 4 * 1024 * 1024;
/// Upper bound on Argon2 passes accepted from a volume config.
pub const ARGON2_MAX_ITERATIONS: u32 = 16;
/// Upper bound on Argon2 lanes accepted from a volume config.
pub const ARGON2_MAX_PARALLELISM: u32 = 16;
/// Upper bound on the Argon2 output length. Only the first 32 bytes are used.
pub const ARGON2_MAX_OUTPUT_LEN: usize = 1024;

impl Argon2Params {
    /// Reject out-of-range cost parameters with an `Err` (core-L1).
    ///
    /// `kdf_params` are read from `volume.json` and fed to Argon2 BEFORE the
    /// password is authenticated, so they are attacker-controlled. Without these
    /// bounds a crafted config aborted the process with a multi-TiB allocation,
    /// ran for hours, or panicked slicing a short output. The bounds sit far
    /// above any value this project has ever written (default 256 MiB / t=4 /
    /// p=4 / 32 bytes), so no existing volume is affected.
    pub fn validate(&self) -> crate::error::Result<()> {
        let bad = |what: String| Err(crate::error::CoreError::KeyDerivation(what));
        if self.parallelism == 0 || self.parallelism > ARGON2_MAX_PARALLELISM {
            return bad(format!(
                "argon2 parallelism {} out of range [1, {ARGON2_MAX_PARALLELISM}]",
                self.parallelism
            ));
        }
        let min_mem = 8 * self.parallelism;
        if self.memory_kib < min_mem || self.memory_kib > ARGON2_MAX_MEMORY_KIB {
            return bad(format!(
                "argon2 memory {} KiB out of range [{min_mem}, {ARGON2_MAX_MEMORY_KIB}]",
                self.memory_kib
            ));
        }
        if self.iterations == 0 || self.iterations > ARGON2_MAX_ITERATIONS {
            return bad(format!(
                "argon2 iterations {} out of range [1, {ARGON2_MAX_ITERATIONS}]",
                self.iterations
            ));
        }
        if self.output_len < 32 || self.output_len > ARGON2_MAX_OUTPUT_LEN {
            return bad(format!(
                "argon2 output length {} out of range [32, {ARGON2_MAX_OUTPUT_LEN}]",
                self.output_len
            ));
        }
        Ok(())
    }
}
