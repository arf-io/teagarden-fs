//! The **shared-volume grant** — the real access-transfer artifact.
//!
//! A grant carries everything a recipient needs to open a volume with no owner
//! password: the owner's non-secret
//! [`VolumeConfig`](teagarden_core::volume::config::VolumeConfig) — since v3 with its
//! verification hash and integrity HMAC removed, because for a password-rooted
//! volume either one lets a holder of the file grind the password offline; the
//! recipient recomputes both from the unwrapped root ([`SharedVolumeGrant::recipient_config`]) — and
//! the volume's 32-byte hierarchy **root**, ML-KEM-wrapped to the recipient's
//! public key and AEAD-bound to the complete config plus `(access_level,
//! derivation, granted_by)`.
//!
//! Wrapping the *root* (not a data sub-key) is what makes the handoff real: from
//! the root the recipient re-derives the entire
//! [`KeyHierarchy`](teagarden_core::crypto::keys::KeyHierarchy) via
//! `derive_hierarchy_v1` — data, meta, schema, integrity, block-id, filename,
//! manifest — and can therefore navigate and decrypt the whole filesystem, which
//! a lone data key can never do.
//!
//! ## Honest limits (see the sharing threat model)
//! - A grant is a **bearer token for the volume root**: whoever holds it has full
//!   cryptographic access, and **no shipped command revokes it**. `key rotate`
//!   does NOT: it only advances the block epoch, and the epoch keys derive
//!   deterministically from the root, so a grant holder re-derives them exactly
//!   as the owner does. The only cryptographic cutoff is moving the data to a
//!   **new volume** (a new random root the holder does not have). For a recipient
//!   using a *distinct Telegram account*, removing that account from the volume's
//!   Telegram group additionally cuts their ability to download blocks, but that
//!   is a Telegram-layer control, not cryptographic revocation.
//! - `access_level` is **advisory**: the recipient holds the root and can ignore a
//!   read-only marker. The AEAD binding stops a *relay* from tampering the level in
//!   transit; it does not constrain the recipient themselves.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use teagarden_core::crypto::keys::SymmetricKey;
use teagarden_core::crypto::mlkem::{MlKemDecapsulationKey, MlKemEncapsulationKey};
use teagarden_core::volume::config::VolumeConfig;
use teagarden_core::volume::manager;
use teagarden_core::volume::shared::SharedDerivation;

use crate::access::AccessLevel;
use crate::error::{Result, SharingError};
use crate::key_exchange::{unwrap_key, wrap_key_for_user, WrappedKey};

/// On-wire grant format version written by [`SharedVolumeGrant::seal`].
///
/// - **v2** shipped the owner's config verbatim, including
///   `password_verification_hash` and `config_integrity`. Both are keyed by the
///   volume hierarchy, which for a password-rooted volume is a function of
///   Argon2(password): anyone holding the FILE could grind the password offline.
/// - **v3** (sharing-M1) ships the config with both anchors removed. The
///   recipient recomputes them from the AEAD-unwrapped root
///   ([`SharedVolumeGrant::recipient_config`]), producing byte-identical
///   anchors, so the materialized `volume.json` is unchanged.
///
/// v2 grants are still read ([`GRANT_VERSION_V2`]). A pre-v3 client refuses a
/// v3 grant with its "unsupported grant version" error.
pub const GRANT_VERSION: u16 = 3;

/// The previous grant format, still accepted on import.
pub const GRANT_VERSION_V2: u16 = 2;

/// Prefix for the fingerprint shown by the owner and required at import.
pub const GRANT_FINGERPRINT_PREFIX: &str = "b3:";

/// A sealed, recipient-encrypted capability to open a specific volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedVolumeGrant {
    /// Format version.
    pub version: u16,
    /// The owner's non-secret volume config. In a v3 grant its verification
    /// hash and integrity HMAC are removed (sharing-M1); use
    /// [`Self::recipient_config`] to get the config to materialize, never this
    /// field directly.
    pub config: VolumeConfig,
    /// How the recipient turns the wrapped root back into the hierarchy.
    pub derivation: SharedDerivation,
    /// The access level the owner granted (advisory; AEAD-bound to prevent relay
    /// tampering).
    pub access_level: AccessLevel,
    /// Who claims to have created the grant (display / audit). The field is
    /// AEAD-bound against relay tampering, but its identity is authenticated only
    /// when the recipient verifies the artifact fingerprint over a separately
    /// authenticated channel.
    pub granted_by: String,
    /// The ML-KEM-wrapped hierarchy root, AEAD-bound to every other grant field.
    pub wrapped_root: WrappedKey,
}

/// Return the stable, algorithm-labelled fingerprint of an exact grant artifact.
///
/// The owner prints this after writing the grant and the recipient must receive it
/// over an authenticated channel before importing the artifact.
pub fn grant_artifact_fingerprint(bytes: &[u8]) -> String {
    format!("{GRANT_FINGERPRINT_PREFIX}{}", blake3::hash(bytes).to_hex())
}

/// Canonical AAD binding the wrapped root to every security- or display-relevant
/// field in the grant.
///
/// A relay that changes the config, access level, derivation, or claimed creator
/// changes this AAD, so the recipient's AEAD unwrap fails closed. Issuer identity
/// still comes from the separately authenticated artifact fingerprint; AEAD alone
/// cannot prove who constructed a ciphertext for a public recipient key.
///
/// The version is bound through the domain-separation prefix, so relabelling a
/// v3 grant as v2 (or the reverse) fails the unwrap.
fn grant_wrap_aad(
    version: u16,
    config: &VolumeConfig,
    level: AccessLevel,
    deriv: SharedDerivation,
    granted_by: &str,
) -> Result<Vec<u8>> {
    let prefix: &[u8] = match version {
        GRANT_VERSION_V2 => b"teagarden-share-root:v2",
        GRANT_VERSION => b"teagarden-share-root:v3",
        other => {
            return Err(SharingError::InvalidInvite(format!(
                "unsupported grant version {other} (expected {GRANT_VERSION_V2} or {GRANT_VERSION})"
            )))
        }
    };
    let config_json = serde_json::to_vec(config)
        .map_err(|e| SharingError::Crypto(format!("serialize grant config for AAD: {e}")))?;
    let config_digest = blake3::hash(&config_json);
    let creator_digest = blake3::hash(granted_by.as_bytes());

    let mut aad = Vec::with_capacity(23 + 16 + 2 + 32 + 32);
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(config.volume_id.as_bytes());
    aad.push(level.as_u8());
    aad.push(match deriv {
        SharedDerivation::HierarchyRootV1 => 0,
    });
    aad.extend_from_slice(config_digest.as_bytes());
    aad.extend_from_slice(creator_digest.as_bytes());
    Ok(aad)
}

impl SharedVolumeGrant {
    /// Owner side: wrap `root` (the volume's `hierarchy.root`) for `recipient_ek`.
    pub fn seal(
        config: &VolumeConfig,
        root: &SymmetricKey,
        access_level: AccessLevel,
        derivation: SharedDerivation,
        granted_by: &str,
        recipient_ek: &MlKemEncapsulationKey,
    ) -> Result<Self> {
        // Owner-side self-check: the root must actually authenticate this config
        // (v2 recipients got this check on import; v3 recipients recompute the
        // anchors from the root, so the check has to happen here instead).
        let hierarchy = manager::derive_shared_hierarchy(root.as_bytes(), derivation, config)
            .map_err(|e| SharingError::Crypto(format!("derive hierarchy: {e}")))?;
        manager::verify_config_anchors(config, &hierarchy).map_err(|e| {
            SharingError::Crypto(format!("the root does not authenticate this config: {e}"))
        })?;

        // sharing-M1: ship neither anchor — each is a password oracle for a
        // password-rooted volume. The AAD covers the config exactly as shipped.
        let mut shipped = config.clone();
        shipped.password_verification_hash = None;
        shipped.config_integrity = None;

        let aad = grant_wrap_aad(
            GRANT_VERSION,
            &shipped,
            access_level,
            derivation,
            granted_by,
        )?;
        let wrapped_root = wrap_key_for_user(root, recipient_ek, &aad)?;
        Ok(Self {
            version: GRANT_VERSION,
            config: shipped,
            derivation,
            access_level,
            granted_by: granted_by.to_string(),
            wrapped_root,
        })
    }

    /// Recipient side: unwrap the root with `recipient_dk`.
    ///
    /// The AAD is recomputed from the grant's config, access level, derivation,
    /// and claimed creator, so a wrong recipient key or transit-tampered metadata
    /// fails the AEAD and returns `Err`.
    pub fn open_root(&self, recipient_dk: &MlKemDecapsulationKey) -> Result<Zeroizing<[u8; 32]>> {
        let aad = grant_wrap_aad(
            self.version,
            &self.config,
            self.access_level,
            self.derivation,
            &self.granted_by,
        )?;
        let key = unwrap_key(&self.wrapped_root, recipient_dk, &aad)?;
        Ok(Zeroizing::new(*key.as_bytes()))
    }

    /// The `VolumeConfig` the recipient writes as its `volume.json`, given the
    /// root returned by [`Self::open_root`].
    ///
    /// - v2: the shipped config, verbatim (it already carries both anchors).
    /// - v3: the shipped config with its verification hash and integrity HMAC
    ///   recomputed from `root` — byte-identical to the owner's, because both
    ///   are deterministic in (hierarchy, config). A v3 config that arrives WITH
    ///   either anchor is malformed and refused.
    ///
    /// Call only with the root `open_root` returned for THIS grant: the AEAD
    /// unwrap is what authenticates the shipped config to that root.
    pub fn recipient_config(&self, root: &[u8; 32]) -> Result<VolumeConfig> {
        match self.version {
            GRANT_VERSION_V2 => Ok(self.config.clone()),
            GRANT_VERSION => {
                let anchored = self.config.password_verification_hash.is_some()
                    || self.config.config_integrity.is_some();
                if anchored {
                    return Err(SharingError::InvalidInvite(
                        "malformed v3 grant: the config must not carry its verification hash \
                         or integrity HMAC"
                            .into(),
                    ));
                }
                let mut config = self.config.clone();
                let hierarchy = manager::derive_shared_hierarchy(root, self.derivation, &config)
                    .map_err(|e| SharingError::Crypto(format!("derive hierarchy: {e}")))?;
                manager::restore_config_anchors(&mut config, &hierarchy);
                Ok(config)
            }
            other => Err(SharingError::InvalidInvite(format!(
                "unsupported grant version {other} (expected {GRANT_VERSION_V2} or {GRANT_VERSION})"
            ))),
        }
    }

    /// Serialize to bytes (the `.tgci` artifact body).
    ///
    /// JSON, deliberately: [`VolumeConfig`] uses `#[serde(skip_serializing_if)]`
    /// fields, which a non-self-describing format (postcard/bincode) cannot
    /// round-trip. JSON is also how the config's `config_integrity` HMAC is
    /// computed, so a round-tripped config reproduces the owner's HMAC exactly.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| SharingError::Crypto(format!("serialize grant: {e}")))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        serde_json::from_slice(b).map_err(|e| SharingError::Crypto(format!("parse grant: {e}")))
    }

    /// base64url (unpadded) of the serialized grant, for copy-paste transport.
    pub fn encode_b64(&self) -> Result<String> {
        use base64ct::{Base64UrlUnpadded, Encoding};
        Ok(Base64UrlUnpadded::encode_string(&self.to_bytes()?))
    }

    /// Decode a base64url grant string.
    pub fn decode_b64(s: &str) -> Result<Self> {
        use base64ct::{Base64UrlUnpadded, Encoding};
        let bytes = Base64UrlUnpadded::decode_vec(s.trim())
            .map_err(|e| SharingError::InvalidInvite(format!("bad grant base64: {e}")))?;
        Self::from_bytes(&bytes)
    }
}
