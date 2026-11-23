use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::access::AccessLevel;
use crate::error::{Result, SharingError};

type HmacSha256 = Hmac<Sha256>;

/// A signed local invite record.
///
/// The shipped product has no consumer that turns this record into volume
/// access. Expiry/use-count logic protects roster bookkeeping only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    /// Unique invite ID.
    pub invite_id: String,
    /// Volume ID this record refers to.
    pub volume_id: String,
    /// Who created the invite.
    pub created_by: String,
    /// Intended, currently unenforced access label.
    pub access_level: AccessLevel,
    /// Unix timestamp when the invite was created.
    pub created_at: i64,
    /// Unix timestamp when the invite expires (0 = never).
    pub expires_at: i64,
    /// Maximum number of uses (0 = unlimited).
    pub max_uses: u32,
    /// Current use count.
    pub use_count: u32,
    /// Whether the invite has been revoked.
    pub revoked: bool,
    /// The wrapped data key, encrypted for the invite recipient.
    /// This is set when the invite is accepted (not at creation time for
    /// multi-use invites), or at creation time for single-use invites
    /// where the recipient's public key is known.
    pub wrapped_key: Option<Vec<u8>>,
}

impl Invite {
    /// Create a new invite.
    pub fn new(
        volume_id: String,
        created_by: String,
        access_level: AccessLevel,
        expires_at: i64,
        max_uses: u32,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            invite_id: Uuid::new_v4().to_string(),
            volume_id,
            created_by,
            access_level,
            created_at: now,
            expires_at,
            max_uses,
            use_count: 0,
            revoked: false,
            wrapped_key: None,
        }
    }

    /// Check if this invite is still valid.
    pub fn is_valid(&self) -> bool {
        if self.revoked {
            return false;
        }
        if self.max_uses > 0 && self.use_count >= self.max_uses {
            return false;
        }
        if self.expires_at > 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            if now > self.expires_at {
                return false;
            }
        }
        true
    }

    /// Try to use this invite. Returns error if invalid.
    pub fn try_use(&mut self) -> Result<()> {
        if !self.is_valid() {
            return Err(SharingError::InvalidInvite(format!(
                "invite {} is no longer valid",
                self.invite_id
            )));
        }
        self.use_count += 1;
        Ok(())
    }

    /// Revoke this invite.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

/// Compact invite code that can be shared out-of-band (e.g. via Telegram message).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteCode {
    /// The invite ID.
    pub invite_id: String,
    /// Volume ID (so the recipient knows which volume).
    pub volume_id: String,
    /// HMAC of the invite for integrity verification.
    pub hmac: Vec<u8>,
}

impl InviteCode {
    /// Compute the canonical HMAC input for this invite code.
    ///
    /// The input is the JSON serialization of the invite code with the `hmac`
    /// field set to an empty array. This covers `volume_id` and `invite_id`
    /// deterministically without any delimiter ambiguity. Any addition of
    /// security-relevant fields to `InviteCode` must also be included here.
    fn hmac_input(&self) -> Result<Vec<u8>> {
        let canonical = InviteCode {
            invite_id: self.invite_id.clone(),
            volume_id: self.volume_id.clone(),
            hmac: Vec::new(),
        };
        serde_json::to_vec(&canonical)
            .map_err(|e| SharingError::InvalidInvite(format!("hmac_input serialize: {e}")))
    }

    /// Sign this invite code with the given 32-byte key.
    ///
    /// Returns a new `InviteCode` with the `hmac` field populated. The caller
    /// should use the returned value — the receiver's `self` is consumed to
    /// prevent accidentally using an unsigned code.
    ///
    /// The key must be derived from the volume's key hierarchy; do not use a
    /// raw password or a key shared between volumes.
    pub fn sign(mut self, key: &[u8; 32]) -> Result<Self> {
        let input = self.hmac_input()?;
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|e| SharingError::Crypto(format!("HMAC key error: {e}")))?;
        mac.update(&input);
        self.hmac = mac.finalize().into_bytes().to_vec();
        Ok(self)
    }

    /// Verify the HMAC of this invite code against the given 32-byte key.
    ///
    /// Returns `Ok(())` if the HMAC is valid. Returns
    /// `Err(SharingError::InvalidInvite)` if the HMAC is absent, empty, or
    /// does not match (fail-closed: codes with an empty `hmac` field are
    /// rejected, not silently accepted, so that downgraded or forged codes
    /// from before signing was enforced are caught).
    pub fn verify(&self, key: &[u8; 32]) -> Result<()> {
        if self.hmac.is_empty() {
            return Err(SharingError::InvalidInvite(
                "invite code has no HMAC — it may have been forged or created by an \
                 older client; reject and ask the owner to re-issue"
                    .into(),
            ));
        }

        let input = self.hmac_input()?;
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|e| SharingError::Crypto(format!("HMAC key error: {e}")))?;
        mac.update(&input);
        let expected = mac.finalize().into_bytes();

        // Constant-time comparison to prevent timing side-channels.
        let hmac_bytes: &[u8] = &self.hmac;
        let expected_bytes: &[u8] = &expected;
        if hmac_bytes.ct_eq(expected_bytes).into() {
            Ok(())
        } else {
            Err(SharingError::InvalidInvite(
                "invite code HMAC verification failed — the code may have been tampered with"
                    .into(),
            ))
        }
    }

    /// Encode as a base64url string for easy sharing.
    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_vec(self)
            .map_err(|e| SharingError::InvalidInvite(format!("encode: {e}")))?;
        Ok(base64_encode(&json))
    }

    /// Decode from a base64url string.
    pub fn decode(encoded: &str) -> Result<Self> {
        let bytes = base64_decode(encoded)
            .map_err(|e| SharingError::InvalidInvite(format!("decode base64: {e}")))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| SharingError::InvalidInvite(format!("decode json: {e}")))
    }
}

/// Derive the invite HMAC key from the volume's metadata key.
///
/// Uses BLAKE3's key derivation function so the invite HMAC key is domain-
/// separated from all other uses of `meta_key`. The context string is fixed
/// and must never be reused for any other purpose.
///
/// The returned 32-byte key is passed to [`InviteCode::sign`] and
/// [`InviteCode::verify`].
pub fn derive_invite_hmac_key(meta_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("teagarden invite-hmac v1", meta_key)
}

/// Simple base64url encoding (no padding).
fn base64_encode(data: &[u8]) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(data)
}

/// Simple base64url decoding (no padding).
fn base64_decode(s: &str) -> std::result::Result<Vec<u8>, base64ct::Error> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::decode_vec(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_invite() {
        let invite = Invite::new(
            "vol-1".into(),
            "user-1".into(),
            AccessLevel::ReadWrite,
            0,
            0,
        );
        assert!(invite.is_valid());
        assert_eq!(invite.use_count, 0);
        assert!(!invite.revoked);
    }

    #[test]
    fn revoke_invite() {
        let mut invite = Invite::new("vol-1".into(), "user-1".into(), AccessLevel::ReadOnly, 0, 0);
        assert!(invite.is_valid());
        invite.revoke();
        assert!(!invite.is_valid());
    }

    #[test]
    fn max_uses_enforced() {
        let mut invite = Invite::new("vol-1".into(), "user-1".into(), AccessLevel::ReadOnly, 0, 2);
        assert!(invite.try_use().is_ok());
        assert!(invite.try_use().is_ok());
        assert!(invite.try_use().is_err());
    }

    #[test]
    fn expired_invite_invalid() {
        let mut invite = Invite::new(
            "vol-1".into(),
            "user-1".into(),
            AccessLevel::ReadOnly,
            1, // expired at epoch second 1
            0,
        );
        assert!(!invite.is_valid());
        assert!(invite.try_use().is_err());
    }

    #[test]
    fn invite_code_roundtrip() {
        let code = InviteCode {
            invite_id: "inv-123".into(),
            volume_id: "vol-456".into(),
            hmac: vec![0xAB; 32],
        };
        let encoded = code.encode().unwrap();
        let decoded = InviteCode::decode(&encoded).unwrap();
        assert_eq!(decoded.invite_id, "inv-123");
        assert_eq!(decoded.volume_id, "vol-456");
        assert_eq!(decoded.hmac, vec![0xAB; 32]);
    }

    #[test]
    fn invalid_invite_code_fails() {
        assert!(InviteCode::decode("not-valid-base64!!!").is_err());
    }

    // --- HMAC sign / verify tests ---

    fn make_test_code() -> InviteCode {
        InviteCode {
            invite_id: "inv-test-001".into(),
            volume_id: "vol-test-abc".into(),
            hmac: Vec::new(),
        }
    }

    #[test]
    fn sign_and_verify_succeeds() {
        let key = [0x5Au8; 32];
        let code = make_test_code().sign(&key).expect("sign should succeed");

        // HMAC must be populated (32 bytes for HMAC-SHA256).
        assert_eq!(code.hmac.len(), 32);

        // Verification with the same key must succeed.
        code.verify(&key)
            .expect("verify should succeed for a correctly signed invite");
    }

    #[test]
    fn verify_fails_for_wrong_key() {
        let key_a = [0x5Au8; 32];
        let key_b = [0x6Bu8; 32];
        let code = make_test_code().sign(&key_a).expect("sign should succeed");

        let result = code.verify(&key_b);
        assert!(result.is_err(), "verify must fail when using the wrong key");
    }

    #[test]
    fn verify_fails_for_empty_hmac() {
        let key = [0x5Au8; 32];
        let code = make_test_code(); // hmac is empty
        let result = code.verify(&key);
        assert!(
            result.is_err(),
            "verify must fail-closed when hmac field is empty (legacy / forged code)"
        );
    }

    #[test]
    fn verify_fails_for_tampered_volume_id() {
        let key = [0x5Au8; 32];
        let mut code = make_test_code().sign(&key).expect("sign should succeed");

        // Attacker overwrites volume_id after signing.
        code.volume_id = "vol-evil-999".into();

        let result = code.verify(&key);
        assert!(
            result.is_err(),
            "verify must fail when volume_id is tampered"
        );
    }

    #[test]
    fn verify_fails_for_tampered_invite_id() {
        let key = [0x5Au8; 32];
        let mut code = make_test_code().sign(&key).expect("sign should succeed");

        // Attacker overwrites invite_id after signing.
        code.invite_id = "inv-different-999".into();

        let result = code.verify(&key);
        assert!(
            result.is_err(),
            "verify must fail when invite_id is tampered"
        );
    }

    #[test]
    fn sign_then_encode_decode_verify_roundtrip() {
        let key = [0xAAu8; 32];
        let original = make_test_code().sign(&key).expect("sign should succeed");

        let encoded = original.encode().expect("encode should succeed");
        let decoded = InviteCode::decode(&encoded).expect("decode should succeed");

        decoded
            .verify(&key)
            .expect("verify should succeed after encode/decode roundtrip");
    }

    #[test]
    fn serialization_roundtrip() {
        let invite = Invite::new("vol-1".into(), "user-1".into(), AccessLevel::Admin, 0, 5);
        let json = serde_json::to_string(&invite).unwrap();
        let deserialized: Invite = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.volume_id, "vol-1");
        assert_eq!(deserialized.access_level, AccessLevel::Admin);
        assert_eq!(deserialized.max_uses, 5);
    }
}
