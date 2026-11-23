use std::sync::Arc;

use teagarden_core::crypto::mlkem::MlKemEncapsulationKey;
use teagarden_sharing::access::{AccessLevel, ShareRecord};
use teagarden_sharing::invite::{derive_invite_hmac_key, Invite, InviteCode};
use teagarden_sharing::key_exchange::wrap_key_for_user;
use teagarden_store::sharing_store::SharingStore;

use crate::error::{ApiError, Result};
use crate::service::session::VolumeSession;

/// Get the current Unix timestamp in seconds.
fn unix_now() -> Result<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| ApiError::Internal(format!("system clock error: {e}")))
}

/// Service wrapping sharing operations through an open volume session.
pub struct SharingService;

impl SharingService {
    /// List all shares for an open volume session.
    pub fn list_shares(session: &Arc<VolumeSession>) -> Result<Vec<ShareRecord>> {
        let conn = session
            .conn
            .lock()
            .map_err(|e| ApiError::Internal(format!("lock poisoned: {e}")))?;
        let store = SharingStore::new(&conn, &session.schema, &session.meta_key);
        store
            .list_shares(&session.volume_id)
            .map_err(|e| ApiError::Storage(format!("list shares: {e}")))
    }

    /// Create a new share in an open volume session.
    ///
    /// `recipient_ek` is the recipient's ML-KEM-768 encapsulation key (public key).
    /// The session's `data_key` is wrapped with it and stored in `wrapped_key`.
    pub fn create_share(
        session: &Arc<VolumeSession>,
        user_id: &str,
        access_level: AccessLevel,
        recipient_ek: &MlKemEncapsulationKey,
    ) -> Result<ShareRecord> {
        let now = unix_now()?;

        let aad = format!("share:{}:{}", session.volume_id, user_id);
        let wrapped = wrap_key_for_user(&session.data_key, recipient_ek, aad.as_bytes())
            .map_err(|e| ApiError::Internal(format!("key wrap failed: {e}")))?;
        let wrapped_key = wrapped
            .to_bytes()
            .map_err(|e| ApiError::Internal(format!("serialize wrapped key: {e}")))?;

        let share = ShareRecord {
            user_id: user_id.to_string(),
            telegram_user_id: 0,
            display_name: user_id.to_string(),
            access_level,
            wrapped_key,
            granted_at: now,
            active: true,
        };

        let conn = session
            .conn
            .lock()
            .map_err(|e| ApiError::Internal(format!("lock poisoned: {e}")))?;
        let store = SharingStore::new(&conn, &session.schema, &session.meta_key);
        store
            .insert_share(&session.volume_id, &share)
            .map_err(|e| ApiError::Storage(format!("create share: {e}")))?;

        Ok(share)
    }

    /// Revoke a share by user ID.
    pub fn revoke_share(session: &Arc<VolumeSession>, user_id: &str) -> Result<()> {
        let conn = session
            .conn
            .lock()
            .map_err(|e| ApiError::Internal(format!("lock poisoned: {e}")))?;
        let store = SharingStore::new(&conn, &session.schema, &session.meta_key);
        store
            .revoke_share(user_id)
            .map_err(|e| ApiError::Storage(format!("revoke share: {e}")))
    }

    /// Create an invite for the volume.
    pub fn create_invite(
        session: &Arc<VolumeSession>,
        access_level: AccessLevel,
        max_uses: u32,
        expires_at: i64,
    ) -> Result<Invite> {
        let invite = Invite::new(
            session.volume_id.clone(),
            "api".into(),
            access_level,
            expires_at,
            max_uses,
        );

        let conn = session
            .conn
            .lock()
            .map_err(|e| ApiError::Internal(format!("lock poisoned: {e}")))?;
        let store = SharingStore::new(&conn, &session.schema, &session.meta_key);
        store
            .insert_invite(&invite)
            .map_err(|e| ApiError::Storage(format!("create invite: {e}")))?;

        Ok(invite)
    }

    /// Accept an invite — verify the signed InviteCode HMAC then redeem the invite.
    ///
    /// `recipient_ek` is the acceptor's ML-KEM-768 encapsulation key. The session's
    /// `data_key` is wrapped with it and stored in `wrapped_key` so the recipient
    /// can later decrypt it using their secret key.
    pub fn accept_invite(
        session: &Arc<VolumeSession>,
        code: &InviteCode,
        user_id: &str,
        recipient_ek: &MlKemEncapsulationKey,
    ) -> Result<ShareRecord> {
        // Verify the HMAC using the volume-scoped key derived from meta_key.
        // Fail with InvalidArgument (400) so the caller gets INVALID_ARGUMENT,
        // not a 500, and the message is safe to surface.
        let hmac_key = derive_invite_hmac_key(session.meta_key.as_bytes());
        code.verify(&hmac_key).map_err(|e| {
            ApiError::InvalidArgument(format!("invite code verification failed: {e}"))
        })?;

        let invite_id = &code.invite_id;

        let conn = session
            .conn
            .lock()
            .map_err(|e| ApiError::Internal(format!("lock poisoned: {e}")))?;
        let store = SharingStore::new(&conn, &session.schema, &session.meta_key);

        let invite = store
            .use_invite(invite_id)
            .map_err(|e| ApiError::Storage(format!("use invite: {e}")))?
            .ok_or_else(|| {
                ApiError::InvalidArgument(format!("invite not found or expired: {invite_id}"))
            })?;

        let now = unix_now()?;

        let aad = format!("share:{}:{}", session.volume_id, user_id);
        let wrapped = wrap_key_for_user(&session.data_key, recipient_ek, aad.as_bytes())
            .map_err(|e| ApiError::Internal(format!("key wrap failed: {e}")))?;
        let wrapped_key = wrapped
            .to_bytes()
            .map_err(|e| ApiError::Internal(format!("serialize wrapped key: {e}")))?;

        let share = ShareRecord {
            user_id: user_id.to_string(),
            telegram_user_id: 0,
            display_name: user_id.to_string(),
            access_level: invite.access_level,
            wrapped_key,
            granted_at: now,
            active: true,
        };

        store
            .insert_share(&session.volume_id, &share)
            .map_err(|e| ApiError::Storage(format!("create share from invite: {e}")))?;

        Ok(share)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::session::SessionManager;
    use teagarden_core::volume::manager;
    use teagarden_sharing::invite::InviteCode;
    use teagarden_sharing::key_exchange::UserKeyPair;
    use tempfile::TempDir;

    fn setup() -> (TempDir, SessionManager, String) {
        let dir = TempDir::new().unwrap();
        let result = manager::create_volume(
            Some("share-test"),
            b"password123",
            dir.path(),
            0,
            0,
            0,
            None,
        )
        .unwrap();
        let vid = result.config.volume_id.to_string();
        crate::service::session::tests::seed_db(dir.path(), &vid, "password123");
        let mgr = SessionManager::new(dir.path().to_path_buf());
        (dir, mgr, vid)
    }

    /// Build a correctly signed InviteCode for a given invite and session.
    fn sign_invite_code(invite: &Invite, session: &VolumeSession) -> InviteCode {
        let hmac_key = derive_invite_hmac_key(session.meta_key.as_bytes());
        InviteCode {
            invite_id: invite.invite_id.clone(),
            volume_id: invite.volume_id.clone(),
            hmac: Vec::new(),
        }
        .sign(&hmac_key)
        .expect("sign should succeed in tests")
    }

    #[tokio::test]
    async fn create_and_list_shares() {
        let (_dir, mgr, vid) = setup();
        let session = mgr.open(&vid, "password123").await.unwrap();

        let kp_alice = UserKeyPair::generate().unwrap();
        let kp_bob = UserKeyPair::generate().unwrap();
        SharingService::create_share(
            &session,
            "alice",
            AccessLevel::ReadOnly,
            &kp_alice.encapsulation_key,
        )
        .unwrap();
        SharingService::create_share(
            &session,
            "bob",
            AccessLevel::ReadWrite,
            &kp_bob.encapsulation_key,
        )
        .unwrap();

        let shares = SharingService::list_shares(&session).unwrap();
        assert_eq!(shares.len(), 2);
    }

    #[tokio::test]
    async fn revoke_share() {
        let (_dir, mgr, vid) = setup();
        let session = mgr.open(&vid, "password123").await.unwrap();

        let kp = UserKeyPair::generate().unwrap();
        SharingService::create_share(
            &session,
            "alice",
            AccessLevel::ReadOnly,
            &kp.encapsulation_key,
        )
        .unwrap();
        SharingService::revoke_share(&session, "alice").unwrap();

        let shares = SharingService::list_shares(&session).unwrap();
        // revoke_share sets active=false; list_shares may still return the record
        // but it should be marked inactive
        let active: Vec<_> = shares.iter().filter(|s| s.active).collect();
        assert!(active.is_empty());
    }

    #[tokio::test]
    async fn create_and_accept_invite() {
        let (_dir, mgr, vid) = setup();
        let session = mgr.open(&vid, "password123").await.unwrap();

        let kp = UserKeyPair::generate().unwrap();
        let invite = SharingService::create_invite(&session, AccessLevel::ReadOnly, 5, 0).unwrap();
        let code = sign_invite_code(&invite, &session);

        let share =
            SharingService::accept_invite(&session, &code, "charlie", &kp.encapsulation_key)
                .unwrap();
        assert_eq!(share.user_id, "charlie");
        assert_eq!(share.access_level, AccessLevel::ReadOnly);
        // wrapped_key must be non-empty — key exchange must have run
        assert!(
            !share.wrapped_key.is_empty(),
            "wrapped_key must be populated after accept_invite"
        );
    }

    #[tokio::test]
    async fn empty_shares_list() {
        let (_dir, mgr, vid) = setup();
        let session = mgr.open(&vid, "password123").await.unwrap();

        let shares = SharingService::list_shares(&session).unwrap();
        assert!(shares.is_empty());
    }

    /// An InviteCode with no HMAC (empty vec) must be rejected before touching
    /// the store, even if the invite_id points to a real invite.
    #[tokio::test]
    async fn accept_invite_rejects_unsigned_code() {
        let (_dir, mgr, vid) = setup();
        let session = mgr.open(&vid, "password123").await.unwrap();

        let invite = SharingService::create_invite(&session, AccessLevel::ReadOnly, 5, 0).unwrap();

        // Build an unsigned code (hmac is empty) — must be rejected.
        let unsigned_code = InviteCode {
            invite_id: invite.invite_id.clone(),
            volume_id: invite.volume_id.clone(),
            hmac: Vec::new(),
        };

        let dummy_kp = UserKeyPair::generate().unwrap();
        let err = SharingService::accept_invite(
            &session,
            &unsigned_code,
            "user",
            &dummy_kp.encapsulation_key,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApiError::InvalidArgument(_)),
            "expected InvalidArgument, got: {err:?}"
        );
    }

    /// A code signed with the wrong key must be rejected.
    #[tokio::test]
    async fn accept_invite_rejects_wrong_key_hmac() {
        let (_dir, mgr, vid) = setup();
        let session = mgr.open(&vid, "password123").await.unwrap();

        let invite = SharingService::create_invite(&session, AccessLevel::ReadOnly, 5, 0).unwrap();

        // Sign with a bogus key — not derived from this volume's meta_key.
        let wrong_key = [0xFFu8; 32];
        let bad_code = InviteCode {
            invite_id: invite.invite_id.clone(),
            volume_id: invite.volume_id.clone(),
            hmac: Vec::new(),
        }
        .sign(&wrong_key)
        .unwrap();

        let dummy_kp = UserKeyPair::generate().unwrap();
        let err =
            SharingService::accept_invite(&session, &bad_code, "user", &dummy_kp.encapsulation_key)
                .unwrap_err();
        assert!(
            matches!(err, ApiError::InvalidArgument(_)),
            "expected InvalidArgument for wrong-key HMAC, got: {err:?}"
        );
    }

    /// A code with a tampered volume_id must be rejected.
    #[tokio::test]
    async fn accept_invite_rejects_tampered_volume_id() {
        let (_dir, mgr, vid) = setup();
        let session = mgr.open(&vid, "password123").await.unwrap();

        let invite = SharingService::create_invite(&session, AccessLevel::ReadOnly, 5, 0).unwrap();
        let mut code = sign_invite_code(&invite, &session);

        // Attacker overwrites volume_id after signing.
        code.volume_id = "vol-evil-999".into();

        let dummy_kp = UserKeyPair::generate().unwrap();
        let err =
            SharingService::accept_invite(&session, &code, "user", &dummy_kp.encapsulation_key)
                .unwrap_err();
        assert!(
            matches!(err, ApiError::InvalidArgument(_)),
            "expected InvalidArgument for tampered volume_id, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn accept_nonexistent_invite_fails() {
        let (_dir, mgr, vid) = setup();
        let session = mgr.open(&vid, "password123").await.unwrap();

        // Build a correctly signed code that points to a nonexistent invite_id.
        let hmac_key = derive_invite_hmac_key(session.meta_key.as_bytes());
        let code = InviteCode {
            invite_id: "nonexistent-id".into(),
            volume_id: vid.clone(),
            hmac: Vec::new(),
        }
        .sign(&hmac_key)
        .unwrap();

        let dummy_kp = UserKeyPair::generate().unwrap();
        let err =
            SharingService::accept_invite(&session, &code, "user", &dummy_kp.encapsulation_key)
                .unwrap_err();
        assert!(matches!(err, ApiError::InvalidArgument(_)));
    }
}
