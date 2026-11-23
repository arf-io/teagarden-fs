use serde::{Deserialize, Serialize};

/// Recorded access-intent label for a roster entry.
///
/// No shipped volume data path enforces these predicates. They must not be
/// presented as authorization until an opener and every read/write/admin path
/// actually consult them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessLevel {
    /// Intended read-only label; currently not enforced.
    ReadOnly,
    /// Intended read/write label; currently not enforced.
    ReadWrite,
    /// Intended administrative label; currently not enforced.
    Admin,
}

impl AccessLevel {
    /// Whether this level permits reading files (true for every level).
    pub fn can_read(&self) -> bool {
        true
    }

    /// Whether this level permits writing files (`ReadWrite` or `Admin`).
    pub fn can_write(&self) -> bool {
        matches!(self, AccessLevel::ReadWrite | AccessLevel::Admin)
    }

    /// Whether this level permits managing other users (`Admin` only).
    pub fn can_manage_users(&self) -> bool {
        matches!(self, AccessLevel::Admin)
    }

    /// Stable byte encoding for AAD binding (see `grant`). Frozen: never reorder.
    pub fn as_u8(&self) -> u8 {
        match self {
            AccessLevel::ReadOnly => 0,
            AccessLevel::ReadWrite => 1,
            AccessLevel::Admin => 2,
        }
    }

    /// The canonical CLI/marker string for this level.
    pub fn as_str(&self) -> &'static str {
        match self {
            AccessLevel::ReadOnly => "read-only",
            AccessLevel::ReadWrite => "read-write",
            AccessLevel::Admin => "admin",
        }
    }
}

/// A user's share record for a volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareRecord {
    /// User identifier.
    pub user_id: String,
    /// Telegram user ID.
    pub telegram_user_id: i64,
    /// Display name.
    pub display_name: String,
    /// Recorded, unenforced access-intent label.
    pub access_level: AccessLevel,
    /// Wrapped data key (encrypted with user's ML-KEM public key).
    pub wrapped_key: Vec<u8>,
    /// When the roster entry was recorded.
    pub granted_at: i64,
    /// Whether this roster entry is currently active.
    pub active: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_levels() {
        assert!(AccessLevel::ReadOnly.can_read());
        assert!(!AccessLevel::ReadOnly.can_write());
        assert!(!AccessLevel::ReadOnly.can_manage_users());

        assert!(AccessLevel::ReadWrite.can_read());
        assert!(AccessLevel::ReadWrite.can_write());
        assert!(!AccessLevel::ReadWrite.can_manage_users());

        assert!(AccessLevel::Admin.can_read());
        assert!(AccessLevel::Admin.can_write());
        assert!(AccessLevel::Admin.can_manage_users());
    }

    #[test]
    fn serialization() {
        let record = ShareRecord {
            user_id: "user-1".into(),
            telegram_user_id: 12345,
            display_name: "Alice".into(),
            access_level: AccessLevel::ReadWrite,
            wrapped_key: vec![0x42; 32],
            granted_at: 1000000,
            active: true,
        };

        let json = serde_json::to_string(&record).unwrap();
        let deserialized: ShareRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.user_id, "user-1");
        assert_eq!(deserialized.access_level, AccessLevel::ReadWrite);
    }
}
