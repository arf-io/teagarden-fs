//! Marker and derivation kind for a volume opened from a **shared root** rather
//! than a local password or MK vault.
//!
//! A volume that was accepted from a share (multi-operator) or brought up on a
//! second machine (multi-computer single-operator) is opened via
//! [`super::manager::open_volume_shared`] using the owner's hierarchy root
//! directly. A small unauthenticated sidecar, [`SharedOrigin`], records that fact
//! next to `volume.json` so the unlock router sends the open down the shared path
//! instead of the password/MK path.
//!
//! The sidecar is deliberately **not** a field of [`super::config::VolumeConfig`]:
//! the config's `config_integrity` HMAC is computed over its exact serialized
//! bytes, and the owner ships those bytes verbatim to the recipient, so adding a
//! field would break the recipient's self-check. Leaving the marker unauthenticated
//! is safe: tampering `derivation` fails closed at the config-integrity check on
//! open, and `access_level` is advisory by construction (the holder possesses the
//! root and could ignore it — see the sharing threat-model notes).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

/// How the recipient reconstructs the key hierarchy from the shared 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SharedDerivation {
    /// The shared 32 bytes **are** `KeyHierarchy::root` — re-derive the hierarchy
    /// with `derive_hierarchy_v1`. This is the value `key export` ships and the
    /// only variant today, for *every* volume type: for a password volume the
    /// root is the Argon2 output, for an MK-rooted volume it is
    /// `HKDF(mk, "teagarden.v2:mk-hierarchy-root")` — in both cases the exact
    /// argument `derive_hierarchy_v1` already consumed, so re-deriving reproduces
    /// the identical hierarchy.
    ///
    /// A `MasterKey` variant must **never** be added that routes these root bytes
    /// back through `derive_hierarchy_from_master_key`: that would apply the
    /// MK-HKDF a second time and derive the wrong keys.
    HierarchyRootV1,
}

/// Sidecar written to `{volume_dir}/shared_origin.json`. Its presence routes
/// `open_volume` down the shared path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedOrigin {
    /// How to turn the stored root back into the key hierarchy.
    pub derivation: SharedDerivation,
    /// `"read-only"` | `"read-write"` | `"admin"` — a string so the mfa crate can
    /// route without depending on `teagarden-sharing::AccessLevel`. The CLI parses
    /// it to decide whether the mount is read-only. Advisory (client-enforced).
    pub access_level: String,
    /// Who granted this share (for display / auditing).
    pub granted_by: String,
    /// The volume this grant is for (matches `volume.json`'s `volume_id`).
    pub volume_id: String,
}

impl SharedOrigin {
    /// The sidecar path for a volume directory.
    pub fn path(base_dir: &Path) -> PathBuf {
        base_dir.join("shared_origin.json")
    }

    /// Whether a volume directory carries a shared-origin marker.
    pub fn exists(base_dir: &Path) -> bool {
        Self::path(base_dir).exists()
    }

    /// Load the marker if present.
    pub fn load(base_dir: &Path) -> Result<Option<Self>> {
        let p = Self::path(base_dir);
        if !p.exists() {
            return Ok(None);
        }
        let json = std::fs::read_to_string(&p)
            .map_err(|e| CoreError::Volume(format!("read shared_origin: {e}")))?;
        let origin: Self = serde_json::from_str(&json)
            .map_err(|e| CoreError::Serialization(format!("parse shared_origin: {e}")))?;
        Ok(Some(origin))
    }

    /// Atomically write the marker at 0600.
    pub fn save(&self, base_dir: &Path) -> Result<()> {
        let path = Self::path(base_dir);
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        crate::fsutil::write_file_atomic(&path, json.as_bytes(), "shared_origin")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_round_trips() {
        let dir = tempfile::TempDir::new().unwrap();
        assert!(!SharedOrigin::exists(dir.path()));
        assert!(SharedOrigin::load(dir.path()).unwrap().is_none());

        let origin = SharedOrigin {
            derivation: SharedDerivation::HierarchyRootV1,
            access_level: "read-only".into(),
            granted_by: "alice".into(),
            volume_id: "vol-1".into(),
        };
        origin.save(dir.path()).unwrap();
        assert!(SharedOrigin::exists(dir.path()));

        let loaded = SharedOrigin::load(dir.path()).unwrap().unwrap();
        assert_eq!(loaded.access_level, "read-only");
        assert_eq!(loaded.granted_by, "alice");
        assert_eq!(loaded.derivation, SharedDerivation::HierarchyRootV1);
    }

    /// Eight writers hammer `save` while reading back. With a fixed temp name they
    /// share (and truncate) one inode, so a torn marker can be renamed into place
    /// and the loser's rename fails; with a unique temp per call neither happens.
    #[test]
    fn concurrent_saves_never_tear_or_fail() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        let dir = tempfile::TempDir::new().unwrap();
        let base = Arc::new(dir.path().to_path_buf());
        let errors = Arc::new(AtomicUsize::new(0));
        let first_error = Arc::new(Mutex::new(None::<String>));
        let threads: Vec<_> = (0..8usize)
            .map(|t| {
                let (base, errors, first_error) =
                    (base.clone(), errors.clone(), first_error.clone());
                std::thread::spawn(move || {
                    // Different lengths per thread, so a torn write is also a parse error.
                    let origin = SharedOrigin {
                        derivation: SharedDerivation::HierarchyRootV1,
                        access_level: "read-only".into(),
                        granted_by: format!("writer-{t}-{}", "x".repeat(t * 97)),
                        volume_id: "vol-1".into(),
                    };
                    for _ in 0..200 {
                        let r = origin
                            .save(&base)
                            .map_err(|e| e.to_string())
                            .and_then(|()| match SharedOrigin::load(&base) {
                                Ok(Some(_)) => Ok(()),
                                Ok(None) => Err("marker vanished".to_string()),
                                Err(e) => Err(format!("torn shared_origin.json: {e}")),
                            });
                        if let Err(e) = r {
                            errors.fetch_add(1, Ordering::Relaxed);
                            first_error.lock().unwrap().get_or_insert(e);
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(
            errors.load(Ordering::Relaxed),
            0,
            "concurrent saves must never fail or tear; first error: {:?}",
            first_error.lock().unwrap()
        );
        assert_only_target_left(dir.path(), "shared_origin.json");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(SharedOrigin::path(dir.path()))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    fn assert_only_target_left(dir: &Path, name: &str) {
        let names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec![name.to_string()], "temp files left behind");
    }
}
