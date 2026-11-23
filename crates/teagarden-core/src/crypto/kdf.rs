use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::crypto::keys::{Argon2Params, EpochKey, KeyHierarchy, SymmetricKey};
use crate::error::{CoreError, Result};

/// Derive the root key from a password and salt using Argon2id.
pub fn derive_root_key(
    password: &[u8],
    salt: &[u8; 32],
    params: &Argon2Params,
) -> Result<SymmetricKey> {
    use argon2::{Algorithm, Argon2, Version};

    // core-L1: bounds-check before argon2 allocates anything or `output[..32]`.
    params.validate()?;

    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        argon2::Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(params.output_len),
        )
        .map_err(|e| CoreError::KeyDerivation(format!("argon2 params: {e}")))?,
    );

    let mut output = vec![0u8; params.output_len];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| CoreError::KeyDerivation(format!("argon2: {e}")))?;

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&output[..32]);
    output.zeroize();
    let key = SymmetricKey::from_bytes(key_bytes);
    key_bytes.zeroize();
    Ok(key)
}

/// Derive a child key from a parent key using HKDF-SHA256.
///
/// An optional salt provides additional domain separation between volumes
/// that might share a password. When `None`, HKDF uses a zero-filled salt
/// per RFC 5869, which is safe when IKM is already uniform.
pub fn hkdf_derive(parent: &SymmetricKey, info: &[u8]) -> Result<SymmetricKey> {
    hkdf_derive_with_salt(parent, info, None)
}

/// Derive a child key with an explicit salt (e.g., the volume salt).
pub fn hkdf_derive_with_salt(
    parent: &SymmetricKey,
    info: &[u8],
    salt: Option<&[u8]>,
) -> Result<SymmetricKey> {
    let hk = Hkdf::<Sha256>::new(salt, parent.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|e| CoreError::KeyDerivation(format!("hkdf: {e}")))?;
    let key = SymmetricKey::from_bytes(okm);
    okm.zeroize();
    Ok(key)
}

/// Derive the complete key hierarchy from a root key and volume salt.
///
/// The salt is passed to HKDF's extract step, providing additional
/// defense-in-depth against related-key scenarios across volumes.
/// Used for legacy (v0) volumes that were created before channel binding.
pub fn derive_hierarchy(root: SymmetricKey, salt: &[u8; 32]) -> Result<KeyHierarchy> {
    derive_hierarchy_raw(root, salt)
}

/// Derive the complete key hierarchy, cryptographically bound to a specific
/// Telegram forum group **and** the volume's topic within it.
///
/// Both the shared `group_id` and the per-volume `topic_id` are appended to the
/// salt before the HKDF extract step, producing a completely distinct key
/// hierarchy for each (group, topic) pair even when the same password and random
/// salt are used. Because every volume lives in its own forum topic, binding the
/// topic id gives each volume a unique key hierarchy and prevents keys derived
/// for one volume's topic from decrypting another volume's data in the same
/// shared group (the T7 anti-substitution property).
pub fn derive_hierarchy_v1(
    root: SymmetricKey,
    salt: &[u8; 32],
    group_id: i64,
    topic_id: i64,
) -> Result<KeyHierarchy> {
    let mut bound_salt = [0u8; 48];
    bound_salt[..32].copy_from_slice(salt);
    bound_salt[32..40].copy_from_slice(&group_id.to_le_bytes());
    bound_salt[40..48].copy_from_slice(&topic_id.to_le_bytes());
    derive_hierarchy_raw(root, &bound_salt)
}

/// Derive the key hierarchy for a **MK-rooted** volume (K0b): the slot vault's
/// *random* 32-byte master key replaces the `Argon2id(password)` root of a legacy
/// volume, so the data/meta/integrity keys can only be reconstructed by unlocking
/// a factor that recovers the MK.
///
/// The MK is already uniform, so no Argon2 stretch is needed. It is first
/// domain-separated through one HKDF-Extract/Expand with a dedicated context —
/// so the master-key material is never used *verbatim* as HKDF IKM shared with
/// any other derivation — and the resulting root is then run through the exact
/// same `(group, topic)`-bound HKDF as [`derive_hierarchy_v1`]. Every
/// sub-key therefore binds to the volume's `(salt, group, topic)` identity
/// identically to a password-rooted volume; only the root differs.
///
/// **This derivation is frozen:** it defines the on-disk keys of every MK-rooted
/// volume ever created, so its context string and structure must never change.
pub fn derive_hierarchy_from_master_key(
    mk: &[u8; 32],
    salt: &[u8; 32],
    group_id: i64,
    topic_id: i64,
) -> Result<KeyHierarchy> {
    let mk_key = SymmetricKey::from_bytes(*mk);
    let root = hkdf_derive(&mk_key, b"teagarden.v2:mk-hierarchy-root")?;
    derive_hierarchy_v1(root, salt, group_id, topic_id)
}

fn derive_hierarchy_raw(root: SymmetricKey, salt: &[u8]) -> Result<KeyHierarchy> {
    use crate::crypto::keys::labels;

    let data = hkdf_derive_with_salt(&root, labels::DATA, Some(salt))?;
    let meta = hkdf_derive_with_salt(&root, labels::META, Some(salt))?;
    let schema = hkdf_derive_with_salt(&root, labels::SCHEMA, Some(salt))?;
    let integrity = hkdf_derive_with_salt(&root, labels::INTEGRITY, Some(salt))?;
    let wrapping = hkdf_derive_with_salt(&root, labels::WRAPPING, Some(salt))?;
    let block_id = hkdf_derive_with_salt(&root, labels::BLOCK_ID, Some(salt))?;
    let filename = hkdf_derive_with_salt(&root, labels::FILENAME, Some(salt))?;
    let manifest = hkdf_derive_with_salt(&root, labels::MANIFEST, Some(salt))?;

    Ok(KeyHierarchy {
        root,
        data,
        meta,
        schema,
        integrity,
        wrapping,
        block_id,
        filename,
        manifest,
    })
}

/// Derive an epoch-scoped key from a parent key.
pub fn derive_epoch_key(parent: &SymmetricKey, epoch: u32) -> Result<EpochKey> {
    let info = format!("epoch:{epoch}");
    let key = hkdf_derive(parent, info.as_bytes())?;
    Ok(EpochKey { epoch, key })
}

#[cfg(test)]
mod tests {
    use super::*;

    // core-L1: `kdf_params` come from volume.json and are read BEFORE any
    // authentication, so they are attacker-controlled. They must be refused with
    // an Err — never a panic, never an allocation abort.

    fn params(
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
        output_len: usize,
    ) -> Argon2Params {
        Argon2Params {
            memory_kib,
            iterations,
            parallelism,
            output_len,
        }
    }

    #[test]
    fn short_output_len_is_an_error_not_a_panic() {
        // output_len < 32 passes argon2's own check (min 4) and then panicked
        // slicing `&output[..32]`.
        let r = derive_root_key(b"pw", &[0x01; 32], &params(1024, 1, 1, 16));
        assert!(r.is_err(), "output_len 16 must be refused");
    }

    #[test]
    fn huge_memory_cost_is_an_error_not_an_abort() {
        // u32::MAX KiB = 4 TiB: argon2 accepts it and the allocation aborts the
        // whole process. It must be refused before any allocation.
        let r = derive_root_key(b"pw", &[0x01; 32], &params(u32::MAX, 1, 1, 32));
        assert!(r.is_err(), "4 TiB memory cost must be refused");
    }

    #[test]
    fn excessive_time_and_lane_costs_are_refused() {
        // A refusal is immediate; acceptance would run for hours, which is the bug.
        let t = derive_root_key(b"pw", &[0x01; 32], &params(1024, u32::MAX, 1, 32));
        assert!(t.is_err(), "iterations u32::MAX must be refused");
        let p = derive_root_key(b"pw", &[0x01; 32], &params(1024, 1, 0x00FF_FFFF, 32));
        assert!(p.is_err(), "parallelism 2^24-1 must be refused");
    }

    #[test]
    fn default_and_historic_params_still_validate() {
        // Every existing volume was created with Argon2Params::default(); it must
        // keep opening. 64 MiB/t=2/p=1 is the old passphrase-slot default, and the
        // low-cost params are what the test suites use.
        Argon2Params::default().validate().unwrap();
        params(65536, 2, 1, 32).validate().unwrap();
        params(65536, 3, 4, 32).validate().unwrap();
        params(1024, 1, 1, 32).validate().unwrap();
    }

    #[test]
    fn derive_root_key_deterministic() {
        let salt = [0x01; 32];
        let params = Argon2Params {
            memory_kib: 1024, // Low for tests
            iterations: 1,
            parallelism: 1,
            output_len: 32,
        };
        let k1 = derive_root_key(b"password", &salt, &params).unwrap();
        let k2 = derive_root_key(b"password", &salt, &params).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn different_passwords_produce_different_keys() {
        let salt = [0x01; 32];
        let params = Argon2Params {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
            output_len: 32,
        };
        let k1 = derive_root_key(b"password1", &salt, &params).unwrap();
        let k2 = derive_root_key(b"password2", &salt, &params).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let params = Argon2Params {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
            output_len: 32,
        };
        let k1 = derive_root_key(b"password", &[0x01; 32], &params).unwrap();
        let k2 = derive_root_key(b"password", &[0x02; 32], &params).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn hkdf_derive_deterministic() {
        let parent = SymmetricKey::from_bytes([0x42; 32]);
        let k1 = hkdf_derive(&parent, b"test-info").unwrap();
        let k2 = hkdf_derive(&parent, b"test-info").unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn hkdf_different_info_produces_different_keys() {
        let parent = SymmetricKey::from_bytes([0x42; 32]);
        let k1 = hkdf_derive(&parent, b"info-a").unwrap();
        let k2 = hkdf_derive(&parent, b"info-b").unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_hierarchy_all_keys_distinct() {
        let root = SymmetricKey::from_bytes([0x42; 32]);
        let h = derive_hierarchy(root, &[0x01; 32]).unwrap();

        let keys: Vec<&[u8; 32]> = vec![
            h.root.as_bytes(),
            h.data.as_bytes(),
            h.meta.as_bytes(),
            h.schema.as_bytes(),
            h.integrity.as_bytes(),
            h.wrapping.as_bytes(),
            h.block_id.as_bytes(),
            h.filename.as_bytes(),
            h.manifest.as_bytes(),
        ];

        // Verify all keys are distinct
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j], "keys {i} and {j} should differ");
            }
        }
    }

    #[test]
    fn derive_hierarchy_v1_is_deterministic_and_topic_bound() {
        let salt = [0x07; 32];
        let group = 1_000_000_000_i64;

        // Same (group, topic) + same root → identical hierarchy.
        let a = derive_hierarchy_v1(SymmetricKey::from_bytes([0x42; 32]), &salt, group, 5).unwrap();
        let b = derive_hierarchy_v1(SymmetricKey::from_bytes([0x42; 32]), &salt, group, 5).unwrap();
        assert_eq!(a.data.as_bytes(), b.data.as_bytes());

        // Different TOPIC in the same group → completely distinct data key (this is
        // the per-volume anti-substitution property: one volume's keys can't read
        // another volume's topic).
        let c = derive_hierarchy_v1(SymmetricKey::from_bytes([0x42; 32]), &salt, group, 6).unwrap();
        assert_ne!(a.data.as_bytes(), c.data.as_bytes());
        assert_ne!(a.integrity.as_bytes(), c.integrity.as_bytes());

        // Different GROUP → also distinct.
        let d =
            derive_hierarchy_v1(SymmetricKey::from_bytes([0x42; 32]), &salt, group + 1, 5).unwrap();
        assert_ne!(a.data.as_bytes(), d.data.as_bytes());
    }

    #[test]
    fn derive_epoch_keys_distinct() {
        let parent = SymmetricKey::from_bytes([0x42; 32]);
        let e0 = derive_epoch_key(&parent, 0).unwrap();
        let e1 = derive_epoch_key(&parent, 1).unwrap();
        assert_ne!(e0.key.as_bytes(), e1.key.as_bytes());
        assert_eq!(e0.epoch, 0);
        assert_eq!(e1.epoch, 1);
    }

    #[test]
    fn epoch_key_derivation_deterministic() {
        let parent = SymmetricKey::from_bytes([0x42; 32]);
        let e0a = derive_epoch_key(&parent, 0).unwrap();
        let e0b = derive_epoch_key(&parent, 0).unwrap();
        assert_eq!(e0a.key.as_bytes(), e0b.key.as_bytes());
    }

    /// Known-answer test for every hierarchy subkey that 1.0 derives, under
    /// the `teagarden.v1:*` labels. Every expected value was computed with an
    /// independent HKDF-SHA256 implementation (Python `hmac`/`hashlib`, checked
    /// against RFC 5869 test case 1), which first reproduced the values this
    /// test held under the earlier labels. If this test fails, existing volumes
    /// no longer decrypt.
    #[test]
    fn hierarchy_kat() {
        fn check(tag: &str, h: &KeyHierarchy, expect: [(&str, &str); 9]) {
            let got = [
                ("root", h.root.as_bytes()),
                ("data", h.data.as_bytes()),
                ("meta", h.meta.as_bytes()),
                ("schema", h.schema.as_bytes()),
                ("integrity", h.integrity.as_bytes()),
                ("wrapping", h.wrapping.as_bytes()),
                ("block_id", h.block_id.as_bytes()),
                ("filename", h.filename.as_bytes()),
                ("manifest", h.manifest.as_bytes()),
            ];
            for ((name, bytes), (ename, ehex)) in got.iter().zip(expect.iter()) {
                assert_eq!(name, ename, "{tag}: KAT table out of order");
                assert_eq!(hex::encode(bytes), *ehex, "{tag}: {name} key changed");
            }
        }

        let v0 = derive_hierarchy(SymmetricKey::from_bytes([0x42; 32]), &[0x01; 32]).unwrap();
        check(
            "derive_hierarchy",
            &v0,
            [
                (
                    "root",
                    "4242424242424242424242424242424242424242424242424242424242424242",
                ),
                (
                    "data",
                    "d9ecab6e9ec5767531e71f3a5412003aedb90d3f0478d3d1b4cec7d0a2200bb1",
                ),
                (
                    "meta",
                    "dd6df5ae57f5ee71aecb91d6006b136f3342c451a88878e8b299ea98a917e263",
                ),
                (
                    "schema",
                    "b6577fc1353c03cd569204d5ac3256c14fecfdb4d02a72689823036b697244f3",
                ),
                (
                    "integrity",
                    "84870cb06eb9c749742573d5458fc0112db81a6363f42a52ec670b5151631e2f",
                ),
                (
                    "wrapping",
                    "866f05acef5da38c31ee1e101238a34df974650f9cc7a43565d3d64956caac5d",
                ),
                (
                    "block_id",
                    "43b0c18af94e5681929423e420460b8efac0d6f76a169c1e5ef5310f8f6f0495",
                ),
                (
                    "filename",
                    "a952541a79eec2f3ced6f66d836b70f12ebbf44af66f8c2a5562850662e5d10d",
                ),
                (
                    "manifest",
                    "c41a4e88a5d8ba42ac48f9a712bff89cee46b5b26d27e1a96af2daf7a6cf9f43",
                ),
            ],
        );

        let v1 = derive_hierarchy_v1(
            SymmetricKey::from_bytes([0x42; 32]),
            &[0x07; 32],
            1_000_000_000,
            5,
        )
        .unwrap();
        check(
            "derive_hierarchy_v1",
            &v1,
            [
                (
                    "root",
                    "4242424242424242424242424242424242424242424242424242424242424242",
                ),
                (
                    "data",
                    "2a2c7b01284ddea749f2e5553d93c05f400d7d6af6b029aa13c9500d5c0db54a",
                ),
                (
                    "meta",
                    "44b946e21d4e6c19bcd8e365cba89d5adcc892d0e9973884137d9a7106fbcb3f",
                ),
                (
                    "schema",
                    "9c7f602b3d8085917d87c90fc5113fb698a51d5df8676465464870ca20d81043",
                ),
                (
                    "integrity",
                    "55b63da67013a590f9c9ca3d8d79e116842eff83ae8590e851932b3c2932ecd1",
                ),
                (
                    "wrapping",
                    "741dfa2d6ded8cb23c13f63fcfcb1903301c76d8e3dc63fbb23ccd5f2b132789",
                ),
                (
                    "block_id",
                    "2b5c1c2c3270b9a87b97775a6d226d81a5de88d3e34ebe5f10d06c979b76d783",
                ),
                (
                    "filename",
                    "396521016cd4d686bfeec3a284b55abc43ece21ccde4b48ef1e42739dbd626b1",
                ),
                (
                    "manifest",
                    "d485fc50b05fa3092802719241cbbbbf1f1667bcb6f5cdcb67879896e981b748",
                ),
            ],
        );

        let mk = derive_hierarchy_from_master_key(&[0x5a; 32], &[0x07; 32], -1_001_234_567_890, 42)
            .unwrap();
        check(
            "derive_hierarchy_from_master_key",
            &mk,
            [
                (
                    "root",
                    "03197d063b7eab33dd695c5b94d9c91ca7d89ba6220b70ac9489b5ad06fefca9",
                ),
                (
                    "data",
                    "60062fd33175a52c389b81cb6899554f6e7c952ec8cfe621330c77ef2c9f9a7f",
                ),
                (
                    "meta",
                    "7fbb35b3f704cf7bfa647a31094a0245cda14fb1fe724fb7142ba21c2d1fd08e",
                ),
                (
                    "schema",
                    "4c38f997c90ff1019723d7f0255f29d2e4b921fc562f936e6acf5570ae82a7cc",
                ),
                (
                    "integrity",
                    "0ce770fcf0c2fda705ddef618e96d8ad7db5bde140d990b8d1de40ae543103c8",
                ),
                (
                    "wrapping",
                    "4e418c195e7d3da6cb122d29bb9966ea22cef99ff3b44f5d48e77afd915f1482",
                ),
                (
                    "block_id",
                    "1b3cee9b13600238fc6140d60d57c819d905c0be4a944ec54e0d5589fb0a2525",
                ),
                (
                    "filename",
                    "4df112469b09f8c8822ec05aadb4be059419df8277f7020a2537c2251ee5164f",
                ),
                (
                    "manifest",
                    "e68512177f51132ca5481def91fdff4e52ad9d58edb95ac1f18abcfb47c3ce03",
                ),
            ],
        );
    }
}
