use rusqlite::{params, Connection};

use teagarden_core::block::pointer::FileManifest;
use teagarden_core::crypto::{aead, keys::SymmetricKey};

use crate::opaque_schema::OpaqueSchema;

/// Encrypted, versioned manifest history backed by SQLite with an opaque schema.
///
/// Every committed write of a file appends its new [`FileManifest`] here, keyed by
/// `(ino, version)`, so prior versions survive instead of being overwritten. This
/// is the durable substrate for `volume history` / `diff` / `revert` (and, later,
/// GC: a superseded block is "still referenced by retained history" rather than an
/// untracked orphan). The *current* version is also held inline on the inode row;
/// this table is the archive of ALL versions including the current one.
///
/// Writes go through the FUSE journal (the same `journaled_txn` as the inode and
/// block-row writes), so history is crash-recoverable and replays deterministically.
/// The `manifests` table has a composite PRIMARY KEY `(ino, version)`, which is
/// required for SQLite changeset capture (`sqlite3session_attach` silently drops
/// changes to PK-less tables).
pub struct ManifestStore<'a> {
    conn: &'a Connection,
    schema: &'a OpaqueSchema,
    meta_key: &'a SymmetricKey,
}

impl<'a> ManifestStore<'a> {
    /// Create a manifest-history store; `meta_key` encrypts the stored manifest blobs.
    pub fn new(conn: &'a Connection, schema: &'a OpaqueSchema, meta_key: &'a SymmetricKey) -> Self {
        Self {
            conn,
            schema,
            meta_key,
        }
    }

    /// AEAD associated data binds the ciphertext to its exact `(ino, version)` slot,
    /// so a database-level attacker cannot move a manifest blob to a different
    /// version or file without the decrypt failing.
    fn aad(ino: u64, version: u64) -> String {
        format!("manifest:{ino}:{version}")
    }

    /// Append a manifest version. Plain `INSERT` (matching `InodeStore`): each
    /// `(ino, version)` is written exactly once with fixed bytes, so a journal
    /// replay onto a fresh base applies cleanly.
    ///
    /// The `(ino, version)` PK columns are necessarily plaintext (they are the
    /// query/PK keys), but they are no more revealing than the inode and block rows
    /// already are. The schema's `created_at` column is written as a constant `0`:
    /// a real per-write nanosecond timestamp would be a metadata-timing leak (write
    /// frequency/timing) inconsistent with the opaque-schema model, where the
    /// inode's own timestamps are encrypted. Version ordering is carried by the
    /// `version` number; a future history view that surfaces timestamps must store
    /// them inside the encrypted blob, not as a cleartext column.
    pub fn insert(&self, manifest: &FileManifest) -> rusqlite::Result<()> {
        let t = self.schema.require_table("manifests")?;
        let c_ino = self.schema.require_column("manifests", "ino")?;
        let c_ver = self.schema.require_column("manifests", "version")?;
        let c_data = self.schema.require_column("manifests", "data")?;
        let c_cat = self.schema.require_column("manifests", "created_at")?;

        let serialized = postcard::to_allocvec(manifest).map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(e.to_string())))
        })?;
        let aad = Self::aad(manifest.inode, manifest.version);
        let encrypted = aead::encrypt(self.meta_key, &serialized, aad.as_bytes()).map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(e.to_string())))
        })?;

        let sql =
            format!("INSERT INTO {t} ({c_ino}, {c_ver}, {c_data}, {c_cat}) VALUES (?1, ?2, ?3, 0)");
        self.conn.execute(
            &sql,
            params![manifest.inode as i64, manifest.version as i64, encrypted],
        )?;
        Ok(())
    }

    /// Fetch a specific manifest version, or `None` if it was never persisted.
    pub fn get(&self, ino: u64, version: u64) -> rusqlite::Result<Option<FileManifest>> {
        let t = self.schema.require_table("manifests")?;
        let c_ino = self.schema.require_column("manifests", "ino")?;
        let c_ver = self.schema.require_column("manifests", "version")?;
        let c_data = self.schema.require_column("manifests", "data")?;

        let sql = format!("SELECT {c_data} FROM {t} WHERE {c_ino} = ?1 AND {c_ver} = ?2");
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query(params![ino as i64, version as i64])?;
        match rows.next()? {
            Some(row) => {
                let encrypted: Vec<u8> = row.get(0)?;
                let aad = Self::aad(ino, version);
                let decrypted =
                    aead::decrypt(self.meta_key, &encrypted, aad.as_bytes()).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Blob,
                            Box::new(std::io::Error::other(e.to_string())),
                        )
                    })?;
                let manifest: FileManifest = postcard::from_bytes(&decrypted).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(std::io::Error::other(e.to_string())),
                    )
                })?;
                Ok(Some(manifest))
            }
            None => Ok(None),
        }
    }

    /// List every persisted version number for an inode, oldest first.
    pub fn list_versions(&self, ino: u64) -> rusqlite::Result<Vec<u64>> {
        let t = self.schema.require_table("manifests")?;
        let c_ino = self.schema.require_column("manifests", "ino")?;
        let c_ver = self.schema.require_column("manifests", "version")?;

        let sql = format!("SELECT {c_ver} FROM {t} WHERE {c_ino} = ?1 ORDER BY {c_ver} ASC");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![ino as i64], |row| {
            let v: i64 = row.get(0)?;
            Ok(v as u64)
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Highest persisted version for an inode, or 0 if none exist. The write path
    /// uses this to keep versioning strictly monotonic: after an `O_TRUNC` or a
    /// truncate-to-zero clears the inode's current manifest, `prev.version` would
    /// otherwise reset to 0 and the next write would collide on the `(ino, version)`
    /// PRIMARY KEY. Sourcing the next version from the retained history avoids reuse.
    pub fn max_version(&self, ino: u64) -> rusqlite::Result<u64> {
        let t = self.schema.require_table("manifests")?;
        let c_ino = self.schema.require_column("manifests", "ino")?;
        let c_ver = self.schema.require_column("manifests", "version")?;
        let sql = format!("SELECT COALESCE(MAX({c_ver}), 0) FROM {t} WHERE {c_ino} = ?1");
        let n: i64 = self
            .conn
            .query_row(&sql, params![ino as i64], |row| row.get(0))?;
        Ok(n as u64)
    }

    /// Number of persisted versions for an inode (cheap count for tests/diagnostics).
    pub fn version_count(&self, ino: u64) -> rusqlite::Result<u64> {
        let t = self.schema.require_table("manifests")?;
        let c_ino = self.schema.require_column("manifests", "ino")?;
        let sql = format!("SELECT COUNT(*) FROM {t} WHERE {c_ino} = ?1");
        let n: i64 = self
            .conn
            .query_row(&sql, params![ino as i64], |row| row.get(0))?;
        Ok(n as u64)
    }

    /// Delete all persisted manifest versions for an inode. Called by the caller
    /// (in the same `journaled_txn`) when the inode is DESTROYED — `unlink`, or a
    /// `rename` over an existing target. Without this, `next_ino` (= `MAX(ino)+1`)
    /// can recycle a freed inode number, and the new file would inherit the old
    /// file's history and version counter (`max_version` would see stale rows) — a
    /// correctness + privacy leak. The referenced blocks are left untouched; they
    /// become unreferenced and are reclaimed by GC (1b), like other superseded
    /// blocks.
    pub fn delete_versions(&self, ino: u64) -> rusqlite::Result<()> {
        let t = self.schema.require_table("manifests")?;
        let c_ino = self.schema.require_column("manifests", "ino")?;
        let sql = format!("DELETE FROM {t} WHERE {c_ino} = ?1");
        self.conn.execute(&sql, params![ino as i64])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::initialize_database;
    use crate::schema::logical_tables;
    use teagarden_core::block::pointer::BlockPointer;
    use teagarden_core::crypto::keys::SymmetricKey;

    fn setup() -> (Connection, OpaqueSchema, SymmetricKey) {
        let conn = Connection::open_in_memory().unwrap();
        let key = SymmetricKey::from_bytes([0x42; 32]);
        let schema = OpaqueSchema::new(key, &logical_tables());
        initialize_database(&conn, &schema).unwrap();
        let meta_key = SymmetricKey::from_bytes([0x99; 32]);
        (conn, schema, meta_key)
    }

    fn manifest(ino: u64, version: u64, size: u64) -> FileManifest {
        FileManifest {
            inode: ino,
            version,
            total_size: size,
            file_hash: [version as u8; 32],
            blocks: vec![BlockPointer {
                block_id: [version as u8; 32],
                message_id: version as i64,
                file_offset: 0,
                length: size,
                block_data_offset: 0,
                encrypted_size: size + 16,
                compressed: false,
                epoch: 0,
            }],
            parent_ids: vec![],
        }
    }

    #[test]
    fn insert_and_get_roundtrip() {
        let (conn, schema, mk) = setup();
        let store = ManifestStore::new(&conn, &schema, &mk);
        let m = manifest(2, 1, 100);
        store.insert(&m).unwrap();
        let got = store.get(2, 1).unwrap().unwrap();
        assert_eq!(got, m);
    }

    #[test]
    fn get_missing_version_returns_none() {
        let (conn, schema, mk) = setup();
        let store = ManifestStore::new(&conn, &schema, &mk);
        store.insert(&manifest(2, 1, 100)).unwrap();
        assert!(store.get(2, 2).unwrap().is_none());
        assert!(store.get(3, 1).unwrap().is_none());
    }

    #[test]
    fn list_versions_oldest_first() {
        let (conn, schema, mk) = setup();
        let store = ManifestStore::new(&conn, &schema, &mk);
        store.insert(&manifest(2, 1, 100)).unwrap();
        store.insert(&manifest(2, 3, 300)).unwrap();
        store.insert(&manifest(2, 2, 200)).unwrap();
        let versions = store.list_versions(2).unwrap();
        assert_eq!(versions, vec![1, 2, 3]);
        assert_eq!(store.version_count(2).unwrap(), 3);
        assert_eq!(store.version_count(9).unwrap(), 0);
    }

    #[test]
    fn delete_versions_clears_history_for_recycled_inode() {
        let (conn, schema, mk) = setup();
        let store = ManifestStore::new(&conn, &schema, &mk);
        store.insert(&manifest(5, 1, 100)).unwrap();
        store.insert(&manifest(5, 2, 200)).unwrap();
        store.insert(&manifest(6, 1, 50)).unwrap();
        assert_eq!(store.max_version(5).unwrap(), 2);

        store.delete_versions(5).unwrap();
        // ino 5's history is gone (so a recycled ino 5 starts fresh at version 1);
        // ino 6 is untouched.
        assert_eq!(store.version_count(5).unwrap(), 0);
        assert_eq!(store.max_version(5).unwrap(), 0);
        assert!(store.list_versions(5).unwrap().is_empty());
        assert_eq!(store.version_count(6).unwrap(), 1);
    }

    #[test]
    fn aad_binds_version_slot() {
        // A manifest blob encrypted for (ino=2, v=1) must not decrypt if moved to a
        // different (ino, version) row — the AAD binding rejects substitution.
        let (conn, schema, mk) = setup();
        let store = ManifestStore::new(&conn, &schema, &mk);
        store.insert(&manifest(2, 1, 100)).unwrap();

        // Hand-copy the v1 ciphertext into the (ino=2, v=2) slot, bypassing insert.
        let t = schema.require_table("manifests").unwrap();
        let c_ino = schema.require_column("manifests", "ino").unwrap();
        let c_ver = schema.require_column("manifests", "version").unwrap();
        let c_data = schema.require_column("manifests", "data").unwrap();
        let c_cat = schema.require_column("manifests", "created_at").unwrap();
        let blob: Vec<u8> = conn
            .query_row(
                &format!("SELECT {c_data} FROM {t} WHERE {c_ino}=2 AND {c_ver}=1"),
                [],
                |r| r.get(0),
            )
            .unwrap();
        conn.execute(
            &format!(
                "INSERT INTO {t} ({c_ino}, {c_ver}, {c_data}, {c_cat}) VALUES (2, 2, ?1, 2000)"
            ),
            params![blob],
        )
        .unwrap();

        // v1 decrypts; the substituted v2 row fails AEAD (wrong AAD), not a panic.
        assert!(store.get(2, 1).unwrap().is_some());
        assert!(store.get(2, 2).is_err());
    }
}
