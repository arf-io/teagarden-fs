//! Journaled local index for uploaded TGFV objects.

use rusqlite::{params, Connection, OptionalExtension};

use crate::opaque_schema::OpaqueSchema;

/// An encrypted file-version object retained beside the local manifest history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSdoVersion {
    /// Keyed digest of the relative path.
    pub path_id: [u8; 32],
    /// Inode that emitted this version (diagnostic/index only).
    pub ino: u64,
    /// Telegram document identity.
    pub message_id: i64,
    /// Complete encrypted TGFV wire bytes.
    pub wire: Vec<u8>,
}

/// Opaque-schema storage for portable versions. Callers write through their
/// existing journaled transaction so the local object identity survives replay.
pub struct SdoVersionStore<'a> {
    conn: &'a Connection,
    schema: &'a OpaqueSchema,
}

impl<'a> SdoVersionStore<'a> {
    /// Create a store over the current metadata connection.
    pub fn new(conn: &'a Connection, schema: &'a OpaqueSchema) -> Self {
        Self { conn, schema }
    }

    /// Record one uploaded object. Duplicate version UUIDs are rejected.
    pub fn insert(
        &self,
        version_id: &[u8; 16],
        version: &StoredSdoVersion,
    ) -> rusqlite::Result<()> {
        let t = self.schema.require_table("sdo_versions")?;
        let c_vid = self.schema.require_column("sdo_versions", "version_id")?;
        let c_path = self.schema.require_column("sdo_versions", "path_id")?;
        let c_ino = self.schema.require_column("sdo_versions", "ino")?;
        let c_mid = self.schema.require_column("sdo_versions", "message_id")?;
        let c_data = self.schema.require_column("sdo_versions", "data")?;
        self.conn.execute(
            &format!("INSERT INTO {t} ({c_vid}, {c_path}, {c_ino}, {c_mid}, {c_data}) VALUES (?1, ?2, ?3, ?4, ?5)"),
            params![version_id.as_slice(), version.path_id.as_slice(), version.ino as i64, version.message_id, version.wire],
        )?;
        Ok(())
    }

    /// Atomically replace the physical location of an authenticated identical
    /// logical version while preserving its local inode and path identity.
    pub fn replace_location(
        &self,
        version_id: &[u8; 16],
        message_id: i64,
        wire: &[u8],
    ) -> rusqlite::Result<()> {
        let table = self.schema.require_table("sdo_versions")?;
        let id = self.schema.require_column("sdo_versions", "version_id")?;
        let message = self.schema.require_column("sdo_versions", "message_id")?;
        let data = self.schema.require_column("sdo_versions", "data")?;
        let count = self.conn.execute(
            &format!("UPDATE {table} SET {message} = ?2, {data} = ?3 WHERE {id} = ?1"),
            params![version_id.as_slice(), message_id, wire],
        )?;
        if count != 1 {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        Ok(())
    }

    /// Fetch one retained version by its opaque UUID.
    pub fn get(&self, version_id: &[u8; 16]) -> rusqlite::Result<Option<StoredSdoVersion>> {
        let t = self.schema.require_table("sdo_versions")?;
        let c_vid = self.schema.require_column("sdo_versions", "version_id")?;
        let c_path = self.schema.require_column("sdo_versions", "path_id")?;
        let c_ino = self.schema.require_column("sdo_versions", "ino")?;
        let c_mid = self.schema.require_column("sdo_versions", "message_id")?;
        let c_data = self.schema.require_column("sdo_versions", "data")?;
        self.conn
            .query_row(
                &format!("SELECT {c_path}, {c_ino}, {c_mid}, {c_data} FROM {t} WHERE {c_vid} = ?1"),
                params![version_id.as_slice()],
                |row| {
                    let raw_path: Vec<u8> = row.get(0)?;
                    let mut path_id = [0u8; 32];
                    if raw_path.len() == 32 {
                        path_id.copy_from_slice(&raw_path);
                    }
                    Ok(StoredSdoVersion {
                        path_id,
                        ino: row.get::<_, i64>(1)? as u64,
                        message_id: row.get(2)?,
                        wire: row.get(3)?,
                    })
                },
            )
            .optional()
    }

    /// Fetch all retained versions emitted by one inode, oldest first by rowid.
    pub fn list_for_inode(&self, ino: u64) -> rusqlite::Result<Vec<StoredSdoVersion>> {
        let t = self.schema.require_table("sdo_versions")?;
        let c_path = self.schema.require_column("sdo_versions", "path_id")?;
        let c_ino = self.schema.require_column("sdo_versions", "ino")?;
        let c_mid = self.schema.require_column("sdo_versions", "message_id")?;
        let c_data = self.schema.require_column("sdo_versions", "data")?;
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {c_path}, {c_mid}, {c_data} FROM {t} WHERE {c_ino} = ?1 ORDER BY rowid"
        ))?;
        let rows = stmt.query_map(params![ino as i64], |row| {
            let raw_path: Vec<u8> = row.get(0)?;
            let mut path_id = [0u8; 32];
            if raw_path.len() == 32 {
                path_id.copy_from_slice(&raw_path);
            }
            Ok(StoredSdoVersion {
                path_id,
                ino,
                message_id: row.get(1)?,
                wire: row.get(2)?,
            })
        })?;
        rows.collect()
    }

    /// Fetch all retained encrypted objects for a keyed path digest.
    pub fn list_for_path(&self, path_id: &[u8; 32]) -> rusqlite::Result<Vec<StoredSdoVersion>> {
        let t = self.schema.require_table("sdo_versions")?;
        let c_path = self.schema.require_column("sdo_versions", "path_id")?;
        let c_ino = self.schema.require_column("sdo_versions", "ino")?;
        let c_mid = self.schema.require_column("sdo_versions", "message_id")?;
        let c_data = self.schema.require_column("sdo_versions", "data")?;
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {c_ino}, {c_mid}, {c_data} FROM {t} WHERE {c_path} = ?1"
        ))?;
        let rows = stmt.query_map(params![path_id.as_slice()], |row| {
            Ok(StoredSdoVersion {
                path_id: *path_id,
                ino: row.get::<_, i64>(0)? as u64,
                message_id: row.get(1)?,
                wire: row.get(2)?,
            })
        })?;
        rows.collect()
    }

    /// List every retained object for snapshot backfill/repair.
    pub fn list_all(&self) -> rusqlite::Result<Vec<StoredSdoVersion>> {
        let t = self.schema.require_table("sdo_versions")?;
        let c_path = self.schema.require_column("sdo_versions", "path_id")?;
        let c_ino = self.schema.require_column("sdo_versions", "ino")?;
        let c_mid = self.schema.require_column("sdo_versions", "message_id")?;
        let c_data = self.schema.require_column("sdo_versions", "data")?;
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {c_path}, {c_ino}, {c_mid}, {c_data} FROM {t}"
        ))?;
        let rows = stmt.query_map([], |row| {
            let raw_path: Vec<u8> = row.get(0)?;
            let mut path_id = [0u8; 32];
            if raw_path.len() == 32 {
                path_id.copy_from_slice(&raw_path);
            }
            Ok(StoredSdoVersion {
                path_id,
                ino: row.get::<_, i64>(1)? as u64,
                message_id: row.get(2)?,
                wire: row.get(3)?,
            })
        })?;
        rows.collect()
    }
}
