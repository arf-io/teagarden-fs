//! Encrypted, journaled per-file identity for portable SDO versions.

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use teagarden_core::crypto::{aead, keys::SymmetricKey};

use crate::opaque_schema::OpaqueSchema;

/// Permanent identity and latest-version linkage for one live inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdoFileIdentity {
    /// UUID shared by every revision and rename of this file.
    pub file_id: Uuid,
    /// Telegram message id of its first TGFV version.
    pub origin_message_id: Option<i64>,
    /// Most recently committed TGFV version UUID.
    pub latest_version_id: Option<Uuid>,
    /// Most recently committed file-wide local version number.
    pub local_version: u64,
}

/// Encrypted identity records stored under opaque SQLite names.
pub struct SdoIdentityStore<'a> {
    conn: &'a Connection,
    schema: &'a OpaqueSchema,
    meta_key: &'a SymmetricKey,
}

impl<'a> SdoIdentityStore<'a> {
    /// Create a store over the current metadata connection.
    pub fn new(conn: &'a Connection, schema: &'a OpaqueSchema, meta_key: &'a SymmetricKey) -> Self {
        Self {
            conn,
            schema,
            meta_key,
        }
    }

    /// Load and authenticate the identity belonging to a live inode.
    pub fn get(&self, ino: u64) -> rusqlite::Result<Option<SdoFileIdentity>> {
        let t = self.schema.require_table("sdo_identities")?;
        let c_ino = self.schema.require_column("sdo_identities", "ino")?;
        let c_data = self.schema.require_column("sdo_identities", "data")?;
        let encrypted: Option<Vec<u8>> = self
            .conn
            .query_row(
                &format!("SELECT {c_data} FROM {t} WHERE {c_ino} = ?1"),
                [ino as i64],
                |row| row.get(0),
            )
            .optional()?;
        encrypted
            .map(|bytes| {
                let aad = format!("sdo-file-identity:{ino}");
                let plain = aead::decrypt(self.meta_key, &bytes, aad.as_bytes()).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(std::io::Error::other(e.to_string())),
                    )
                })?;
                postcard::from_bytes(&plain).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(std::io::Error::other(e.to_string())),
                    )
                })
            })
            .transpose()
    }

    /// Save an encrypted identity; callers use their journaled transaction.
    pub fn set(&self, ino: u64, identity: &SdoFileIdentity) -> rusqlite::Result<()> {
        let t = self.schema.require_table("sdo_identities")?;
        let c_ino = self.schema.require_column("sdo_identities", "ino")?;
        let c_data = self.schema.require_column("sdo_identities", "data")?;
        let plain = postcard::to_allocvec(identity).map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(e.to_string())))
        })?;
        let aad = format!("sdo-file-identity:{ino}");
        let encrypted = aead::encrypt(self.meta_key, &plain, aad.as_bytes()).map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(e.to_string())))
        })?;
        self.conn.execute(
            &format!(
                "INSERT INTO {t} ({c_ino}, {c_data}) VALUES (?1, ?2) \
                 ON CONFLICT({c_ino}) DO UPDATE SET {c_data} = excluded.{c_data}"
            ),
            params![ino as i64, encrypted],
        )?;
        Ok(())
    }

    /// Remove an identity when its inode is deleted, so inode-number reuse starts
    /// a distinct portable file lineage. Retained encrypted versions remain intact.
    pub fn delete(&self, ino: u64) -> rusqlite::Result<()> {
        let t = self.schema.require_table("sdo_identities")?;
        let c_ino = self.schema.require_column("sdo_identities", "ino")?;
        self.conn
            .execute(&format!("DELETE FROM {t} WHERE {c_ino} = ?1"), [ino as i64])?;
        Ok(())
    }
}
