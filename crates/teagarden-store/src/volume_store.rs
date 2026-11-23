use rusqlite::{params, Connection};

use teagarden_core::crypto::{aead, keys::SymmetricKey};
use teagarden_core::volume::config::VolumeConfig;

use crate::opaque_schema::OpaqueSchema;

/// Volume configuration storage (encrypted).
pub struct VolumeStore<'a> {
    conn: &'a Connection,
    schema: &'a OpaqueSchema,
    meta_key: &'a SymmetricKey,
}

impl<'a> VolumeStore<'a> {
    /// Create a volume-config store; `meta_key` encrypts the stored volume configuration.
    pub fn new(conn: &'a Connection, schema: &'a OpaqueSchema, meta_key: &'a SymmetricKey) -> Self {
        Self {
            conn,
            schema,
            meta_key,
        }
    }

    /// Insert or replace the volume configuration, storing it as an AEAD-encrypted
    /// JSON blob keyed by `volume_id` and refreshing the `created_at`/`updated_at` columns.
    pub fn save_config(&self, config: &VolumeConfig) -> rusqlite::Result<()> {
        let t = self.schema.require_table("volume")?;
        let c_vid = self.schema.require_column("volume", "volume_id")?;
        let c_data = self.schema.require_column("volume", "data")?;
        let c_cat = self.schema.require_column("volume", "created_at")?;
        let c_uat = self.schema.require_column("volume", "updated_at")?;

        // Use a self-describing format (JSON): VolumeConfig has
        // `skip_serializing_if` fields (e.g. `metadata_version`, `block_v2_from_epoch`)
        // that omit themselves at their default value. A non-self-describing format
        // like postcard would write nothing for an omitted field but still expect it
        // on read, so an omitted-default field breaks the round-trip. JSON tolerates
        // the absence and falls back to `#[serde(default)]`.
        let serialized = serde_json::to_vec(config).map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(e.to_string())))
        })?;
        let aad = format!("volume:{}", config.volume_id);
        let encrypted = aead::encrypt(self.meta_key, &serialized, aad.as_bytes()).map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(e.to_string())))
        })?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let sql = format!(
            "INSERT OR REPLACE INTO {t} ({c_vid}, {c_data}, {c_cat}, {c_uat}) VALUES (?1, ?2, ?3, ?4)"
        );
        self.conn.execute(
            &sql,
            params![config.volume_id.to_string(), encrypted, now, now],
        )?;
        Ok(())
    }

    /// Load and decrypt the configuration for a volume, or `None` if absent.
    pub fn load_config(&self, volume_id: &str) -> rusqlite::Result<Option<VolumeConfig>> {
        let t = self.schema.require_table("volume")?;
        let c_vid = self.schema.require_column("volume", "volume_id")?;
        let c_data = self.schema.require_column("volume", "data")?;

        let sql = format!("SELECT {c_data} FROM {t} WHERE {c_vid} = ?1");
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query(params![volume_id])?;

        match rows.next()? {
            Some(row) => {
                let encrypted: Vec<u8> = row.get(0)?;
                let aad = format!("volume:{volume_id}");
                let decrypted =
                    aead::decrypt(self.meta_key, &encrypted, aad.as_bytes()).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Blob,
                            Box::new(std::io::Error::other(e.to_string())),
                        )
                    })?;
                let config: VolumeConfig = serde_json::from_slice(&decrypted).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(std::io::Error::other(e.to_string())),
                    )
                })?;
                Ok(Some(config))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::initialize_database;
    use crate::opaque_schema::OpaqueSchema;
    use crate::schema::logical_tables;

    fn setup() -> (Connection, OpaqueSchema, SymmetricKey) {
        let conn = Connection::open_in_memory().unwrap();
        let schema_key = SymmetricKey::from_bytes([0x42; 32]);
        let schema = OpaqueSchema::new(schema_key, &logical_tables());
        initialize_database(&conn, &schema).unwrap();
        let meta_key = SymmetricKey::from_bytes([0x99; 32]);
        (conn, schema, meta_key)
    }

    #[test]
    fn save_and_load_config() {
        let (conn, schema, meta_key) = setup();
        let store = VolumeStore::new(&conn, &schema, &meta_key);

        let config = VolumeConfig::new("test-vol".into(), "noun verb adj".into());
        let vol_id = config.volume_id.to_string();

        store.save_config(&config).unwrap();
        let loaded = store.load_config(&vol_id).unwrap().unwrap();
        assert_eq!(loaded.display_name, "test-vol");
        assert_eq!(loaded.volume_id, config.volume_id);
    }

    #[test]
    fn load_nonexistent() {
        let (conn, schema, meta_key) = setup();
        let store = VolumeStore::new(&conn, &schema, &meta_key);
        assert!(store.load_config("nonexistent").unwrap().is_none());
    }
}
