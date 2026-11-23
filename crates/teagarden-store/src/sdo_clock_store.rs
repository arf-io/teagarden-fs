use rusqlite::{params, Connection, OptionalExtension};

use crate::opaque_schema::OpaqueSchema;

/// Durable local hybrid logical clock values for one private volume index.
pub struct SdoClockStore<'a> {
    conn: &'a Connection,
    schema: &'a OpaqueSchema,
}

impl<'a> SdoClockStore<'a> {
    /// Open the clock state in a volume's local SQLite index.
    pub fn new(conn: &'a Connection, schema: &'a OpaqueSchema) -> Self {
        Self { conn, schema }
    }

    /// Load the persisted `(physical_ms, counter)` pair, if one has been written.
    pub fn get(&self) -> rusqlite::Result<Option<(u64, u64)>> {
        let table = self.schema.require_table("sdo_clock")?;
        let id = self.schema.require_column("sdo_clock", "clock_id")?;
        let physical = self.schema.require_column("sdo_clock", "physical_ms")?;
        let counter = self.schema.require_column("sdo_clock", "counter")?;
        self.conn
            .query_row(
                &format!("SELECT {physical}, {counter} FROM {table} WHERE {id} = 1"),
                [],
                |row| {
                    let p: Vec<u8> = row.get(0)?;
                    let c: Vec<u8> = row.get(1)?;
                    let p: [u8; 8] = p.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?;
                    let c: [u8; 8] = c.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?;
                    Ok((u64::from_le_bytes(p), u64::from_le_bytes(c)))
                },
            )
            .optional()
    }

    /// Persist a clock pair before the corresponding TGFV upload.
    pub fn set(&self, physical_ms: u64, counter: u64) -> rusqlite::Result<()> {
        let table = self.schema.require_table("sdo_clock")?;
        let id = self.schema.require_column("sdo_clock", "clock_id")?;
        let physical = self.schema.require_column("sdo_clock", "physical_ms")?;
        let count = self.schema.require_column("sdo_clock", "counter")?;
        self.conn.execute(
            &format!("INSERT INTO {table} ({id}, {physical}, {count}) VALUES (1, ?1, ?2) ON CONFLICT({id}) DO UPDATE SET {physical} = excluded.{physical}, {count} = excluded.{count}"),
            params![physical_ms.to_le_bytes().as_slice(), counter.to_le_bytes().as_slice()],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{migrations::initialize_database, schema::logical_tables};
    use teagarden_core::crypto::keys::SymmetricKey;

    #[test]
    fn hybrid_clock_survives_store_recreation_and_preserves_full_u64() {
        let conn = Connection::open_in_memory().unwrap();
        let schema = OpaqueSchema::new(SymmetricKey::from_bytes([7; 32]), &logical_tables());
        initialize_database(&conn, &schema).unwrap();
        {
            let store = SdoClockStore::new(&conn, &schema);
            assert_eq!(store.get().unwrap(), None);
            store.set(u64::MAX, 42).unwrap();
        }
        assert_eq!(
            SdoClockStore::new(&conn, &schema).get().unwrap(),
            Some((u64::MAX, 42))
        );
    }
}
