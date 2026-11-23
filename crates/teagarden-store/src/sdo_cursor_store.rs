use rusqlite::{Connection, OptionalExtension};

use crate::opaque_schema::OpaqueSchema;

/// Durable high-water and applied cursor for descending raw-message polling.
pub struct SdoCursorStore<'a> {
    conn: &'a Connection,
    schema: &'a OpaqueSchema,
}

impl<'a> SdoCursorStore<'a> {
    /// Open the cursor in a private volume index.
    pub fn new(conn: &'a Connection, schema: &'a OpaqueSchema) -> Self {
        Self { conn, schema }
    }

    /// Return the last applied message ID and active batch high-water ID.
    pub fn get(&self) -> rusqlite::Result<Option<(i64, i64)>> {
        let table = self.schema.require_table("sdo_poll_cursor")?;
        let id = self.schema.require_column("sdo_poll_cursor", "cursor_id")?;
        let cursor = self
            .schema
            .require_column("sdo_poll_cursor", "message_id")?;
        let high = self
            .schema
            .require_column("sdo_poll_cursor", "high_water_id")?;
        self.conn
            .query_row(
                &format!("SELECT {cursor}, {high} FROM {table} WHERE {id} = 1"),
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
    }

    /// Persist cursor progress after applying a page in the caller's transaction.
    pub fn set(&self, message_id: i64, high_water_id: i64) -> rusqlite::Result<()> {
        let table = self.schema.require_table("sdo_poll_cursor")?;
        let id = self.schema.require_column("sdo_poll_cursor", "cursor_id")?;
        let cursor = self
            .schema
            .require_column("sdo_poll_cursor", "message_id")?;
        let high = self
            .schema
            .require_column("sdo_poll_cursor", "high_water_id")?;
        self.conn.execute(
            &format!("INSERT INTO {table} ({id}, {cursor}, {high}) VALUES (1, ?1, ?2) ON CONFLICT({id}) DO UPDATE SET {cursor} = excluded.{cursor}, {high} = excluded.{high}"),
            (message_id, high_water_id),
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
    fn poll_cursor_survives_store_recreation_and_tracks_batch_high_water() {
        let conn = Connection::open_in_memory().unwrap();
        let schema = OpaqueSchema::new(SymmetricKey::from_bytes([0x73; 32]), &logical_tables());
        initialize_database(&conn, &schema).unwrap();
        let store = SdoCursorStore::new(&conn, &schema);
        assert_eq!(store.get().unwrap(), None);
        store.set(220, 255).unwrap();
        assert_eq!(
            SdoCursorStore::new(&conn, &schema).get().unwrap(),
            Some((220, 255))
        );
    }
}
