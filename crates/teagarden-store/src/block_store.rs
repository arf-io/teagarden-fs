use rusqlite::{params, Connection, Transaction, TransactionBehavior};

use crate::opaque_schema::OpaqueSchema;

/// Block reference record for tracking uploaded blocks on Telegram.
///
/// `block_id` is the keyed BLAKE3 identity per CABS spec §3 — it is the
/// canonical address used for deduplication. The unkeyed content hash is
/// never stored (see CABS spec §2 — Forensic Hash Problem).
#[derive(Clone)]
pub struct BlockRecord {
    /// Keyed block identity: `BLAKE3_keyed(Kblocks_epoch, plaintext)`.
    pub block_id: [u8; 32],
    /// Grammar-derived Telegram document filename (e.g. `bright-falcon-echoes-softly.jpg`).
    pub filename: String,
    /// Telegram message ID where the encrypted block is stored.
    pub message_id: i64,
    /// Plaintext byte count for this block.
    pub plaintext_size: i64,
    /// Encrypted byte count on Telegram (includes SRB2/AEAD overhead).
    pub encrypted_size: i64,
    /// Key epoch used to compute `block_id` and `filename`.
    pub epoch: u32,
    /// Number of live manifest references to this block.
    pub ref_count: i64,
    /// Whether the plaintext was compressed before encryption.
    pub compressed: bool,
    /// SRB2: SHA-256 of the plaintext, verified after decrypt. Zero-filled for legacy SRB1 blocks.
    pub plaintext_sha256: [u8; 32],
    /// SRB2: SHA-256 of the encrypted payload, verified before decrypt. Zero-filled for legacy SRB1 blocks.
    pub ciphertext_sha256: [u8; 32],
}

/// Block reference storage.
pub struct BlockStore<'a> {
    conn: &'a Connection,
    schema: &'a OpaqueSchema,
}

impl<'a> BlockStore<'a> {
    /// Create a block store over the given connection and opaque schema.
    pub fn new(conn: &'a Connection, schema: &'a OpaqueSchema) -> Self {
        Self { conn, schema }
    }

    /// Insert a new block reference.
    pub fn insert(&self, block: &BlockRecord) -> rusqlite::Result<()> {
        let t = self.schema.require_table("blocks")?;
        let c_bid = self.schema.require_column("blocks", "block_id")?;
        let c_fn = self.schema.require_column("blocks", "filename")?;
        let c_mid = self.schema.require_column("blocks", "message_id")?;
        let c_ps = self.schema.require_column("blocks", "plaintext_size")?;
        let c_es = self.schema.require_column("blocks", "encrypted_size")?;
        let c_ep = self.schema.require_column("blocks", "epoch")?;
        let c_rc = self.schema.require_column("blocks", "ref_count")?;
        let c_comp = self.schema.require_column("blocks", "compressed")?;
        let c_pt_sha = self.schema.require_column("blocks", "plaintext_sha256")?;
        let c_ct_sha = self.schema.require_column("blocks", "ciphertext_sha256")?;

        let sql = format!(
            "INSERT INTO {t} ({c_bid}, {c_fn}, {c_mid}, {c_ps}, {c_es}, {c_ep}, {c_rc}, {c_comp}, {c_pt_sha}, {c_ct_sha})
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
        );
        self.conn.execute(
            &sql,
            params![
                block.block_id.as_slice(),
                block.filename,
                block.message_id,
                block.plaintext_size,
                block.encrypted_size,
                block.epoch,
                block.ref_count,
                i64::from(block.compressed),
                block.plaintext_sha256.as_slice(),
                block.ciphertext_sha256.as_slice(),
            ],
        )?;
        Ok(())
    }

    /// Get a block by its keyed block identity.
    pub fn get(&self, block_id: &[u8; 32]) -> rusqlite::Result<Option<BlockRecord>> {
        let t = self.schema.require_table("blocks")?;
        let c_bid = self.schema.require_column("blocks", "block_id")?;
        let c_fn = self.schema.require_column("blocks", "filename")?;
        let c_mid = self.schema.require_column("blocks", "message_id")?;
        let c_ps = self.schema.require_column("blocks", "plaintext_size")?;
        let c_es = self.schema.require_column("blocks", "encrypted_size")?;
        let c_ep = self.schema.require_column("blocks", "epoch")?;
        let c_rc = self.schema.require_column("blocks", "ref_count")?;
        let c_comp = self.schema.require_column("blocks", "compressed")?;
        let c_pt_sha = self.schema.require_column("blocks", "plaintext_sha256")?;
        let c_ct_sha = self.schema.require_column("blocks", "ciphertext_sha256")?;

        let sql = format!(
            "SELECT {c_fn}, {c_mid}, {c_ps}, {c_es}, {c_ep}, {c_rc}, {c_comp}, {c_pt_sha}, {c_ct_sha}
             FROM {t} WHERE {c_bid} = ?1"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query(params![block_id.as_slice()])?;

        match rows.next()? {
            Some(row) => {
                let pt_sha_bytes: Vec<u8> = row.get(7)?;
                let ct_sha_bytes: Vec<u8> = row.get(8)?;
                let mut plaintext_sha256 = [0u8; 32];
                let mut ciphertext_sha256 = [0u8; 32];
                if pt_sha_bytes.len() == 32 {
                    plaintext_sha256.copy_from_slice(&pt_sha_bytes);
                }
                if ct_sha_bytes.len() == 32 {
                    ciphertext_sha256.copy_from_slice(&ct_sha_bytes);
                }
                Ok(Some(BlockRecord {
                    block_id: *block_id,
                    filename: row.get(0)?,
                    message_id: row.get(1)?,
                    plaintext_size: row.get(2)?,
                    encrypted_size: row.get(3)?,
                    epoch: row.get::<_, i64>(4)? as u32,
                    ref_count: row.get(5)?,
                    compressed: row.get::<_, i64>(6)? != 0,
                    plaintext_sha256,
                    ciphertext_sha256,
                }))
            }
            None => Ok(None),
        }
    }

    /// Find a block by its keyed identity (for deduplication).
    ///
    /// Replaces the former `find_by_content_hash`. The unkeyed content hash
    /// is no longer stored — dedup is performed using `block_id` which is
    /// itself content-derived but keyed with the volume key (see CABS spec §3).
    pub fn find_by_block_id(&self, block_id: &[u8; 32]) -> rusqlite::Result<Option<BlockRecord>> {
        self.get(block_id)
    }

    /// Increment the reference count for a block.
    pub fn increment_ref(&self, block_id: &[u8; 32]) -> rusqlite::Result<()> {
        let t = self.schema.require_table("blocks")?;
        let c_bid = self.schema.require_column("blocks", "block_id")?;
        let c_rc = self.schema.require_column("blocks", "ref_count")?;

        let sql = format!("UPDATE {t} SET {c_rc} = {c_rc} + 1 WHERE {c_bid} = ?1");
        self.conn.execute(&sql, params![block_id.as_slice()])?;
        Ok(())
    }

    /// Decrement the reference count. Returns `true` if the block should be garbage collected.
    ///
    /// The UPDATE is guarded by `WHERE {c_rc} > 0` so `ref_count` never goes below zero.
    /// Both statements run inside a `BEGIN IMMEDIATE` transaction to prevent a TOCTOU
    /// race between the UPDATE and the subsequent SELECT.
    ///
    /// The transaction is managed via [`rusqlite::Transaction`], which automatically rolls
    /// back on drop if [`Transaction::commit`] has not been called. This ensures no dangling
    /// open transaction is left on the connection in any error path.
    pub fn decrement_ref(&self, block_id: &[u8; 32]) -> rusqlite::Result<bool> {
        let t = self.schema.require_table("blocks")?;
        let c_bid = self.schema.require_column("blocks", "block_id")?;
        let c_rc = self.schema.require_column("blocks", "ref_count")?;

        // `Transaction::new_unchecked` begins a `BEGIN IMMEDIATE` on the shared
        // `&Connection` and rolls back automatically on drop if not committed.
        let tx = Transaction::new_unchecked(self.conn, TransactionBehavior::Immediate)?;

        let update_sql =
            format!("UPDATE {t} SET {c_rc} = {c_rc} - 1 WHERE {c_bid} = ?1 AND {c_rc} > 0");
        tx.execute(&update_sql, params![block_id.as_slice()])?;

        let select_sql = format!("SELECT {c_rc} FROM {t} WHERE {c_bid} = ?1");
        let rc: i64 = tx.query_row(&select_sql, params![block_id.as_slice()], |r| r.get(0))?;

        tx.commit()?;

        Ok(rc <= 0)
    }

    /// List all blocks at a given epoch (for key rotation or migration).
    pub fn list_by_epoch(&self, epoch: u32) -> rusqlite::Result<Vec<BlockRecord>> {
        let t = self.schema.require_table("blocks")?;
        let c_bid = self.schema.require_column("blocks", "block_id")?;
        let c_fn = self.schema.require_column("blocks", "filename")?;
        let c_mid = self.schema.require_column("blocks", "message_id")?;
        let c_ps = self.schema.require_column("blocks", "plaintext_size")?;
        let c_es = self.schema.require_column("blocks", "encrypted_size")?;
        let c_ep = self.schema.require_column("blocks", "epoch")?;
        let c_rc = self.schema.require_column("blocks", "ref_count")?;
        let c_comp = self.schema.require_column("blocks", "compressed")?;
        let c_pt_sha = self.schema.require_column("blocks", "plaintext_sha256")?;
        let c_ct_sha = self.schema.require_column("blocks", "ciphertext_sha256")?;

        let sql = format!(
            "SELECT {c_bid}, {c_fn}, {c_mid}, {c_ps}, {c_es}, {c_rc}, {c_comp}, {c_pt_sha}, {c_ct_sha}
             FROM {t} WHERE {c_ep} = ?1"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![epoch], |row| {
            let bid_bytes: Vec<u8> = row.get(0)?;
            let mut block_id = [0u8; 32];
            block_id.copy_from_slice(&bid_bytes);
            let pt_sha_bytes: Vec<u8> = row.get(7)?;
            let ct_sha_bytes: Vec<u8> = row.get(8)?;
            let mut plaintext_sha256 = [0u8; 32];
            let mut ciphertext_sha256 = [0u8; 32];
            if pt_sha_bytes.len() == 32 {
                plaintext_sha256.copy_from_slice(&pt_sha_bytes);
            }
            if ct_sha_bytes.len() == 32 {
                ciphertext_sha256.copy_from_slice(&ct_sha_bytes);
            }
            Ok(BlockRecord {
                block_id,
                filename: row.get(1)?,
                message_id: row.get(2)?,
                plaintext_size: row.get(3)?,
                encrypted_size: row.get(4)?,
                epoch,
                ref_count: row.get(5)?,
                compressed: row.get::<_, i64>(6)? != 0,
                plaintext_sha256,
                ciphertext_sha256,
            })
        })?;

        let mut blocks = Vec::new();
        for row in rows {
            blocks.push(row?);
        }
        Ok(blocks)
    }

    /// Update a block's epoch, message_id, and ciphertext hash after
    /// re-encryption (key rotation).
    pub fn update_block_epoch(
        &self,
        block_id: &[u8; 32],
        new_epoch: u32,
        new_message_id: i64,
        new_encrypted_size: i64,
        new_ciphertext_sha256: &[u8; 32],
    ) -> rusqlite::Result<()> {
        let t = self.schema.require_table("blocks")?;
        let c_bid = self.schema.require_column("blocks", "block_id")?;
        let c_ep = self.schema.require_column("blocks", "epoch")?;
        let c_mid = self.schema.require_column("blocks", "message_id")?;
        let c_es = self.schema.require_column("blocks", "encrypted_size")?;
        let c_ct_sha = self.schema.require_column("blocks", "ciphertext_sha256")?;

        // Re-encryption produces a fresh AEAD nonce and therefore a new
        // ciphertext, so the stored ciphertext SHA-256 MUST be refreshed too —
        // otherwise a T7 fail-closed read of the rotated block would mismatch the
        // stale hash and be refused (data loss). The plaintext is unchanged, so
        // plaintext_sha256 is intentionally left as-is.
        let sql = format!(
            "UPDATE {t} SET {c_ep} = ?1, {c_mid} = ?2, {c_es} = ?3, {c_ct_sha} = ?4 WHERE {c_bid} = ?5"
        );
        self.conn.execute(
            &sql,
            params![
                new_epoch,
                new_message_id,
                new_encrypted_size,
                new_ciphertext_sha256.as_slice(),
                block_id.as_slice()
            ],
        )?;
        Ok(())
    }

    /// Delete a block reference (used after garbage collection removes it from Telegram).
    pub fn delete(&self, block_id: &[u8; 32]) -> rusqlite::Result<()> {
        let t = self.schema.require_table("blocks")?;
        let c_bid = self.schema.require_column("blocks", "block_id")?;
        let sql = format!("DELETE FROM {t} WHERE {c_bid} = ?1");
        self.conn.execute(&sql, params![block_id.as_slice()])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::initialize_database;
    use crate::opaque_schema::OpaqueSchema;
    use crate::schema::logical_tables;
    use teagarden_core::crypto::keys::SymmetricKey;

    fn setup() -> (Connection, OpaqueSchema) {
        let conn = Connection::open_in_memory().unwrap();
        let key = SymmetricKey::from_bytes([0x42; 32]);
        let schema = OpaqueSchema::new(key, &logical_tables());
        initialize_database(&conn, &schema).unwrap();
        (conn, schema)
    }

    fn test_block() -> BlockRecord {
        BlockRecord {
            block_id: [0x01; 32],
            filename: "bright-falcon-echoes-softly.jpg".to_string(),
            message_id: 12345,
            plaintext_size: 49000,
            encrypted_size: 50000,
            epoch: 0,
            ref_count: 1,
            compressed: true,
            plaintext_sha256: [0xAA; 32],
            ciphertext_sha256: [0xBB; 32],
        }
    }

    #[test]
    fn insert_and_get() {
        let (conn, schema) = setup();
        let store = BlockStore::new(&conn, &schema);
        let block = test_block();
        store.insert(&block).unwrap();

        let retrieved = store.get(&[0x01; 32]).unwrap().unwrap();
        assert_eq!(retrieved.message_id, 12345);
        assert_eq!(retrieved.plaintext_size, 49000);
        assert_eq!(retrieved.encrypted_size, 50000);
        assert!(retrieved.compressed);
        assert_eq!(retrieved.filename, "bright-falcon-echoes-softly.jpg");
    }

    #[test]
    fn find_by_block_id() {
        let (conn, schema) = setup();
        let store = BlockStore::new(&conn, &schema);
        store.insert(&test_block()).unwrap();

        let found = store.find_by_block_id(&[0x01; 32]).unwrap().unwrap();
        assert_eq!(found.block_id, [0x01; 32]);

        assert!(store.find_by_block_id(&[0xBB; 32]).unwrap().is_none());
    }

    #[test]
    fn ref_counting() {
        let (conn, schema) = setup();
        let store = BlockStore::new(&conn, &schema);
        store.insert(&test_block()).unwrap();

        store.increment_ref(&[0x01; 32]).unwrap();
        let b = store.get(&[0x01; 32]).unwrap().unwrap();
        assert_eq!(b.ref_count, 2);

        assert!(!store.decrement_ref(&[0x01; 32]).unwrap()); // 2 -> 1
        assert!(store.decrement_ref(&[0x01; 32]).unwrap()); // 1 -> 0 (GC-able)
    }

    #[test]
    fn decrement_ref_does_not_go_negative() {
        let (conn, schema) = setup();
        let store = BlockStore::new(&conn, &schema);
        store.insert(&test_block()).unwrap(); // ref_count = 1

        // First decrement: 1 -> 0 (GC candidate)
        assert!(store.decrement_ref(&[0x01; 32]).unwrap());

        // Second decrement: should NOT go to -1
        assert!(store.decrement_ref(&[0x01; 32]).unwrap()); // still 0, still GC-able
        let b = store.get(&[0x01; 32]).unwrap().unwrap();
        assert_eq!(b.ref_count, 0, "ref_count must not go below 0");
    }

    #[test]
    fn delete_block() {
        let (conn, schema) = setup();
        let store = BlockStore::new(&conn, &schema);
        store.insert(&test_block()).unwrap();
        store.delete(&[0x01; 32]).unwrap();
        assert!(store.get(&[0x01; 32]).unwrap().is_none());
    }

    #[test]
    fn list_by_epoch() {
        let (conn, schema) = setup();
        let store = BlockStore::new(&conn, &schema);

        store.insert(&test_block()).unwrap(); // epoch 0, block_id [0x01; 32]
        store
            .insert(&BlockRecord {
                block_id: [0x02; 32],
                filename: "dark-wolf-sings-quietly.png".to_string(),
                message_id: 22222,
                plaintext_size: 59000,
                encrypted_size: 60000,
                epoch: 0,
                ref_count: 1,
                compressed: false,
                plaintext_sha256: [0x00; 32],
                ciphertext_sha256: [0x00; 32],
            })
            .unwrap();
        store
            .insert(&BlockRecord {
                block_id: [0x03; 32],
                filename: "cold-river-flows-gently.mp4".to_string(),
                message_id: 33333,
                plaintext_size: 69000,
                encrypted_size: 70000,
                epoch: 1,
                ref_count: 1,
                compressed: true,
                plaintext_sha256: [0x00; 32],
                ciphertext_sha256: [0x00; 32],
            })
            .unwrap();

        let epoch0 = store.list_by_epoch(0).unwrap();
        assert_eq!(epoch0.len(), 2);

        let epoch1 = store.list_by_epoch(1).unwrap();
        assert_eq!(epoch1.len(), 1);
        assert_eq!(epoch1[0].message_id, 33333);

        let epoch2 = store.list_by_epoch(2).unwrap();
        assert!(epoch2.is_empty());
    }

    #[test]
    fn update_block_epoch() {
        let (conn, schema) = setup();
        let store = BlockStore::new(&conn, &schema);
        store.insert(&test_block()).unwrap();

        let new_ct_sha = [0xEE; 32];
        store
            .update_block_epoch(&[0x01; 32], 1, 99999, 55000, &new_ct_sha)
            .unwrap();

        let block = store.get(&[0x01; 32]).unwrap().unwrap();
        assert_eq!(block.epoch, 1);
        assert_eq!(block.message_id, 99999);
        assert_eq!(block.encrypted_size, 55000);
        // Rotation must refresh the ciphertext hash (regression for the key-
        // rotation data-loss bug: a stale hash bricks fail-closed reads).
        assert_eq!(block.ciphertext_sha256, new_ct_sha);

        let epoch0 = store.list_by_epoch(0).unwrap();
        assert!(epoch0.is_empty());
        let epoch1 = store.list_by_epoch(1).unwrap();
        assert_eq!(epoch1.len(), 1);
    }
}
