//! Encrypted crash-safe pending bytes for portable writes.

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use teagarden_core::crypto::{aead, keys::SymmetricKey};
use uuid::Uuid;

use crate::opaque_schema::OpaqueSchema;

/// One not-yet-acknowledged portable file save, including its deterministic retry identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdoPendingWrite {
    /// TGFV version UUID chosen before first upload; retries reuse this value.
    pub version_id: Uuid,
    /// Local inode number used to reconnect the pending save after mount restart.
    pub inode: u64,
    /// Open handle that last refreshed this durable image in the current mount.
    pub handle_id: u64,
    /// The exact version this writer opened, preserved for stale-writer lineage.
    pub predecessor: Option<Uuid>,
    /// Hybrid logical clock physical component chosen before first upload.
    pub clock_ms: u64,
    /// Hybrid logical clock counter chosen before first upload.
    pub clock_counter: u64,
    /// Complete plaintext image to publish; encrypted at rest by this store.
    pub bytes: Vec<u8>,
    /// Exact encoded upload, once generated, so an ambiguous Telegram result retries identically.
    pub wire: Option<Vec<u8>>,
    /// Complete logical record captured before local write acknowledgement, so
    /// recovery does not depend on a disposable mount's inode numbers.
    #[serde(default)]
    pub metadata_snapshot: Option<Vec<u8>>,
}

/// Opaque SQLite store for durable, encrypted pending portable writes.
pub struct SdoPendingWriteStore<'a> {
    conn: &'a Connection,
    schema: &'a OpaqueSchema,
    key: &'a SymmetricKey,
}

// A missing size descriptor denotes the pre-chunking whole-record encoding.
type PendingHeader = (SdoPendingWrite, Option<(u64, Option<u64>)>);

impl<'a> SdoPendingWriteStore<'a> {
    /// Open this store over a metadata connection and its volume metadata key.
    pub fn new(conn: &'a Connection, schema: &'a OpaqueSchema, key: &'a SymmetricKey) -> Self {
        Self { conn, schema, key }
    }

    /// Persist a complete retry image atomically, including its exact encoded wire.
    pub fn put(&self, value: &SdoPendingWrite) -> rusqlite::Result<()> {
        self.put_image(value, &value.bytes)
    }

    /// Start or replace a retry using separately encrypted fixed-size chunks.
    /// The header and every changed chunk commit together before acknowledgement.
    pub fn put_image(&self, header: &SdoPendingWrite, image: &[u8]) -> rusqlite::Result<()> {
        self.atomic(|| {
            self.delete_chunks(&header.version_id)?;
            self.write_chunks(header.version_id, image, 0..image.len())?;
            self.write_header(header, image.len())
        })
    }

    /// Replace only chunks intersecting a write, including any newly zero-filled gap.
    /// `image` is borrowed; neither existing chunks nor the growing file are cloned.
    pub fn patch_image(
        &self,
        header: &SdoPendingWrite,
        image: &[u8],
        changed: std::ops::Range<usize>,
    ) -> rusqlite::Result<()> {
        let Some((previous, Some((old_size, _)))) = self.read_header(&header.version_id)? else {
            return self.put_image(header, image);
        };
        if previous.wire.is_some() {
            return Err(sql_encode_error("cannot alter an encoded pending upload"));
        }
        if image.len() < usize::try_from(old_size).map_err(sql_decode_error)? {
            return self.put_image(header, image);
        }
        if changed.start > changed.end || changed.end > image.len() {
            return Err(sql_encode_error("invalid pending write range"));
        }
        self.atomic(|| {
            let start = changed
                .start
                .min(usize::try_from(old_size).map_err(sql_decode_error)?);
            self.write_chunks(header.version_id, image, start..changed.end)?;
            self.write_header(header, image.len())
        })
    }

    fn write_chunks(
        &self,
        version: Uuid,
        image: &[u8],
        changed: std::ops::Range<usize>,
    ) -> rusqlite::Result<()> {
        let (table, id, index, data) = self.chunk_columns()?;
        let mut insert = self.conn.prepare_cached(&format!(
            "INSERT INTO {table} ({id}, {index}, {data}) VALUES (?1, ?2, ?3) ON CONFLICT({id}, {index}) DO UPDATE SET {data}=excluded.{data}"))?;
        if !changed.is_empty() {
            for n in changed.start / PENDING_CHUNK_BYTES..changed.end.div_ceil(PENDING_CHUNK_BYTES)
            {
                let chunk = &image
                    [n * PENDING_CHUNK_BYTES..((n + 1) * PENDING_CHUNK_BYTES).min(image.len())];
                let aad = format!("sdo-pending-chunk:{version}:{n}");
                let encrypted =
                    aead::encrypt(self.key, chunk, aad.as_bytes()).map_err(sql_encode_error)?;
                insert.execute(params![version.as_bytes().as_slice(), n as i64, encrypted])?;
            }
        }
        self.conn.execute(
            &format!("DELETE FROM {table} WHERE {id}=?1 AND {index}>=?2"),
            params![
                version.as_bytes().as_slice(),
                image.len().div_ceil(PENDING_CHUNK_BYTES) as i64
            ],
        )?;
        Ok(())
    }

    fn write_header(&self, value: &SdoPendingWrite, size: usize) -> rusqlite::Result<()> {
        let (table, id, data) = self.columns()?;
        let header = SdoPendingWrite {
            version_id: value.version_id,
            inode: value.inode,
            handle_id: value.handle_id,
            predecessor: value.predecessor,
            clock_ms: value.clock_ms,
            clock_counter: value.clock_counter,
            bytes: Vec::new(),
            wire: None,
            metadata_snapshot: value.metadata_snapshot.clone(),
        };
        let wire_size = value.wire.as_ref().map(|wire| wire.len() as u64);
        if let Some(wire) = &value.wire {
            let (table, id, index, data) = self.chunk_columns()?;
            let mut insert = self.conn.prepare_cached(&format!(
                "INSERT INTO {table} ({id}, {index}, {data}) VALUES (?1, ?2, ?3)"
            ))?;
            for (n, chunk) in wire.chunks(PENDING_CHUNK_BYTES).enumerate() {
                let aad = format!("sdo-pending-wire:{}:{n}", value.version_id);
                let encrypted =
                    aead::encrypt(self.key, chunk, aad.as_bytes()).map_err(sql_encode_error)?;
                insert.execute(params![
                    value.version_id.as_bytes().as_slice(),
                    -1 - n as i64,
                    encrypted
                ])?;
            }
        }
        let mut plain = CHUNKED_MAGIC.to_vec();
        plain.extend(
            postcard::to_allocvec(&(size as u64, wire_size, header)).map_err(sql_encode_error)?,
        );
        let aad = format!("sdo-pending-write:{}", value.version_id);
        let encrypted =
            aead::encrypt(self.key, &plain, aad.as_bytes()).map_err(sql_encode_error)?;
        self.conn.execute(&format!("INSERT INTO {table} ({id}, {data}) VALUES (?1, ?2) ON CONFLICT({id}) DO UPDATE SET {data}=excluded.{data}"),
            params![value.version_id.as_bytes().as_slice(), encrypted])?;
        Ok(())
    }

    fn read_header(&self, version: &Uuid) -> rusqlite::Result<Option<PendingHeader>> {
        let (table, id, data) = self.columns()?;
        let raw: Option<Vec<u8>> = self
            .conn
            .query_row(
                &format!("SELECT {data} FROM {table} WHERE {id}=?1"),
                params![version.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        raw.map(|raw| {
            let aad = format!("sdo-pending-write:{version}");
            let plain = aead::decrypt(self.key, &raw, aad.as_bytes()).map_err(sql_decode_error)?;
            let (record, size) = if let Some(body) = plain.strip_prefix(CHUNKED_MAGIC) {
                let (size, wire_size, mut record): (u64, Option<u64>, SdoPendingWrite) =
                    postcard::from_bytes(body).map_err(sql_decode_error)?;
                if !record.bytes.is_empty() || record.wire.is_some() {
                    return Err(sql_decode_error("invalid chunked pending header"));
                }
                record.wire = wire_size.map(|_| Vec::new());
                (record, Some((size, wire_size)))
            } else {
                (decode_pending(&plain).map_err(sql_decode_error)?, None)
            };
            if record.version_id != *version {
                return Err(sql_decode_error("pending UUID mismatch"));
            }
            Ok((record, size))
        })
        .transpose()
    }

    /// Load and authenticate one complete retry, including all pending chunks.
    pub fn get(&self, version: &Uuid) -> rusqlite::Result<Option<SdoPendingWrite>> {
        let Some((mut record, size)) = self.read_header(version)? else {
            return Ok(None);
        };
        if let Some((size, wire_size)) = size {
            record.bytes = self.read_chunks(version, size, false)?;
            record.wire = wire_size
                .map(|size| self.read_chunks(version, size, true))
                .transpose()?;
        }
        Ok(Some(record))
    }

    fn read_chunks(&self, version: &Uuid, size: u64, wire: bool) -> rusqlite::Result<Vec<u8>> {
        let size = usize::try_from(size).map_err(sql_decode_error)?;
        let mut image = Vec::new();
        image.try_reserve_exact(size).map_err(sql_decode_error)?;
        let (table, id, index, data) = self.chunk_columns()?;
        let (condition, order) = if wire {
            ("< 0", "DESC")
        } else {
            (">= 0", "ASC")
        };
        let mut query=self.conn.prepare(&format!("SELECT {index}, {data} FROM {table} WHERE {id}=?1 AND {index} {condition} ORDER BY {index} {order}"))?;
        let mut rows = query.query(params![version.as_bytes().as_slice()])?;
        let mut next = 0i64;
        while let Some(row) = rows.next()? {
            let n: i64 = row.get(0)?;
            let expected = if wire { -1 - next } else { next };
            if n != expected || image.len() >= size {
                return Err(sql_decode_error("unexpected pending chunk"));
            }
            let raw: Vec<u8> = row.get(1)?;
            let aad = if wire {
                format!("sdo-pending-wire:{version}:{next}")
            } else {
                format!("sdo-pending-chunk:{version}:{next}")
            };
            let chunk = aead::decrypt(self.key, &raw, aad.as_bytes()).map_err(sql_decode_error)?;
            if chunk.len() != PENDING_CHUNK_BYTES.min(size - image.len()) {
                return Err(sql_decode_error("invalid pending chunk size"));
            }
            image.extend_from_slice(&chunk);
            next += 1;
        }
        if image.len() != size {
            return Err(sql_decode_error("missing pending chunk"));
        }
        Ok(image)
    }

    /// Read retry identities/metadata without materializing chunked file images.
    /// Bytes are omitted and an existing wire is represented by `Some(empty)`.
    /// Recovery must use `get` or `list`, which authenticate every required chunk.
    pub fn list_headers(&self) -> rusqlite::Result<Vec<SdoPendingWrite>> {
        self.ids()?
            .into_iter()
            .map(|id| {
                self.read_header(&id)?
                    .map(|(r, _)| r)
                    .ok_or_else(|| sql_decode_error("pending header disappeared"))
            })
            .collect()
    }

    /// List complete durable retries in insertion order for mount recovery.
    pub fn list(&self) -> rusqlite::Result<Vec<SdoPendingWrite>> {
        self.ids()?
            .into_iter()
            .map(|id| {
                self.get(&id)?
                    .ok_or_else(|| sql_decode_error("pending record disappeared"))
            })
            .collect()
    }

    fn ids(&self) -> rusqlite::Result<Vec<Uuid>> {
        let (table, id, _) = self.columns()?;
        let mut statement = self
            .conn
            .prepare(&format!("SELECT {id} FROM {table} ORDER BY rowid"))?;
        let rows = statement.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        rows.map(|r| Uuid::from_slice(&r?).map_err(sql_decode_error))
            .collect()
    }

    /// Remove a retry and its chunks atomically after publication/index commit.
    pub fn delete(&self, version: &Uuid) -> rusqlite::Result<()> {
        self.atomic(|| {
            self.delete_chunks(version)?;
            let (table, id, _) = self.columns()?;
            self.conn.execute(
                &format!("DELETE FROM {table} WHERE {id}=?1"),
                params![version.as_bytes().as_slice()],
            )?;
            Ok(())
        })
    }

    fn delete_chunks(&self, version: &Uuid) -> rusqlite::Result<()> {
        let (table, id, _, _) = self.chunk_columns()?;
        self.conn.execute(
            &format!("DELETE FROM {table} WHERE {id}=?1"),
            params![version.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    fn columns(&self) -> rusqlite::Result<(&str, &str, &str)> {
        Ok((
            self.schema.require_table("sdo_pending_writes")?,
            self.schema
                .require_column("sdo_pending_writes", "version_id")?,
            self.schema.require_column("sdo_pending_writes", "data")?,
        ))
    }

    fn chunk_columns(&self) -> rusqlite::Result<(&str, &str, &str, &str)> {
        Ok((
            self.schema.require_table("sdo_pending_chunks")?,
            self.schema
                .require_column("sdo_pending_chunks", "version_id")?,
            self.schema
                .require_column("sdo_pending_chunks", "chunk_index")?,
            self.schema.require_column("sdo_pending_chunks", "data")?,
        ))
    }

    fn atomic<T>(&self, work: impl FnOnce() -> rusqlite::Result<T>) -> rusqlite::Result<T> {
        // SAVEPOINT also nests safely inside a caller's journal/index transaction.
        self.conn.execute_batch("SAVEPOINT tg_pending_image")?;
        let mut rollback = PendingRollback {
            conn: self.conn,
            active: true,
        };
        let result = work()?;
        self.conn.execute_batch("RELEASE tg_pending_image")?;
        rollback.active = false;
        Ok(result)
    }
}

// Small fixed chunks keep the encrypted outbox's work linear in written bytes,
// even when the kernel sends a large cp as many small FUSE requests.
const PENDING_CHUNK_BYTES: usize = 64 * 1024;
const CHUNKED_MAGIC: &[u8] = b"teagarden.pending.chunked.v1\0";
struct PendingRollback<'a> {
    conn: &'a Connection,
    active: bool,
}
impl Drop for PendingRollback<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self
                .conn
                .execute_batch("ROLLBACK TO tg_pending_image; RELEASE tg_pending_image");
        }
    }
}

#[derive(Deserialize)]
struct LegacyPendingWrite {
    version_id: Uuid,
    inode: u64,
    handle_id: u64,
    predecessor: Option<Uuid>,
    clock_ms: u64,
    clock_counter: u64,
    bytes: Vec<u8>,
    wire: Option<Vec<u8>>,
}

fn decode_pending(plain: &[u8]) -> Result<SdoPendingWrite, postcard::Error> {
    if let Ok(value) = postcard::from_bytes(plain) {
        return Ok(value);
    }
    let (legacy, remaining): (LegacyPendingWrite, _) = postcard::take_from_bytes(plain)?;
    if !remaining.is_empty() {
        return Err(postcard::Error::DeserializeBadEncoding);
    }
    Ok(SdoPendingWrite {
        version_id: legacy.version_id,
        inode: legacy.inode,
        handle_id: legacy.handle_id,
        predecessor: legacy.predecessor,
        clock_ms: legacy.clock_ms,
        clock_counter: legacy.clock_counter,
        bytes: legacy.bytes,
        wire: legacy.wire,
        metadata_snapshot: None,
    })
}

fn sql_encode_error(error: impl std::fmt::Display) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(error.to_string())))
}

fn sql_decode_error(error: impl std::fmt::Display) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Blob,
        Box::new(std::io::Error::other(error.to_string())),
    )
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use teagarden_core::crypto::keys::SymmetricKey;
    use uuid::Uuid;

    use crate::{
        migrations::initialize_database, opaque_schema::OpaqueSchema, schema::logical_tables,
    };

    #[test]
    fn pending_write_survives_store_recreation_and_is_encrypted() {
        let conn = Connection::open_in_memory().unwrap();
        let key = SymmetricKey::from_bytes([0x91; 32]);
        let schema = OpaqueSchema::new(key.clone(), &logical_tables());
        initialize_database(&conn, &schema).unwrap();
        let id = Uuid::from_bytes([0x23; 16]);
        let pending = crate::sdo_pending_store::SdoPendingWrite {
            metadata_snapshot: None,
            version_id: id,
            inode: 7,
            handle_id: 11,
            predecessor: Some(Uuid::from_bytes([0x24; 16])),
            clock_ms: 1234,
            clock_counter: 5,
            bytes: b"pending-secret".to_vec(),
            wire: None,
        };
        let store = crate::sdo_pending_store::SdoPendingWriteStore::new(&conn, &schema, &key);
        store.put(&pending).unwrap();
        assert_eq!(store.get(&id).unwrap(), Some(pending));
        let table = schema.require_table("sdo_pending_writes").unwrap();
        let data = schema.require_column("sdo_pending_writes", "data").unwrap();
        let raw: Vec<u8> = conn
            .query_row(&format!("SELECT {data} FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert!(!raw.windows(14).any(|part| part == b"pending-secret"));
    }

    #[test]
    fn legacy_whole_image_pending_record_is_preserved_and_migrates_on_write() {
        let conn = Connection::open_in_memory().unwrap();
        let key = SymmetricKey::from_bytes([0x91; 32]);
        let schema = OpaqueSchema::new(key.clone(), &logical_tables());
        initialize_database(&conn, &schema).unwrap();
        let store = super::SdoPendingWriteStore::new(&conn, &schema, &key);
        let mut old = super::SdoPendingWrite {
            version_id: Uuid::new_v4(),
            inode: 7,
            handle_id: 11,
            predecessor: None,
            clock_ms: 12,
            clock_counter: 0,
            bytes: b"old acknowledged bytes".to_vec(),
            wire: None,
            metadata_snapshot: None,
        };
        let plain = postcard::to_allocvec(&old).unwrap();
        let aad = format!("sdo-pending-write:{}", old.version_id);
        let raw = teagarden_core::crypto::aead::encrypt(&key, &plain, aad.as_bytes()).unwrap();
        let (table, id, data) = store.columns().unwrap();
        conn.execute(
            &format!("INSERT INTO {table} ({id},{data}) VALUES (?1,?2)"),
            rusqlite::params![old.version_id.as_bytes().as_slice(), raw],
        )
        .unwrap();
        assert_eq!(store.get(&old.version_id).unwrap(), Some(old.clone()));
        old.bytes.extend_from_slice(b" plus more");
        store
            .patch_image(&old, &old.bytes, 22..old.bytes.len())
            .unwrap();
        assert_eq!(store.get(&old.version_id).unwrap(), Some(old));
        assert!(store.list_headers().unwrap()[0].bytes.is_empty());
    }

    #[test]
    fn chunked_pending_patch_is_atomic_and_detects_missing_or_swapped_chunks() {
        let conn = Connection::open_in_memory().unwrap();
        let key = SymmetricKey::from_bytes([0x91; 32]);
        let schema = OpaqueSchema::new(key.clone(), &logical_tables());
        initialize_database(&conn, &schema).unwrap();
        let store = super::SdoPendingWriteStore::new(&conn, &schema, &key);
        let header = super::SdoPendingWrite {
            version_id: Uuid::new_v4(),
            inode: 7,
            handle_id: 11,
            predecessor: None,
            clock_ms: 12,
            clock_counter: 0,
            bytes: Vec::new(),
            wire: None,
            metadata_snapshot: None,
        };
        let original = vec![0x4a; 3 * super::PENDING_CHUNK_BYTES];
        store.put_image(&header, &original).unwrap();
        let (table, id, index, data) = store.chunk_columns().unwrap();
        conn.execute_batch(&format!("CREATE TEMP TRIGGER fail_second BEFORE INSERT ON {table} WHEN new.{index}=1 BEGIN SELECT RAISE(ABORT,'injected storage failure'); END;")).unwrap();
        assert!(store
            .patch_image(&header, &vec![0x5b; original.len()], 0..original.len())
            .is_err());
        conn.execute_batch("DROP TRIGGER fail_second").unwrap();
        assert_eq!(
            store.get(&header.version_id).unwrap().unwrap().bytes,
            original,
            "a failed patch rolls back every chunk and the header"
        );
        let mut patched = original.clone();
        patched[65530..65546].copy_from_slice(&[0x19; 16]);
        store.patch_image(&header, &patched, 65530..65546).unwrap();
        assert_eq!(
            store.get(&header.version_id).unwrap().unwrap().bytes,
            patched
        );
        let raw: Vec<u8> = conn
            .query_row(
                &format!("SELECT {data} FROM {table} WHERE {id}=?1 AND {index}=0"),
                [header.version_id.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        conn.execute(
            &format!("UPDATE {table} SET {data}=?1 WHERE {index}=1"),
            [raw],
        )
        .unwrap();
        assert!(
            store.get(&header.version_id).is_err(),
            "chunk indices are authenticated"
        );
        let mut sealed = header.clone();
        sealed.bytes = original.clone();
        sealed.wire = Some(vec![0x8c; 5 * super::PENDING_CHUNK_BYTES + 13]);
        store.put(&sealed).unwrap();
        assert_eq!(store.get(&sealed.version_id).unwrap(), Some(sealed));
        assert!(
            store.patch_image(&header, &original, 0..1).is_err(),
            "encoded retry is immutable"
        );
        store.put_image(&header, &original).unwrap();
        conn.execute(&format!("DELETE FROM {table} WHERE {index}=1"), [])
            .unwrap();
        assert!(
            store.list().is_err(),
            "recovery refuses an incomplete image"
        );
        store.delete(&header.version_id).unwrap();
        assert!(store.list().unwrap().is_empty());
        assert_eq!(
            conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn pending_write_delete_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        let key = SymmetricKey::from_bytes([0x92; 32]);
        let schema = OpaqueSchema::new(key.clone(), &logical_tables());
        initialize_database(&conn, &schema).unwrap();
        let store = crate::sdo_pending_store::SdoPendingWriteStore::new(&conn, &schema, &key);
        let id = Uuid::from_bytes([0x25; 16]);
        store.delete(&id).unwrap();
        assert_eq!(store.get(&id).unwrap(), None);
    }
}
