use rusqlite::Connection;

use crate::opaque_schema::OpaqueSchema;

/// Schema version this build writes to `PRAGMA user_version`.
///
/// - 0: every DB created by a build that did not record a version. It may
///   contain the unused legacy table that step 0 → 1 drops (see `drop_legacy_tables`).
/// - 1: that table is gone.
///
/// Migrations are forward-only. A DB with a higher version than this (written
/// by a newer build) is opened as it is, and its version is never lowered.
pub const SCHEMA_VERSION: i64 = 1;

/// Create any missing tables under their opaque names, then bring the schema up
/// to [`SCHEMA_VERSION`].
///
/// Every path that opens a volume's metadata DB calls this, including the first
/// open after a snapshot restore or a journal rebuild, so a DB from an older
/// build is migrated before anything reads it.
pub fn initialize_database(conn: &Connection, schema: &OpaqueSchema) -> rusqlite::Result<()> {
    create_tables(conn, schema)?;
    migrate(conn, schema, &|_| {})
}

fn create_tables(conn: &Connection, schema: &OpaqueSchema) -> rusqlite::Result<()> {
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch("PRAGMA foreign_keys=OFF;")?;

    // Volume table
    let t = schema.require_table("volume")?;
    let c_vid = schema.require_column("volume", "volume_id")?;
    let c_data = schema.require_column("volume", "data")?;
    let c_cat = schema.require_column("volume", "created_at")?;
    let c_uat = schema.require_column("volume", "updated_at")?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {t} (
            {c_vid} TEXT PRIMARY KEY,
            {c_data} BLOB NOT NULL,
            {c_cat} INTEGER NOT NULL,
            {c_uat} INTEGER NOT NULL
        );"
    ))?;

    // Inodes table
    let t = schema.require_table("inodes")?;
    let c_ino = schema.require_column("inodes", "ino")?;
    let c_parent = schema.require_column("inodes", "parent")?;
    let c_nh = schema.require_column("inodes", "name_hash")?;
    let c_data = schema.require_column("inodes", "data")?;
    let c_ver = schema.require_column("inodes", "version")?;
    let i_parent = schema.require_index("inodes_parent")?;
    let i_pn = schema.require_index("inodes_parent_name")?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {t} (
            {c_ino} INTEGER PRIMARY KEY,
            {c_parent} INTEGER NOT NULL,
            {c_nh} BLOB NOT NULL,
            {c_data} BLOB NOT NULL,
            {c_ver} INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS {i_parent} ON {t}({c_parent});
        CREATE UNIQUE INDEX IF NOT EXISTS {i_pn} ON {t}({c_parent}, {c_nh});"
    ))?;

    // Blocks table (CABS spec §3 — keyed block_id as primary key, no unkeyed content hash)
    let t = schema.require_table("blocks")?;
    let c_bid = schema.require_column("blocks", "block_id")?;
    let c_fn = schema.require_column("blocks", "filename")?;
    let c_mid = schema.require_column("blocks", "message_id")?;
    let c_ps = schema.require_column("blocks", "plaintext_size")?;
    let c_es = schema.require_column("blocks", "encrypted_size")?;
    let c_ep = schema.require_column("blocks", "epoch")?;
    let c_rc = schema.require_column("blocks", "ref_count")?;
    let c_comp = schema.require_column("blocks", "compressed")?;
    let c_pt_sha = schema.require_column("blocks", "plaintext_sha256")?;
    let c_ct_sha = schema.require_column("blocks", "ciphertext_sha256")?;
    let i_mid = schema.require_index("blocks_message_id")?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {t} (
            {c_bid} BLOB PRIMARY KEY,
            {c_fn} TEXT NOT NULL,
            {c_mid} INTEGER NOT NULL,
            {c_ps} INTEGER NOT NULL,
            {c_es} INTEGER NOT NULL,
            {c_ep} INTEGER NOT NULL,
            {c_rc} INTEGER NOT NULL DEFAULT 1,
            {c_comp} INTEGER NOT NULL DEFAULT 0,
            {c_pt_sha} BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000',
            {c_ct_sha} BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
        );
        CREATE INDEX IF NOT EXISTS {i_mid} ON {t}({c_mid});"
    ))?;

    // Manifests table
    let t = schema.require_table("manifests")?;
    let c_ino = schema.require_column("manifests", "ino")?;
    let c_ver = schema.require_column("manifests", "version")?;
    let c_data = schema.require_column("manifests", "data")?;
    let c_cat = schema.require_column("manifests", "created_at")?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {t} (
            {c_ino} INTEGER NOT NULL,
            {c_ver} INTEGER NOT NULL,
            {c_data} BLOB NOT NULL,
            {c_cat} INTEGER NOT NULL,
            PRIMARY KEY ({c_ino}, {c_ver})
        );"
    ))?;

    // Portable file versions retain the encrypted TGFV object identity inside
    // the journaled metadata DB. The path index is a keyed digest, never a clear
    // pathname; the table's primary key makes SQLite session journaling include
    // every insert.
    let t = schema.require_table("sdo_versions")?;
    let c_vid = schema.require_column("sdo_versions", "version_id")?;
    let c_path = schema.require_column("sdo_versions", "path_id")?;
    let c_ino = schema.require_column("sdo_versions", "ino")?;
    let c_mid = schema.require_column("sdo_versions", "message_id")?;
    let c_data = schema.require_column("sdo_versions", "data")?;
    let i_path = schema.require_index("sdo_versions_path")?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {t} (
            {c_vid} BLOB PRIMARY KEY,
            {c_path} BLOB NOT NULL,
            {c_ino} INTEGER NOT NULL,
            {c_mid} INTEGER NOT NULL,
            {c_data} BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS {i_path} ON {t}({c_path});"
    ))?;

    // Persistent per-file SDO identity lives outside the postcard-serialized
    // Inode so older inode blobs and journal deltas remain byte-compatible.
    let t = schema.require_table("sdo_identities")?;
    let c_ino = schema.require_column("sdo_identities", "ino")?;
    let c_data = schema.require_column("sdo_identities", "data")?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {t} (
            {c_ino} INTEGER PRIMARY KEY,
            {c_data} BLOB NOT NULL
        );"
    ))?;

    // Local HLC state is durable before a portable object upload and is never
    // derived from filesystem mtime. Fixed-width blobs preserve the full u64 range.
    let t = schema.require_table("sdo_clock")?;
    let c_id = schema.require_column("sdo_clock", "clock_id")?;
    let c_physical = schema.require_column("sdo_clock", "physical_ms")?;
    let c_counter = schema.require_column("sdo_clock", "counter")?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {t} (
            {c_id} INTEGER PRIMARY KEY CHECK ({c_id} = 1),
            {c_physical} BLOB NOT NULL CHECK (length({c_physical}) = 8),
            {c_counter} BLOB NOT NULL CHECK (length({c_counter}) = 8)
        );"
    ))?;

    let t = schema.require_table("sdo_pending_writes")?;
    let c_id = schema.require_column("sdo_pending_writes", "version_id")?;
    let c_data = schema.require_column("sdo_pending_writes", "data")?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {t} (
            {c_id} BLOB PRIMARY KEY,
            {c_data} BLOB NOT NULL
        );"
    ))?;

    let t = schema.require_table("sdo_pending_chunks")?;
    let c_id = schema.require_column("sdo_pending_chunks", "version_id")?;
    let c_index = schema.require_column("sdo_pending_chunks", "chunk_index")?;
    let c_data = schema.require_column("sdo_pending_chunks", "data")?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {t} (
            {c_id} BLOB NOT NULL, {c_index} INTEGER NOT NULL, {c_data} BLOB NOT NULL,
            PRIMARY KEY ({c_id}, {c_index})
        );"
    ))?;

    let t = schema.require_table("sdo_poll_cursor")?;
    let c_id = schema.require_column("sdo_poll_cursor", "cursor_id")?;
    let c_cursor = schema.require_column("sdo_poll_cursor", "message_id")?;
    let c_high = schema.require_column("sdo_poll_cursor", "high_water_id")?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {t} (
            {c_id} INTEGER PRIMARY KEY CHECK ({c_id} = 1),
            {c_cursor} INTEGER NOT NULL,
            {c_high} INTEGER NOT NULL
        );"
    ))?;

    // Snapshots table
    let t = schema.require_table("snapshots")?;
    let c_sid = schema.require_column("snapshots", "sid")?;
    let c_ts = schema.require_column("snapshots", "timestamp")?;
    let c_data = schema.require_column("snapshots", "data")?;
    let c_ino = schema.require_column("snapshots", "ino")?;
    let i_ts = schema.require_index("snapshots_ts")?;
    let i_ino = schema.require_index("snapshots_ino")?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {t} (
            {c_sid} INTEGER PRIMARY KEY AUTOINCREMENT,
            {c_ts} INTEGER NOT NULL,
            {c_data} BLOB NOT NULL,
            {c_ino} INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS {i_ts} ON {t}({c_ts});
        CREATE INDEX IF NOT EXISTS {i_ino} ON {t}({c_ino});"
    ))?;

    // Policies table
    let t = schema.require_table("policies")?;
    let c_pid = schema.require_column("policies", "pid")?;
    let c_data = schema.require_column("policies", "data")?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {t} (
            {c_pid} INTEGER PRIMARY KEY,
            {c_data} BLOB NOT NULL
        );"
    ))?;

    // Path-policy mapping.
    //
    // `path_pattern` is the PRIMARY KEY: each pattern maps to exactly one policy,
    // and `priority` orders matches across DIFFERENT patterns. A PRIMARY KEY is
    // also REQUIRED for the v0.4.3 metadata journal — SQLite's session extension
    // silently omits changes to PK-less tables, so a journaled table without a PK
    // would drop its writes from the durability log (see the changeset spike and
    // the fail-closed PK check in the journal). The PK's implicit unique index
    // supersedes the old explicit index, so it is no longer created here.
    let t = schema.require_table("path_policies")?;
    let c_pp = schema.require_column("path_policies", "path_pattern")?;
    let c_pid = schema.require_column("path_policies", "pid")?;
    let c_pr = schema.require_column("path_policies", "priority")?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {t} (
            {c_pp} BLOB NOT NULL PRIMARY KEY,
            {c_pid} INTEGER NOT NULL,
            {c_pr} INTEGER NOT NULL
        );"
    ))?;

    // Users table
    let t = schema.require_table("users")?;
    let c_uid = schema.require_column("users", "uid")?;
    let c_data = schema.require_column("users", "data")?;
    let c_active = schema.require_column("users", "active")?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {t} (
            {c_uid} TEXT PRIMARY KEY,
            {c_data} BLOB NOT NULL,
            {c_active} INTEGER NOT NULL DEFAULT 1
        );"
    ))?;

    // Audit log
    let t = schema.require_table("audit_log")?;
    let c_id = schema.require_column("audit_log", "id")?;
    let c_ts = schema.require_column("audit_log", "timestamp")?;
    let c_uid = schema.require_column("audit_log", "uid")?;
    let c_act = schema.require_column("audit_log", "action")?;
    let c_det = schema.require_column("audit_log", "details")?;
    let i_ts = schema.require_index("audit_ts")?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {t} (
            {c_id} INTEGER PRIMARY KEY AUTOINCREMENT,
            {c_ts} INTEGER NOT NULL,
            {c_uid} TEXT,
            {c_act} BLOB NOT NULL,
            {c_det} BLOB
        );
        CREATE INDEX IF NOT EXISTS {i_ts} ON {t}({c_ts});"
    ))?;

    // Shares table
    let t = schema.require_table("shares")?;
    let c_sid = schema.require_column("shares", "sid")?;
    let c_vid = schema.require_column("shares", "volume_id")?;
    let c_uid = schema.require_column("shares", "uid")?;
    let c_data = schema.require_column("shares", "data")?;
    let c_active = schema.require_column("shares", "active")?;
    let i_vol = schema.require_index("shares_volume")?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {t} (
            {c_sid} TEXT PRIMARY KEY,
            {c_vid} TEXT NOT NULL,
            {c_uid} TEXT NOT NULL,
            {c_data} BLOB NOT NULL,
            {c_active} INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS {i_vol} ON {t}({c_vid});"
    ))?;

    // Invites table
    let t = schema.require_table("invites")?;
    let c_iid = schema.require_column("invites", "invite_id")?;
    let c_vid = schema.require_column("invites", "volume_id")?;
    let c_data = schema.require_column("invites", "data")?;
    let c_active = schema.require_column("invites", "active")?;
    let i_vol = schema.require_index("invites_volume")?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {t} (
            {c_iid} TEXT PRIMARY KEY,
            {c_vid} TEXT NOT NULL,
            {c_data} BLOB NOT NULL,
            {c_active} INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS {i_vol} ON {t}({c_vid});"
    ))?;

    // DAG edges table (Phase 4: manifest history DAG).
    // (child_id, parent_id) pairs form the version history graph.
    let t = schema.require_table("dag_edges")?;
    let c_child = schema.require_column("dag_edges", "child_id")?;
    let c_parent = schema.require_column("dag_edges", "parent_id")?;
    let i_child = schema.require_index("dag_edges_child")?;
    let i_parent = schema.require_index("dag_edges_parent")?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {t} (
            {c_child} BLOB NOT NULL,
            {c_parent} BLOB NOT NULL,
            PRIMARY KEY ({c_child}, {c_parent})
        );
        CREATE INDEX IF NOT EXISTS {i_child} ON {t}({c_child});
        CREATE INDEX IF NOT EXISTS {i_parent} ON {t}({c_parent});"
    ))?;

    create_lineage_table(conn, schema)?;
    create_session_table(conn, schema)?;

    Ok(())
}

fn user_version(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("PRAGMA user_version", [], |r| r.get(0))
}

/// Run every migration step from the DB's `user_version` up to
/// [`SCHEMA_VERSION`].
///
/// All steps run in ONE write transaction together with the version bump, so a
/// process killed part-way leaves the DB exactly as it was (still at the old
/// version) and the next open simply runs the migration again. The version is
/// re-read after the write lock is taken, so two processes opening the same old
/// DB at once migrate it exactly once. A DB that is already current is never
/// write-locked, so a reader such as `history` next to a live mount is
/// unaffected. `after_step` is a test hook, called inside the transaction
/// after each step.
fn migrate(
    conn: &Connection,
    schema: &OpaqueSchema,
    after_step: &dyn Fn(i64),
) -> rusqlite::Result<()> {
    if user_version(conn)? >= SCHEMA_VERSION {
        return Ok(());
    }
    // Nested inside a caller's transaction a SAVEPOINT is the only option; on
    // its own, BEGIN IMMEDIATE takes the write lock before the version is read.
    let nested = !conn.is_autocommit();
    conn.execute_batch(if nested {
        "SAVEPOINT teagarden_migrate"
    } else {
        "BEGIN IMMEDIATE"
    })?;
    let run = || -> rusqlite::Result<()> {
        let from = user_version(conn)?;
        if from < 1 {
            drop_legacy_tables(conn, schema)?;
            after_step(1);
        }
        if from < SCHEMA_VERSION {
            conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))?;
        }
        Ok(())
    };
    match run() {
        Ok(()) => conn.execute_batch(if nested {
            "RELEASE teagarden_migrate"
        } else {
            "COMMIT"
        }),
        Err(e) => {
            let _ = conn.execute_batch(if nested {
                "ROLLBACK TO teagarden_migrate; RELEASE teagarden_migrate"
            } else {
                "ROLLBACK"
            });
            Err(e)
        }
    }
}

/// Step 0 → 1: drop the legacy table.
///
/// Earlier builds created one more table, for a feature removed before 1.0.0.
/// No released build reads or writes it, and its rows were sealed under a
/// subkey the hierarchy no longer derives, so its contents are unreachable.
///
/// Its on-disk name is a keyed hash of a logical name that is no longer in
/// [`crate::schema::logical_tables`], so it is found by elimination and shape
/// instead: an opaque `t_` table that is not one of the current tables, whose
/// columns match [`is_legacy_table_shape`]. No current table has that shape
/// (tested), so this can never drop a table that holds live data, even if the
/// schema key were wrong. Unknown tables of any other shape are left alone.
fn drop_legacy_tables(conn: &Connection, schema: &OpaqueSchema) -> rusqlite::Result<()> {
    for t in legacy_tables(conn, schema)? {
        conn.execute_batch(&format!("DROP TABLE IF EXISTS {t}"))?;
    }
    Ok(())
}

/// `t_` followed by 16 lowercase hex digits (or `c_` for a column): the form
/// every opaque name has. Anything else is not ours and is never touched.
fn is_opaque_name(name: &str, prefix: &str) -> bool {
    name.len() == 18
        && name.starts_with(prefix)
        && name[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Opaque tables in `conn` that are not current logical tables and have the
/// legacy table's shape.
pub(crate) fn legacy_tables(
    conn: &Connection,
    schema: &OpaqueSchema,
) -> rusqlite::Result<Vec<String>> {
    let mut known = std::collections::HashSet::new();
    for td in crate::schema::logical_tables() {
        known.insert(schema.require_table(&td.name)?.to_string());
    }
    let mut st = conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table'")?;
    let names: Vec<String> = st
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let mut out = Vec::new();
    for name in names {
        if is_opaque_name(&name, "t_")
            && !known.contains(&name)
            && is_legacy_table_shape(conn, &name)?
        {
            out.push(name);
        }
    }
    Ok(out)
}

/// The legacy table was created by earlier builds as
///
/// ```sql
/// CREATE TABLE IF NOT EXISTS t_<hex> (
///     c_<hex> TEXT PRIMARY KEY,
///     c_<hex> BLOB NOT NULL,
///     c_<hex> INTEGER NOT NULL DEFAULT 0,
///     c_<hex> INTEGER
/// );
/// ```
///
/// with no index other than its primary key's. This checks exactly that.
/// The lineage stamp's table (see `local_db::DbStamp`). Deliberately without
/// a PRIMARY KEY: the SQLite session extension ignores such a table, so a
/// stamp is never part of a journal entry and a replayed journal never
/// changes it. Added in 1.0.0; a DB from an earlier build gets it on its next
/// read-write open (empty: unstamped).
pub(crate) fn create_lineage_table(
    conn: &Connection,
    schema: &OpaqueSchema,
) -> rusqlite::Result<()> {
    let t = schema.require_table("lineage")?;
    let c_vid = schema.require_column("lineage", "volume_id")?;
    let c_ver = schema.require_column("lineage", "version")?;
    let c_nonce = schema.require_column("lineage", "nonce")?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {t} (
            {c_vid} TEXT NOT NULL,
            {c_ver} INTEGER NOT NULL,
            {c_nonce} BLOB NOT NULL
        );"
    ))
}

/// The session record's table (see `local_db::SessionRecord`): the nonce of
/// the session that last opened the DB, and the journal position (HEAD seq)
/// the DB holds. Without a PRIMARY KEY, like the lineage table, so it is
/// never part of a journal entry. Added additively (`CREATE TABLE IF NOT
/// EXISTS`, no `user_version` step): an earlier build ignores it, and a DB
/// written by an earlier build has no row, which `local_db` reads as "no
/// record" (no position to compare), never as a mismatch.
pub(crate) fn create_session_table(
    conn: &Connection,
    schema: &OpaqueSchema,
) -> rusqlite::Result<()> {
    let t = schema.require_table("db_session")?;
    let c = |n| schema.require_column("db_session", n);
    let (c_nonce, c_seq) = (c("nonce")?, c("seq")?);
    let replaced = [
        (c("replaced_volume_id")?, "TEXT"),
        (c("replaced_version")?, "INTEGER"),
        (c("replaced_nonce")?, "BLOB"),
        (c("replaced_seq")?, "INTEGER"),
    ];
    // A new table gets every column at once: concurrent first openers then
    // never race to add one.
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {t} (
            {c_nonce} BLOB,
            {c_seq} INTEGER NOT NULL,
            {} {}, {} {}, {} {}, {} {}
        );",
        replaced[0].0,
        replaced[0].1,
        replaced[1].0,
        replaced[1].1,
        replaced[2].0,
        replaced[2].1,
        replaced[3].0,
        replaced[3].1
    ))?;
    // The stamp and position a publish's restamp replaced (round 13 of
    // 1.0.0): added, all nullable, to a table created without them. Another
    // opener may add one first; that is not an error.
    let have: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info(?1)")?
        .query_map([&t], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    for (col, ty) in replaced {
        if have.iter().any(|h| h == col) {
            continue;
        }
        match conn.execute_batch(&format!("ALTER TABLE {t} ADD COLUMN {col} {ty};")) {
            Err(rusqlite::Error::SqliteFailure(_, Some(m))) if m.contains("duplicate column") => {}
            other => other?,
        }
    }
    Ok(())
}

pub(crate) fn is_legacy_table_shape(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    // (type, notnull, default, pk) per column, in order.
    const SHAPE: [(&str, i64, Option<&str>, i64); 4] = [
        ("TEXT", 0, None, 1),
        ("BLOB", 1, None, 0),
        ("INTEGER", 1, Some("0"), 0),
        ("INTEGER", 0, None, 0),
    ];
    let mut st =
        conn.prepare("SELECT name, type, \"notnull\", dflt_value, pk FROM pragma_table_info(?1)")?;
    let cols: Vec<(String, String, i64, Option<String>, i64)> = st
        .query_map([table], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    if cols.len() != SHAPE.len() {
        return Ok(false);
    }
    for ((name, ty, notnull, dflt, pk), (sty, snn, sdf, spk)) in cols.iter().zip(SHAPE.iter()) {
        if !is_opaque_name(name, "c_")
            || ty != sty
            || notnull != snn
            || dflt.as_deref() != *sdf
            || pk != spk
        {
            return Ok(false);
        }
    }
    let mut st = conn.prepare("SELECT origin FROM pragma_index_list(?1)")?;
    let origins: Vec<String> = st
        .query_map([table], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(origins.iter().all(|o| o == "pk"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::opaque_schema::OpaqueSchema;
    use crate::schema::logical_tables;
    use teagarden_core::crypto::keys::SymmetricKey;

    fn test_schema() -> OpaqueSchema {
        let key = SymmetricKey::from_bytes([0x42; 32]);
        OpaqueSchema::new(key, &logical_tables())
    }

    #[test]
    fn initialize_creates_all_tables() {
        let conn = Connection::open_in_memory().unwrap();
        let schema = test_schema();
        initialize_database(&conn, &schema).unwrap();

        // Verify tables exist by querying sqlite_master
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, logical_tables().len() as i64);
    }

    #[test]
    fn table_names_are_opaque() {
        let conn = Connection::open_in_memory().unwrap();
        let schema = test_schema();
        initialize_database(&conn, &schema).unwrap();

        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            )
            .unwrap();
        let names: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        for name in &names {
            assert!(
                name.starts_with("t_"),
                "table name should be opaque: {name}"
            );
            assert!(
                !name.contains("inode"),
                "table name should not contain logical name: {name}"
            );
            assert!(
                !name.contains("block"),
                "table name should not contain logical name: {name}"
            );
        }
    }

    #[test]
    fn column_names_are_opaque() {
        let conn = Connection::open_in_memory().unwrap();
        let schema = test_schema();
        initialize_database(&conn, &schema).unwrap();

        let inodes_table = schema.table("inodes").unwrap();
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({inodes_table})"))
            .unwrap();
        let col_names: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        for col in &col_names {
            assert!(col.starts_with("c_"), "column name should be opaque: {col}");
        }
    }

    #[test]
    fn idempotent_initialization() {
        let conn = Connection::open_in_memory().unwrap();
        let schema = test_schema();
        initialize_database(&conn, &schema).unwrap();
        // Second call should not fail
        initialize_database(&conn, &schema).unwrap();
    }

    // ---- Schema version 1: the unused legacy table is dropped (forward-only) ----

    use rusqlite::types::Value;

    /// A metadata DB written by the code at 9a3a97a (schema key `[0x42; 32]`,
    /// meta key `[0x43; 32]`), before this migration existed: `user_version` 0,
    /// all 13 tables of that schema, one row in every table (two inodes, written
    /// through `InodeStore`), and a 48-byte row in the legacy table.
    /// sha256 1bd5ca60af71af04f5cef4c56ba008a49a0051b22a45fac7fb4d6a92d5e94303.
    pub(crate) const PRE_MIGRATION_DB: &[u8] =
        include_bytes!("../tests/fixtures/pre_migration_metadata.db");
    /// The opaque name the legacy table has in [`PRE_MIGRATION_DB`].
    pub(crate) const FIXTURE_LEGACY_TABLE: &str = "t_9e4b3912b731994e";

    fn user_version(conn: &Connection) -> i64 {
        conn.query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap()
    }

    fn opaque_tables(conn: &Connection) -> Vec<String> {
        let mut st = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 't\\_%' ESCAPE '\\' ORDER BY name")
            .unwrap();
        st.query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    /// Every row of every CURRENT logical table, in a stable order.
    fn dump_current_tables(
        conn: &Connection,
        schema: &OpaqueSchema,
    ) -> Vec<(String, Vec<Vec<Value>>)> {
        logical_tables()
            .iter()
            // The fixture predates the `lineage` and `db_session` tables
            // (1.0.0); a migrated DB has them empty (unstamped, no session
            // record), which `local_db` tests cover.
            .filter(|td| {
                td.name != "lineage"
                    && td.name != "db_session"
                    && td.name != "sdo_versions"
                    && td.name != "sdo_identities"
                    && td.name != "sdo_clock"
                    && td.name != "sdo_poll_cursor"
                    && td.name != "sdo_pending_writes"
                    && td.name != "sdo_pending_chunks"
            })
            .map(|td| {
                let t = schema.require_table(&td.name).unwrap();
                let mut st = conn
                    .prepare(&format!("SELECT * FROM {t} ORDER BY 1, 2"))
                    .unwrap();
                let n = st.column_count();
                let rows = st
                    .query_map([], |r| (0..n).map(|i| r.get::<_, Value>(i)).collect())
                    .unwrap()
                    .map(Result::unwrap)
                    .collect();
                (td.name.clone(), rows)
            })
            .collect()
    }

    fn fixture_copy(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let p = dir.path().join("metadata.db");
        std::fs::write(&p, PRE_MIGRATION_DB).unwrap();
        p
    }

    #[test]
    fn fresh_database_is_at_the_current_version_without_the_legacy_table() {
        let dir = tempfile::tempdir().unwrap();
        let conn = Connection::open(dir.path().join("fresh.db")).unwrap();
        initialize_database(&conn, &test_schema()).unwrap();
        assert_eq!(user_version(&conn), SCHEMA_VERSION);
        assert_eq!(SCHEMA_VERSION, 1);
        let tables = opaque_tables(&conn);
        assert_eq!(tables.len(), logical_tables().len(), "{tables:?}");
        assert!(!tables.iter().any(|t| t == FIXTURE_LEGACY_TABLE));
        // Every table of a fresh DB is a current logical table.
        let schema = test_schema();
        let mut known: Vec<String> = logical_tables()
            .iter()
            .map(|td| schema.require_table(&td.name).unwrap().to_string())
            .collect();
        known.sort();
        assert_eq!(tables, known);
    }

    #[test]
    fn pre_migration_db_opens_with_the_legacy_table_dropped_and_all_rows_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture_copy(&dir);
        let schema = test_schema();

        // State as the old build left it.
        let before = {
            let c = Connection::open(&path).unwrap();
            assert_eq!(user_version(&c), 0);
            let tables = opaque_tables(&c);
            assert_eq!(tables.len(), 13);
            assert!(tables.iter().any(|t| t == FIXTURE_LEGACY_TABLE));
            let legacy_rows: i64 = c
                .query_row(
                    &format!("SELECT COUNT(*) FROM {FIXTURE_LEGACY_TABLE}"),
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(legacy_rows, 1);
            dump_current_tables(&c, &schema)
        };
        for (name, rows) in &before {
            assert!(!rows.is_empty(), "fixture table {name} has no row");
        }

        // Open with the current code.
        let conn = Connection::open(&path).unwrap();
        initialize_database(&conn, &schema).unwrap();

        assert_eq!(user_version(&conn), SCHEMA_VERSION);
        let tables = opaque_tables(&conn);
        assert_eq!(tables.len(), logical_tables().len(), "{tables:?}");
        assert!(!tables.iter().any(|t| t == FIXTURE_LEGACY_TABLE));
        assert_eq!(dump_current_tables(&conn, &schema), before);
        let ok: String = conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ok, "ok");

        // The rows are still readable through the real store API.
        let mk = SymmetricKey::from_bytes([0x43; 32]);
        let inodes = crate::inode_store::InodeStore::new(&conn, &schema, &mk);
        assert!(inodes.get(1).unwrap().is_some());
        assert_eq!(inodes.lookup(1, "kept.txt").unwrap().unwrap().ino, 2);

        // And it persists: a later open sees the migrated DB, and is a no-op.
        drop(conn);
        let conn = Connection::open(&path).unwrap();
        assert_eq!(user_version(&conn), SCHEMA_VERSION);
        initialize_database(&conn, &schema).unwrap();
        assert_eq!(opaque_tables(&conn).len(), logical_tables().len());
        assert_eq!(dump_current_tables(&conn, &schema), before);
    }

    #[test]
    fn the_legacy_shape_matches_no_current_table_and_does_match_the_fixture() {
        // The safety argument for dropping by shape: no table that holds live
        // data can ever be dropped, whatever key the opaque names came from.
        let schema = test_schema();
        let conn = Connection::open_in_memory().unwrap();
        initialize_database(&conn, &schema).unwrap();
        for td in logical_tables() {
            let t = schema.require_table(&td.name).unwrap();
            assert!(
                !is_legacy_table_shape(&conn, t).unwrap(),
                "current table {} has the legacy shape",
                td.name
            );
        }
        let dir = tempfile::tempdir().unwrap();
        let old = Connection::open(fixture_copy(&dir)).unwrap();
        assert!(is_legacy_table_shape(&old, FIXTURE_LEGACY_TABLE).unwrap());
        assert_eq!(
            legacy_tables(&old, &schema).unwrap(),
            vec![FIXTURE_LEGACY_TABLE]
        );
    }

    #[test]
    fn unrecognised_tables_are_left_alone() {
        let schema = test_schema();
        let dir = tempfile::tempdir().unwrap();
        let path = fixture_copy(&dir);
        {
            let c = Connection::open(&path).unwrap();
            // Opaque-looking but a different shape; and the legacy shape under a
            // name that is not an opaque name.
            c.execute_batch(
                "CREATE TABLE t_00112233445566aa (c_0011223344556677 TEXT PRIMARY KEY, \
                     c_0011223344556688 BLOB NOT NULL);
                 CREATE TABLE someone_elses (c_0011223344556677 TEXT PRIMARY KEY, \
                     c_0011223344556688 BLOB NOT NULL, \
                     c_0011223344556699 INTEGER NOT NULL DEFAULT 0, c_00112233445566ff INTEGER);",
            )
            .unwrap();
        }
        let conn = Connection::open(&path).unwrap();
        initialize_database(&conn, &schema).unwrap();
        let names: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table'")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(names.iter().any(|n| n == "t_00112233445566aa"));
        assert!(names.iter().any(|n| n == "someone_elses"));
        assert!(!names.iter().any(|n| n == FIXTURE_LEGACY_TABLE));
    }

    #[test]
    fn a_newer_schema_version_is_opened_untouched() {
        let schema = test_schema();
        let dir = tempfile::tempdir().unwrap();
        let path = fixture_copy(&dir);
        Connection::open(&path)
            .unwrap()
            .execute_batch("PRAGMA user_version = 5")
            .unwrap();
        let conn = Connection::open(&path).unwrap();
        initialize_database(&conn, &schema).unwrap();
        assert_eq!(user_version(&conn), 5, "a version must never be lowered");
        assert!(opaque_tables(&conn)
            .iter()
            .any(|t| t == FIXTURE_LEGACY_TABLE));
    }

    #[test]
    fn migration_inside_a_caller_transaction_uses_a_savepoint() {
        let schema = test_schema();
        let dir = tempfile::tempdir().unwrap();
        let conn = Connection::open(fixture_copy(&dir)).unwrap();
        // Already in WAL mode, as every DB in the field is: switching INTO WAL
        // mode inside a transaction is refused by SQLite itself.
        conn.execute_batch("PRAGMA journal_mode=WAL").unwrap();
        conn.execute_batch("BEGIN").unwrap();
        initialize_database(&conn, &schema).unwrap();
        assert!(
            !conn.is_autocommit(),
            "the caller's transaction is still open"
        );
        conn.execute_batch("ROLLBACK").unwrap();
        // Rolled back with the caller's transaction: still the old state.
        assert_eq!(user_version(&conn), 0);
        assert!(opaque_tables(&conn)
            .iter()
            .any(|t| t == FIXTURE_LEGACY_TABLE));
        initialize_database(&conn, &schema).unwrap();
        assert_eq!(user_version(&conn), SCHEMA_VERSION);
        assert!(!opaque_tables(&conn)
            .iter()
            .any(|t| t == FIXTURE_LEGACY_TABLE));
    }

    const DIE_ENV: &str = "TEAGARDEN_TEST_MIGRATE_AND_DIE";

    /// A real killed writer: a child process runs the migration and aborts
    /// INSIDE the transaction, after the DROP and before the version bump and
    /// COMMIT. The DB must be exactly the old one, and the next open migrates it.
    #[test]
    fn killed_mid_migration_leaves_the_old_state_and_the_next_open_finishes() {
        if let Ok(p) = std::env::var(DIE_ENV) {
            let schema = test_schema();
            let conn = Connection::open(&p).unwrap();
            create_tables(&conn, &schema).unwrap();
            let r = migrate(&conn, &schema, &|step| {
                let gone = !opaque_tables(&conn)
                    .iter()
                    .any(|t| t == FIXTURE_LEGACY_TABLE);
                eprintln!("child: step {step} done inside the transaction, legacy table gone={gone}; aborting before COMMIT");
                std::process::abort();
            });
            panic!("child: the hook did not abort the process (migrate returned {r:?})");
        }

        let dir = tempfile::tempdir().unwrap();
        let path = fixture_copy(&dir);
        let schema = test_schema();
        let before = dump_current_tables(&Connection::open(&path).unwrap(), &schema);

        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "migrations::tests::killed_mid_migration_leaves_the_old_state_and_the_next_open_finishes",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(DIE_ENV, &path)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        eprintln!("parent: child exit status {:?}", out.status);
        eprintln!(
            "parent: child stderr: {}",
            stderr
                .lines()
                .find(|l| l.starts_with("child:"))
                .unwrap_or("<none>")
        );
        assert!(!out.status.success());
        assert!(
            stderr.contains("legacy table gone=true; aborting before COMMIT"),
            "{stderr}"
        );

        // Interrupted state is the old state, and is distinguishable by version.
        {
            let c = Connection::open(&path).unwrap();
            assert_eq!(user_version(&c), 0);
            assert!(opaque_tables(&c).iter().any(|t| t == FIXTURE_LEGACY_TABLE));
            let ok: String = c
                .query_row("PRAGMA integrity_check", [], |r| r.get(0))
                .unwrap();
            assert_eq!(ok, "ok");
            assert_eq!(dump_current_tables(&c, &schema), before);
            eprintln!("parent: after kill: user_version=0, legacy table present, integrity ok");
        }
        // Resume.
        let conn = Connection::open(&path).unwrap();
        initialize_database(&conn, &schema).unwrap();
        assert_eq!(user_version(&conn), SCHEMA_VERSION);
        assert!(!opaque_tables(&conn)
            .iter()
            .any(|t| t == FIXTURE_LEGACY_TABLE));
        assert_eq!(dump_current_tables(&conn, &schema), before);
        eprintln!(
            "parent: resumed open: user_version={}, tables={}",
            user_version(&conn),
            opaque_tables(&conn).len()
        );
    }

    /// Several connections (one per thread, as separate processes would have)
    /// open the same old DB at the same moment. Each must succeed, and the
    /// migration step must run exactly once. (The killed-writer test above is
    /// the cross-process one.)
    #[test]
    fn concurrent_first_opens_migrate_exactly_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Barrier};
        const OPENERS: usize = 4;
        for round in 0..50 {
            let dir = tempfile::tempdir().unwrap();
            let path = fixture_copy(&dir);
            // Every DB in the field is already in WAL mode (`create_tables` has
            // always set it, and it persists in the file). Switching a DB into
            // WAL mode is not what is under test here.
            let mode: String = Connection::open(&path)
                .unwrap()
                .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
                .unwrap();
            assert_eq!(mode, "wal");
            let steps = Arc::new(AtomicUsize::new(0));
            let barrier = Arc::new(Barrier::new(OPENERS));
            let handles: Vec<_> = (0..OPENERS)
                .map(|_| {
                    let (path, steps, barrier) = (path.clone(), steps.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        let schema = test_schema();
                        let conn = Connection::open(&path).unwrap();
                        barrier.wait();
                        create_tables(&conn, &schema).map_err(|e| format!("create_tables: {e}"))?;
                        migrate(&conn, &schema, &|_| {
                            steps.fetch_add(1, Ordering::SeqCst);
                        })
                        .map_err(|e| format!("migrate: {e}"))
                    })
                })
                .collect();
            for h in handles {
                h.join()
                    .unwrap()
                    .unwrap_or_else(|e| panic!("round {round}: {e}"));
            }
            assert_eq!(steps.load(Ordering::SeqCst), 1, "round {round}");
            let conn = Connection::open(&path).unwrap();
            assert_eq!(user_version(&conn), SCHEMA_VERSION);
            assert_eq!(opaque_tables(&conn).len(), logical_tables().len());
        }
    }
}
