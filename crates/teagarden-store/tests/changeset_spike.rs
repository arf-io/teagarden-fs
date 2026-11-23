//! GATE SPIKE for the v0.4.3 metadata journal: confirm rusqlite's `session`
//! feature compiles in the bundled build and that a changeset round-trips
//! (capture raw bytes on one DB, apply to a copy, assert equality). Also pins
//! the silent-omission trap: a PK-less table's changes are NOT captured — the
//! reason `path_policies` must gain a PRIMARY KEY before it is wired to writes.
//!
//! This mirrors exactly what the journal will do: `changeset_strm` → encrypt →
//! publish as a delta; on recovery, decrypt → `apply_strm` over a fresh DB.

use rusqlite::session::{ConflictAction, Session};
use rusqlite::Connection;

fn open() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(
        "CREATE TABLE inodes (ino INTEGER PRIMARY KEY, data BLOB NOT NULL);
         CREATE TABLE no_pk (pattern BLOB NOT NULL, val INTEGER NOT NULL);",
    )
    .unwrap();
    c
}

#[test]
fn changeset_round_trips_on_pk_table() {
    let src = open();

    // Attach a session over the whole DB, then mutate.
    let mut session = Session::new(&src).unwrap();
    session.attach(None::<&str>).unwrap();
    src.execute(
        "INSERT INTO inodes (ino, data) VALUES (1, ?1)",
        [b"hello".as_slice()],
    )
    .unwrap();
    src.execute(
        "INSERT INTO inodes (ino, data) VALUES (2, ?1)",
        [b"world".as_slice()],
    )
    .unwrap();
    src.execute(
        "UPDATE inodes SET data = ?1 WHERE ino = 1",
        [b"HELLO".as_slice()],
    )
    .unwrap();

    // Capture raw changeset bytes — this is what the journal encrypts + publishes.
    let mut bytes = Vec::new();
    session.changeset_strm(&mut bytes).unwrap();
    assert!(!bytes.is_empty(), "changeset bytes must be non-empty");

    // Apply to a fresh copy via apply_strm — what recovery does after decrypt.
    let dst = open();
    dst.apply_strm(
        &mut &bytes[..],
        None::<fn(&str) -> bool>,
        |_conflict_type, _item| ConflictAction::SQLITE_CHANGESET_ABORT,
    )
    .unwrap();

    let d1: Vec<u8> = dst
        .query_row("SELECT data FROM inodes WHERE ino = 1", [], |r| r.get(0))
        .unwrap();
    let d2: Vec<u8> = dst
        .query_row("SELECT data FROM inodes WHERE ino = 2", [], |r| r.get(0))
        .unwrap();
    assert_eq!(d1, b"HELLO");
    assert_eq!(d2, b"world");
}

#[test]
fn pk_less_table_is_silently_omitted() {
    // The trap: sqlite3session_attach records changes ONLY for tables with a PK.
    // A change to a PK-less table is silently absent from the changeset — which is
    // why every write-path table (incl. path_policies) must have a PRIMARY KEY.
    let src = open();
    let mut session = Session::new(&src).unwrap();
    session.attach(None::<&str>).unwrap();
    src.execute(
        "INSERT INTO no_pk (pattern, val) VALUES (?1, 5)",
        [b"p".as_slice()],
    )
    .unwrap();

    let mut bytes = Vec::new();
    session.changeset_strm(&mut bytes).unwrap();
    assert!(
        bytes.is_empty(),
        "PK-less table change must NOT appear in the changeset (v0.4.3 PK gate)"
    );
}

#[test]
fn changeset_captures_mid_transaction_on_opaque_schema() {
    // The journal pulls the changeset INSIDE an explicit transaction, BEFORE
    // COMMIT, against the real obscured tables — confirm both here (the earlier
    // spikes captured post-autocommit on plain tables).
    use rusqlite::params;
    use teagarden_core::crypto::keys::SymmetricKey;
    use teagarden_store::migrations::initialize_database;
    use teagarden_store::opaque_schema::OpaqueSchema;
    use teagarden_store::schema::logical_tables;

    let key = SymmetricKey::from_bytes([0x42; 32]);
    let mk_db = || {
        let c = Connection::open_in_memory().unwrap();
        let schema = OpaqueSchema::new(key.clone(), &logical_tables());
        initialize_database(&c, &schema).unwrap();
        (c, schema)
    };

    let (src, schema) = mk_db();
    let t = schema.require_table("inodes").unwrap();
    let c_ino = schema.require_column("inodes", "ino").unwrap();
    let c_parent = schema.require_column("inodes", "parent").unwrap();
    let c_nh = schema.require_column("inodes", "name_hash").unwrap();
    let c_data = schema.require_column("inodes", "data").unwrap();

    let mut session = Session::new(&src).unwrap();
    session.attach(None::<&str>).unwrap();

    // Mutate INSIDE an explicit transaction; capture BEFORE COMMIT.
    src.execute_batch("BEGIN IMMEDIATE").unwrap();
    src.execute(
        &format!("INSERT INTO {t} ({c_ino},{c_parent},{c_nh},{c_data}) VALUES (?1,?2,?3,?4)"),
        params![42i64, 1i64, b"nh".as_slice(), b"inode-blob".as_slice()],
    )
    .unwrap();

    let mut bytes = Vec::new();
    session.changeset_strm(&mut bytes).unwrap();
    assert!(
        !bytes.is_empty(),
        "changeset must reflect uncommitted writes captured mid-transaction"
    );

    src.execute_batch("COMMIT").unwrap();

    // Replay into a fresh, independently-initialized opaque DB → the row appears.
    let (dst, schema2) = mk_db();
    let t2 = schema2.require_table("inodes").unwrap();
    dst.apply_strm(&mut &bytes[..], None::<fn(&str) -> bool>, |_ct, _item| {
        ConflictAction::SQLITE_CHANGESET_ABORT
    })
    .unwrap();
    let n: i64 = dst
        .query_row(&format!("SELECT COUNT(*) FROM {t2}"), [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1, "replayed changeset must materialize the inode row");
}
