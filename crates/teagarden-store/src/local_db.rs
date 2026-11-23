//! Opening a volume's local metadata DB without ever creating one, and deciding
//! whether it must be rebuilt from Telegram before anything may use it.
//!
//! `rusqlite::Connection::open` creates a missing database file. For a volume
//! that has published a snapshot, a missing DB means "lost, rebuild it", and a
//! freshly created one is an EMPTY filesystem that a later unmount would
//! publish over the real one. So every opener of an existing volume's DB goes
//! through [`open_existing`] or [`open_read_only`] (no `SQLITE_OPEN_CREATE`) and
//! first asks [`local_db_state`] whether the DB is usable: for a volume with a
//! published snapshot, only when it carries the lineage stamp ([`DbStamp`])
//! the journal HEAD records. Only the first mount of a volume without a
//! published snapshot ([`manager::has_published_snapshot`]) creates the file
//! ([`create_db_atomically`]).

use std::path::Path;

use rusqlite::{Connection, OpenFlags};

use teagarden_core::crypto::keys::SymmetricKey;
use teagarden_core::error::CoreError;
use teagarden_core::volume::config::VolumeConfig;
use teagarden_core::volume::journal_head::{JournalHead, Lineage};
use teagarden_core::volume::{manager, rebuild_marker};

use crate::opaque_schema::OpaqueSchema;

/// Open an existing DB read-write. Fails (SQLITE_CANTOPEN) when the file does
/// not exist; never creates it.
pub fn open_existing(db_path: &Path) -> rusqlite::Result<Connection> {
    Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
}

/// Open an existing DB read-only. Fails when the file does not exist.
pub fn open_read_only(db_path: &Path) -> rusqlite::Result<Connection> {
    Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
}

/// `Ok(true)` when the DB file does not exist or is zero-length. Any other
/// failure to check it (permissions, a path component that is not a
/// directory, I/O) is an error: it is neither "absent" (a new volume, or a lost
/// DB to rebuild) nor a usable file.
pub fn db_file_absent(db_path: &Path) -> std::io::Result<bool> {
    match std::fs::metadata(db_path) {
        Ok(m) => Ok(m.len() == 0),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e),
    }
}

fn check_absent(db_path: &Path) -> Result<bool, CoreError> {
    db_file_absent(db_path).map_err(|e| {
        CoreError::Volume(format!(
            "check the local metadata database {}: {e}",
            db_path.display()
        ))
    })
}

/// How much of a filesystem tree a metadata DB holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeSummary {
    /// Whether the root directory's inode (ino 1) exists.
    pub has_root: bool,
    /// Inodes other than the root (files, directories, symlinks).
    pub entries: u64,
}

impl TreeSummary {
    /// The summary of a DB with no inodes at all.
    pub const NOTHING: TreeSummary = TreeSummary {
        has_root: false,
        entries: 0,
    };

    /// No file, directory or symlink below the root (the root itself may or may
    /// not exist).
    pub fn is_empty(&self) -> bool {
        self.entries == 0
    }
}

/// Count the inodes in `conn`. A DB without the inodes table (no schema yet)
/// holds nothing. Reads only clear columns; nothing is decrypted.
pub fn tree_summary(conn: &Connection, schema: &OpaqueSchema) -> rusqlite::Result<TreeSummary> {
    let t = schema.require_table("inodes")?;
    let c_ino = schema.require_column("inodes", "ino")?;
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [t],
        |r| r.get(0),
    )?;
    if !exists {
        return Ok(TreeSummary::NOTHING);
    }
    let (has_root, entries): (bool, i64) = conn.query_row(
        &format!(
            "SELECT EXISTS(SELECT 1 FROM {t} WHERE {c_ino} = 1), \
                    (SELECT COUNT(*) FROM {t} WHERE {c_ino} != 1)"
        ),
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(TreeSummary {
        has_root,
        entries: entries.max(0) as u64,
    })
}

/// [`tree_summary`] of the DB file at `db_path`, opened read-only.
/// [`TreeSummary::NOTHING`] when the file is absent; an error when it cannot be
/// checked or read.
pub fn tree_summary_of(db_path: &Path, schema: &OpaqueSchema) -> Result<TreeSummary, CoreError> {
    if check_absent(db_path)? {
        return Ok(TreeSummary::NOTHING);
    }
    open_read_only(db_path)
        .and_then(|c| tree_summary(&c, schema))
        .map_err(|e| {
            CoreError::Volume(format!(
                "read the local metadata database {}: {e}",
                db_path.display()
            ))
        })
}

/// The lineage stamp of a local metadata DB: which volume it belongs to and
/// which state of that volume's metadata it holds ([`Lineage`]: a snapshot
/// version and a random nonce). Kept in the DB's `lineage` table, which has no
/// PRIMARY KEY, so the SQLite session extension never records it: it is never
/// in a journal entry, and replaying entries never changes it. A snapshot
/// carries the stamp the DB had when it was snapshotted.
///
/// The stamp detects accidents (an older copy of the DB put back, another
/// volume's DB, a DB some other build created); it is not a defence against a
/// local writer, who can read the HEAD's lineage and write it into any DB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbStamp {
    /// The volume's id (its directory name).
    pub volume_id: String,
    /// The snapshot version and nonce.
    pub lineage: Lineage,
}

/// The DB's stamp: `None` when it has none (a DB written before stamps
/// existed, or created by something else than this build), or when its
/// `lineage` table does not hold exactly one row.
pub fn read_stamp(conn: &Connection, schema: &OpaqueSchema) -> rusqlite::Result<Option<DbStamp>> {
    let t = schema.require_table("lineage")?;
    let c_vid = schema.require_column("lineage", "volume_id")?;
    let c_ver = schema.require_column("lineage", "version")?;
    let c_nonce = schema.require_column("lineage", "nonce")?;
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [t],
        |r| r.get(0),
    )?;
    if !exists {
        return Ok(None);
    }
    let mut st = conn.prepare(&format!(
        "SELECT {c_vid}, {c_ver}, {c_nonce} FROM {t} LIMIT 2"
    ))?;
    let rows: Vec<(String, i64, Vec<u8>)> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let [(volume_id, version, nonce)] = rows.as_slice() else {
        return Ok(None);
    };
    let (Ok(nonce), Ok(version)) = (
        <[u8; 16]>::try_from(nonce.as_slice()),
        u64::try_from(*version),
    ) else {
        return Ok(None);
    };
    Ok(Some(DbStamp {
        volume_id: volume_id.clone(),
        lineage: Lineage { version, nonce },
    }))
}

/// Replace the DB's stamp with `stamp` (or remove it, `None`), in one
/// transaction.
pub fn write_stamp(
    conn: &Connection,
    schema: &OpaqueSchema,
    stamp: Option<&DbStamp>,
) -> rusqlite::Result<()> {
    crate::migrations::create_lineage_table(conn, schema)?;
    let tx = conn.unchecked_transaction()?;
    write_stamp_rows(&tx, schema, stamp)?;
    tx.commit()
}

/// [`write_stamp`]'s rows, inside the caller's transaction.
fn write_stamp_rows(
    conn: &Connection,
    schema: &OpaqueSchema,
    stamp: Option<&DbStamp>,
) -> rusqlite::Result<()> {
    let t = schema.require_table("lineage")?;
    let c_vid = schema.require_column("lineage", "volume_id")?;
    let c_ver = schema.require_column("lineage", "version")?;
    let c_nonce = schema.require_column("lineage", "nonce")?;
    conn.execute(&format!("DELETE FROM {t}"), [])?;
    if let Some(s) = stamp {
        let version = i64::try_from(s.lineage.version)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.execute(
            &format!("INSERT INTO {t} ({c_vid}, {c_ver}, {c_nonce}) VALUES (?1, ?2, ?3)"),
            rusqlite::params![s.volume_id, version, s.lineage.nonce.to_vec()],
        )?;
    }
    Ok(())
}

/// Which session last opened a local metadata DB, and which journal position
/// it holds: the `db_session` table's one row (no PRIMARY KEY, so, like the
/// stamp, it is never journaled and a replayed journal never changes it).
///
/// A session (a mount, `revert`, `key rotate`) writes a fresh random `nonce`
/// and the HEAD's `seq` when it opens the DB ([`begin_session`]); every
/// journaled transaction writes the seq it produces into the same row in the
/// same transaction ([`set_session_seq`]); a publish resets `seq` to 0 with
/// the new stamp ([`restamp_db_file`]). A publish then proves by content that
/// the file it reads is this session's DB (its nonce) at the HEAD's journal
/// position (its seq). Like the stamp it detects accidents, not a local
/// writer who copies the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRecord {
    /// The nonce of the session that last opened the DB (`None`: the row was
    /// written without one, by a journaled write or a publish on a DB no
    /// session of this build had opened).
    pub nonce: Option<[u8; 16]>,
    /// The journal position (HEAD seq) the DB holds.
    pub seq: u64,
}

/// The DB's session record: `None` when the table or its row is missing (a
/// DB last written by a build before the record existed), or when the table
/// does not hold exactly one row.
pub fn read_session(
    conn: &Connection,
    schema: &OpaqueSchema,
) -> rusqlite::Result<Option<SessionRecord>> {
    let t = schema.require_table("db_session")?;
    let c_nonce = schema.require_column("db_session", "nonce")?;
    let c_seq = schema.require_column("db_session", "seq")?;
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [t],
        |r| r.get(0),
    )?;
    if !exists {
        return Ok(None);
    }
    let mut st = conn.prepare(&format!("SELECT {c_nonce}, {c_seq} FROM {t} LIMIT 2"))?;
    let rows: Vec<(Option<Vec<u8>>, i64)> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let [(nonce, seq)] = rows.as_slice() else {
        return Ok(None);
    };
    let Ok(seq) = u64::try_from(*seq) else {
        return Ok(None);
    };
    Ok(Some(SessionRecord {
        nonce: nonce.as_deref().and_then(|n| <[u8; 16]>::try_from(n).ok()),
        seq,
    }))
}

/// The stamp and journal position the DB carried before a publish's
/// restamp replaced them ([`restamp_db_file`]): `None` when no restamp
/// recorded one. A DB a publish stamped and then did not finish (killed
/// before `journal.head` was reset onto it) carries the state `journal.head`
/// still names under its old stamp, so [`keep_replaced`] finds it
/// reproducible by these.
pub fn replaced_stamp(
    conn: &Connection,
    schema: &OpaqueSchema,
) -> rusqlite::Result<Option<Reproduces>> {
    let t = schema.require_table("db_session")?;
    let cols = [
        "replaced_volume_id",
        "replaced_version",
        "replaced_nonce",
        "replaced_seq",
    ]
    .map(|c| schema.require_column("db_session", c));
    let [Ok(c_vid), Ok(c_ver), Ok(c_nonce), Ok(c_seq)] = cols else {
        return Ok(None);
    };
    let have: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info(?1)")?
        .query_map([t], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    if !have.iter().any(|h| h == c_seq) {
        return Ok(None);
    }
    let mut st = conn.prepare(&format!(
        "SELECT {c_vid}, {c_ver}, {c_nonce}, {c_seq} FROM {t} LIMIT 2"
    ))?;
    type Row = (Option<String>, Option<i64>, Option<Vec<u8>>, Option<i64>);
    let rows: Vec<Row> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let [(Some(volume_id), Some(version), Some(nonce), Some(seq))] = rows.as_slice() else {
        return Ok(None);
    };
    let (Ok(version), Ok(nonce), Ok(seq)) = (
        u64::try_from(*version),
        <[u8; 16]>::try_from(nonce.as_slice()),
        u64::try_from(*seq),
    ) else {
        return Ok(None);
    };
    Ok(Some(Reproduces {
        stamp: DbStamp {
            volume_id: volume_id.clone(),
            lineage: Lineage { version, nonce },
        },
        seq,
    }))
}

fn sql_seq(seq: u64) -> rusqlite::Result<i64> {
    i64::try_from(seq).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
}

/// Start a session on the DB: replace its session record with `nonce` and
/// `seq` (the HEAD's, or 0 without a HEAD), in one transaction. The caller
/// checkpoints afterwards, so the record is in the main file.
pub fn begin_session(
    conn: &Connection,
    schema: &OpaqueSchema,
    nonce: [u8; 16],
    seq: u64,
) -> rusqlite::Result<()> {
    crate::migrations::create_session_table(conn, schema)?;
    let t = schema.require_table("db_session")?;
    let c_nonce = schema.require_column("db_session", "nonce")?;
    let c_seq = schema.require_column("db_session", "seq")?;
    let tx = conn.unchecked_transaction()?;
    tx.execute(&format!("DELETE FROM {t}"), [])?;
    tx.execute(
        &format!("INSERT INTO {t} ({c_nonce}, {c_seq}) VALUES (?1, ?2)"),
        rusqlite::params![nonce.to_vec(), sql_seq(seq)?],
    )?;
    tx.commit()
}

/// Record that the DB now holds journal position `seq`, keeping the session
/// nonce (a row without one is created when there is none). Runs inside the
/// caller's transaction: a journaled transaction calls it with the seq it
/// produces, before its COMMIT. The table is created if a DB written by an
/// earlier build lacks it.
pub fn set_session_seq(conn: &Connection, schema: &OpaqueSchema, seq: u64) -> rusqlite::Result<()> {
    crate::migrations::create_session_table(conn, schema)?;
    let t = schema.require_table("db_session")?;
    let c_nonce = schema.require_column("db_session", "nonce")?;
    let c_seq = schema.require_column("db_session", "seq")?;
    let seq = sql_seq(seq)?;
    if conn.execute(&format!("UPDATE {t} SET {c_seq} = ?1"), [seq])? == 0 {
        conn.execute(
            &format!("INSERT INTO {t} ({c_nonce}, {c_seq}) VALUES (NULL, ?1)"),
            [seq],
        )?;
    }
    Ok(())
}

/// `PRAGMA quick_check` of `conn`: `Ok(None)` when it reports `ok`,
/// `Ok(Some(problems))` otherwise. A database SQLite cannot even walk fails
/// with its error (SQLITE_CORRUPT, SQLITE_NOTADB; see [`is_damage`]).
pub fn quick_check(conn: &Connection) -> rusqlite::Result<Option<String>> {
    let mut st = conn.prepare("PRAGMA quick_check(5)")?;
    let rows: Vec<String> = st
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(if rows.len() == 1 && rows[0] == "ok" {
        None
    } else {
        Some(rows.join("; "))
    })
}

/// Whether SQLite says the file is damaged (SQLITE_NOTADB: not a database;
/// SQLITE_CORRUPT: malformed), as opposed to "cannot be read right now"
/// (permissions, a lock another process holds, I/O): only damage is ever a
/// reason to rebuild over a DB.
pub fn is_damage(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(f, _)
            if matches!(
                f.code,
                rusqlite::ErrorCode::NotADatabase | rusqlite::ErrorCode::DatabaseCorrupt
            )
    )
}

/// What [`probe_db`] found at a DB path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbProbe {
    /// Missing or zero-length.
    Absent,
    /// SQLite reports damage (not a database, malformed, or `PRAGMA
    /// quick_check` is not `ok`); the text says what.
    Damaged(String),
    /// Read, and `PRAGMA quick_check` is `ok`.
    Readable(DbContent),
}

/// What a readable DB holds (only clear columns are read).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbContent {
    /// Root directory and entry count.
    pub tree: TreeSummary,
    /// The lineage stamp.
    pub stamp: Option<DbStamp>,
    /// The session record.
    pub session: Option<SessionRecord>,
    /// What the last publish's restamp replaced ([`replaced_stamp`]).
    pub replaced: Option<Reproduces>,
}

/// The refusal for a DB at `db_path` that exists but cannot be read now.
fn cannot_open_now(db_path: &Path, e: &rusqlite::Error) -> CoreError {
    CoreError::Volume(format!(
        "refusing to go on: the local metadata database {} exists but cannot be opened or \
         read right now ({e}). That is not damage SQLite reports (not a database, or \
         malformed): its permissions may not allow reading it, another program may hold it \
         locked, or the disk may have failed. It was neither used nor replaced. Nothing was \
         changed. Fix the cause (for example `chmod 600` it, or stop the program that has \
         it open), then run the command again",
        db_path.display()
    ))
}

/// Read the DB at `db_path` read-only: absent, damaged, or what it holds. A
/// DB that exists but cannot be opened or read for any reason other than
/// damage SQLite reports ([`is_damage`]) is an error ("cannot be opened
/// right now"), never [`DbProbe::Damaged`].
pub fn probe_db(db_path: &Path, schema: &OpaqueSchema) -> Result<DbProbe, CoreError> {
    if check_absent(db_path)? {
        return Ok(DbProbe::Absent);
    }
    let read = open_read_only(db_path).and_then(|c| {
        if let Some(problems) = quick_check(&c)? {
            return Ok(Err(problems));
        }
        Ok(Ok(DbContent {
            tree: tree_summary(&c, schema)?,
            stamp: read_stamp(&c, schema)?,
            session: read_session(&c, schema)?,
            replaced: replaced_stamp(&c, schema)?,
        }))
    });
    match read {
        Ok(Ok(content)) => Ok(DbProbe::Readable(content)),
        Ok(Err(problems)) => Ok(DbProbe::Damaged(format!(
            "PRAGMA quick_check reports: {problems}"
        ))),
        Err(e) if is_damage(&e) => Ok(DbProbe::Damaged(e.to_string())),
        Err(e) => Err(cannot_open_now(db_path, &e)),
    }
}

/// Replace the DB's stamp with `stamp` and its session record's journal
/// position with `seq` (keeping the nonce; `None` removes the record), in
/// one transaction, and checkpoint it into the main file. Returns the stamp
/// and the position it replaced (to put back with the same call). Never
/// creates the file.
pub fn restamp_db_file(
    db_path: &Path,
    schema: &OpaqueSchema,
    stamp: Option<&DbStamp>,
    seq: Option<u64>,
) -> Result<(Option<DbStamp>, Option<u64>), CoreError> {
    let conn = open_existing(db_path).map_err(|e| file_err("open", db_path, e))?;
    crate::migrations::create_lineage_table(&conn, schema)
        .and_then(|()| crate::migrations::create_session_table(&conn, schema))
        .map_err(|e| file_err("create the stamp tables of", db_path, e))?;
    let previous =
        read_stamp(&conn, schema).map_err(|e| file_err("read the stamp of", db_path, e))?;
    let previous_seq = read_session(&conn, schema)
        .map_err(|e| file_err("read the session record of", db_path, e))?
        .map(|r| r.seq);
    let t = schema
        .require_table("db_session")
        .map_err(|e| file_err("stamp", db_path, e))?;
    let write = || -> rusqlite::Result<()> {
        let tx = conn.unchecked_transaction()?;
        write_stamp_rows(&tx, schema, stamp)?;
        match seq {
            Some(seq) => {
                set_session_seq(&tx, schema, seq)?;
                // What this restamp replaces, in the same transaction.
                let c = |n| schema.require_column("db_session", n);
                let replaced = previous.as_ref().zip(previous_seq);
                tx.execute(
                    &format!(
                        "UPDATE {t} SET {} = ?1, {} = ?2, {} = ?3, {} = ?4",
                        c("replaced_volume_id")?,
                        c("replaced_version")?,
                        c("replaced_nonce")?,
                        c("replaced_seq")?
                    ),
                    rusqlite::params![
                        replaced.map(|(s, _)| s.volume_id.clone()),
                        replaced
                            .map(|(s, _)| sql_seq(s.lineage.version))
                            .transpose()?,
                        replaced.map(|(s, _)| s.lineage.nonce.to_vec()),
                        replaced.map(|(_, q)| sql_seq(q)).transpose()?,
                    ],
                )?;
            }
            None => {
                tx.execute(&format!("DELETE FROM {t}"), [])?;
            }
        }
        tx.commit()
    };
    write().map_err(|e| file_err("stamp", db_path, e))?;
    checkpoint_fully(&conn, db_path)?;
    Ok((previous, previous_seq))
}

/// `db_bytes` (a DB file's bytes, such as a decrypted snapshot) stamped with
/// `stamp` at journal position `seq`: written to `scratch` (removed before
/// and after, sidecars included), restamped there, checkpointed, read back.
/// `volume restore` installs these bytes, so the DB it installs already
/// carries the lineage and position the HEAD records.
pub fn stamp_db_bytes(
    db_bytes: &[u8],
    scratch: &Path,
    schema: &OpaqueSchema,
    stamp: &DbStamp,
    seq: u64,
) -> Result<Vec<u8>, CoreError> {
    use teagarden_core::volume::metadata_snapshot::remove_db_files;
    remove_db_files(scratch)?;
    let out = (|| {
        std::fs::write(scratch, db_bytes).map_err(|e| file_err("write", scratch, e))?;
        restamp_db_file(scratch, schema, Some(stamp), Some(seq))?;
        std::fs::read(scratch).map_err(|e| file_err("read", scratch, e))
    })();
    let removed = remove_db_files(scratch);
    let out = out?;
    removed?;
    Ok(out)
}

fn file_err(what: &str, db_path: &Path, e: impl std::fmt::Display) -> CoreError {
    CoreError::Volume(format!("{what} {}: {e}", db_path.display()))
}

/// Fold the WAL into the main DB file (`PRAGMA wal_checkpoint(TRUNCATE)`) and
/// fail unless every frame was copied: a snapshot reads the file itself.
pub fn checkpoint_fully(conn: &Connection, db_path: &Path) -> Result<(), CoreError> {
    let (busy, log, done): (i64, i64, i64) = conn
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .map_err(|e| file_err("checkpoint", db_path, e))?;
    if busy != 0 || log != done {
        return Err(file_err(
            "checkpoint",
            db_path,
            format!("incomplete (busy {busy}, {done} of {log} WAL frames copied)"),
        ));
    }
    Ok(())
}

/// Write `stamp` into the existing DB file at `db_path` and checkpoint it into
/// the main file (so a snapshot of the file carries it). Returns the stamp it
/// replaced. Never creates the file.
pub fn stamp_db_file(
    db_path: &Path,
    schema: &OpaqueSchema,
    stamp: Option<&DbStamp>,
) -> Result<Option<DbStamp>, CoreError> {
    let conn = open_existing(db_path).map_err(|e| file_err("open", db_path, e))?;
    let previous =
        read_stamp(&conn, schema).map_err(|e| file_err("read the stamp of", db_path, e))?;
    write_stamp(&conn, schema, stamp).map_err(|e| file_err("stamp", db_path, e))?;
    checkpoint_fully(&conn, db_path)?;
    Ok(previous)
}

/// What the volume's own records say its local metadata DB must be, for
/// [`local_db_state`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    /// The volume's id: a stamp naming another volume is not this volume's DB.
    pub volume_id: String,
    /// [`manager::has_published_snapshot`]: there is a snapshot on Telegram to
    /// rebuild the DB from, so the DB is checked against [`Self::lineage`].
    pub published_snapshot: bool,
    /// The lineage the journal HEAD records ([`JournalHead::lineage`]); `None`
    /// without a HEAD, or with a HEAD written before the field existed.
    pub lineage: Option<Lineage>,
    /// Why journal.head could not be read (it does not authenticate, or does
    /// not parse), if it could not: then nothing vouches for any DB.
    pub head_unreadable: Option<String>,
    /// The journal position the HEAD records (its seq); `None` without a
    /// HEAD. A DB whose session record holds another position is not the
    /// volume's current database.
    pub head_seq: Option<u64>,
}

impl Expected {
    /// The expectation for the volume `config` in `base_dir`, reading its
    /// journal HEAD (authenticated with `integrity_key`). A HEAD that cannot
    /// be read is recorded in [`Self::head_unreadable`], not an error: the
    /// openers that do not rebuild then refuse as for any DB that must be
    /// rebuilt, and a mount refuses in its own recovery (naming `volume
    /// restore --discard-journal` and `volume republish --from-local-db`).
    pub fn of_volume(
        config: &VolumeConfig,
        base_dir: &Path,
        integrity_key: &SymmetricKey,
    ) -> Result<Self, CoreError> {
        let (lineage, head_seq, head_unreadable) =
            match JournalHead::load(&base_dir.join(manager::JOURNAL_HEAD_FILE), integrity_key) {
                Ok(head) => (
                    head.as_ref().and_then(|h| h.lineage),
                    head.map(|h| h.seq),
                    None,
                ),
                Err(e) => (None, None, Some(e.to_string())),
            };
        Ok(Expected {
            volume_id: config.volume_id.to_string(),
            published_snapshot: manager::has_published_snapshot(config, base_dir),
            lineage,
            head_unreadable,
            head_seq,
        })
    }

    /// The stamp a DB holding this lineage carries.
    pub fn stamp(&self, lineage: Lineage) -> DbStamp {
        DbStamp {
            volume_id: self.volume_id.clone(),
            lineage,
        }
    }
}

/// What the local metadata DB of a volume can be used for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalDb {
    /// It exists and may be opened.
    Usable,
    /// It does not exist and the volume has no published snapshot: the
    /// (next) first mount creates it.
    Fresh,
    /// It is not the volume's current database and must be rebuilt from the
    /// volume's snapshot and journal on Telegram first; the text says why.
    NeedsRebuild(String),
    /// It cannot be used, and the volume has no published snapshot to rebuild
    /// it from (and no user data: see [`manager::has_published_snapshot`]).
    /// The next mount sets it aside ([`set_aside`]) and creates a new one; the
    /// text says why.
    Unusable(String),
}

/// Decide whether the volume's local DB at `db_path` (in `base_dir`) may be
/// used, against what the volume's records say it must be (`expected`).
///
/// For a volume with a published snapshot, the DB is used as it is only when
/// it carries the lineage stamp the journal HEAD records, for this volume.
/// It must be rebuilt when the rebuild marker is present (a `volume restore`
/// that did not finish), when it is missing or zero-length, when SQLite
/// reports it damaged (NOTADB, CORRUPT, or `PRAGMA quick_check` not `ok`:
/// torn or overwritten by a crash, a full disk, or a copy written over it in
/// place), when its session record holds a journal position other than the
/// HEAD's,
/// when it has no root directory, when it carries no stamp (written by an
/// earlier build, or created by something else), a stamp naming another
/// volume, or a stamp other than the HEAD's (an older copy of the volume's DB,
/// or a DB stamped by a publish that did not finish), and when the HEAD records
/// no lineage (missing, or written by an earlier build). The volume's snapshot
/// and journal on Telegram hold everything such a DB should hold.
///
/// For a volume without a published snapshot there is nothing to rebuild from
/// (and nothing to compare a stamp with): its marker is ignored (the mount
/// removes it), a missing DB is [`LocalDb::Fresh`], and one that is unreadable,
/// has no root directory or is stamped as another volume's is
/// [`LocalDb::Unusable`].
///
/// A path that cannot even be checked (not "does not exist") is an error, and
/// so is a DB that exists but cannot be opened or read right now
/// ([`probe_db`]: permissions, a lock, I/O): never a reason to rebuild over it.
pub fn local_db_state(
    base_dir: &Path,
    db_path: &Path,
    schema: &OpaqueSchema,
    expected: &Expected,
) -> Result<LocalDb, CoreError> {
    let published = expected.published_snapshot;
    if published {
        if let Some(reason) = rebuild_marker::load(base_dir)? {
            return Ok(LocalDb::NeedsRebuild(format!(
                "the local metadata database is marked to be rebuilt ({reason})"
            )));
        }
        if let Some(why) = &expected.head_unreadable {
            return Ok(LocalDb::NeedsRebuild(format!(
                "the journal HEAD (journal.head) cannot be read ({why}), so nothing shows the \
                 local metadata database is the volume's current one"
            )));
        }
    }
    let bad = |why: String| {
        if published {
            LocalDb::NeedsRebuild(why)
        } else {
            LocalDb::Unusable(why)
        }
    };
    // A DB that exists but cannot be opened or read right now is an error
    // (`probe_db`), never a reason to rebuild over it.
    let content = match probe_db(db_path, schema)? {
        DbProbe::Absent => {
            return Ok(if published {
                LocalDb::NeedsRebuild("the local metadata database is missing".into())
            } else {
                LocalDb::Fresh
            })
        }
        // Torn or overwritten (a crash, a full disk, a copy put over it in
        // place while its WAL still held newer pages).
        DbProbe::Damaged(why) => {
            return Ok(bad(format!(
                "the local metadata database is unreadable: SQLite reports it damaged ({why})"
            )))
        }
        DbProbe::Readable(c) => c,
    };
    let (summary, stamp) = (content.tree, content.stamp);
    if !summary.has_root {
        return Ok(bad(
            "the local metadata database has no root directory (every database a mount \
             served has one; this one was created by something else, or by a first mount \
             that stopped before it created the root)"
                .into(),
        ));
    }
    if let Some(s) = &stamp {
        if s.volume_id != expected.volume_id {
            return Ok(bad(format!(
                "the local metadata database is stamped as the database of another volume \
                 ({}), not of this one",
                s.volume_id
            )));
        }
    }
    if !published {
        return Ok(LocalDb::Usable);
    }
    let Some(stamp) = stamp else {
        return Ok(LocalDb::NeedsRebuild(
            "the local metadata database carries no lineage stamp, so nothing shows it is the \
             volume's current database (it was written by an earlier version of teagarden, or \
             created by something else); the first mount by this version rebuilds it once from \
             the snapshot and journal journal.head names (without journal.head, a mount refuses \
             a database that can be read and names `volume restore` and `volume republish \
             --from-local-db`)"
                .into(),
        ));
    };
    let Some(want) = expected.lineage else {
        return Ok(LocalDb::NeedsRebuild(
            "the journal HEAD records no lineage (it is missing, or was written by an earlier \
             version of teagarden), so nothing shows the local metadata database is the \
             volume's current one"
                .into(),
        ));
    };
    if stamp.lineage != want {
        return Ok(LocalDb::NeedsRebuild(format!(
            "the local metadata database is not the volume's current database: it is stamped \
             as {}, the journal HEAD records {want} (an older copy of the database, or a \
             snapshot publish that did not finish)",
            stamp.lineage
        )));
    }
    // A DB last written by an earlier build has no session record: nothing
    // to compare (its stamp matched).
    if let (Some(rec), Some(head_seq)) = (content.session, expected.head_seq) {
        if rec.seq != head_seq {
            return Ok(LocalDb::NeedsRebuild(format!(
                "the local metadata database holds journal position {}, the journal HEAD \
                 records {head_seq} (a copy of the database from earlier in the same \
                 lineage, or a session whose last local commit did not happen)",
                rec.seq
            )));
        }
    }
    Ok(LocalDb::Usable)
}

/// File name prefix [`set_aside`] renames an unusable DB of a volume without
/// a published snapshot to: `metadata.db.unusable.<unix time>`.
pub const SET_ASIDE_PREFIX: &str = "metadata.db.unusable.";

/// Rename the DB at `db_path` (then its `-wal`/`-shm`/`-journal`) aside as
/// `metadata.db.unusable.<unix time>` in the same directory, and fsync the
/// directory: the DB is then absent. The main file goes first; a crash after
/// it leaves only sidecars without a main file, which [`create_db_atomically`]
/// removes before it installs a new DB. Returns the new path. Nothing removes
/// the renamed files.
pub fn set_aside(db_path: &Path) -> Result<std::path::PathBuf, CoreError> {
    let dir = db_path
        .parent()
        .ok_or_else(|| file_err("set aside", db_path, "no parent directory"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut aside = dir.join(format!("{SET_ASIDE_PREFIX}{now}"));
    let mut n = 1;
    while aside.exists() {
        aside = dir.join(format!("{SET_ASIDE_PREFIX}{now}.{n}"));
        n += 1;
    }
    std::fs::rename(db_path, &aside).map_err(|e| file_err("rename", db_path, e))?;
    for sfx in ["-wal", "-shm", "-journal"] {
        let mut from = db_path.as_os_str().to_os_string();
        from.push(sfx);
        let mut to = aside.as_os_str().to_os_string();
        to.push(sfx);
        match std::fs::rename(&from, &to) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(file_err("rename", Path::new(&from), e)),
        }
    }
    fsync_dir(dir)?;
    Ok(aside)
}

fn fsync_dir(dir: &Path) -> Result<(), CoreError> {
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| file_err("fsync", dir, e))
}

/// Create the volume's first metadata DB at `db_path` (which must be
/// absent) atomically: build it at `<db_path>.creating` with the schema,
/// `root` and `stamp`, close it (folding its WAL in), fsync it, remove any
/// sidecars left at `db_path` (SQLite would apply a stale `-wal` to the new
/// file), rename it into place and fsync the directory. A crash at any point
/// leaves either no DB (the next first mount starts again; a leftover
/// `.creating` file is removed first) or the whole new one.
pub fn create_db_atomically(
    db_path: &Path,
    schema: &OpaqueSchema,
    meta_key: &SymmetricKey,
    root: &teagarden_core::metadata::inode::Inode,
    stamp: &DbStamp,
) -> Result<(), CoreError> {
    let dir = db_path
        .parent()
        .ok_or_else(|| file_err("create", db_path, "no parent directory"))?;
    let mut tmp = db_path.as_os_str().to_os_string();
    tmp.push(".creating");
    let tmp = std::path::PathBuf::from(tmp);
    teagarden_core::volume::metadata_snapshot::remove_db_files(&tmp)?;
    {
        let conn = Connection::open(&tmp).map_err(|e| file_err("create", &tmp, e))?;
        crate::migrations::initialize_database(&conn, schema)
            .map_err(|e| file_err("initialize", &tmp, e))?;
        crate::inode_store::InodeStore::new(&conn, schema, meta_key)
            .insert(root)
            .map_err(|e| file_err("create the root directory in", &tmp, e))?;
        write_stamp(&conn, schema, Some(stamp)).map_err(|e| file_err("stamp", &tmp, e))?;
        checkpoint_fully(&conn, &tmp)?;
    }
    std::fs::File::open(&tmp)
        .and_then(|f| f.sync_all())
        .map_err(|e| file_err("fsync", &tmp, e))?;
    // Only the main file may remain (its WAL was folded in on close).
    for sfx in ["-wal", "-shm", "-journal"] {
        let mut side = tmp.as_os_str().to_os_string();
        side.push(sfx);
        match std::fs::remove_file(&side) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(file_err("remove", Path::new(&side), e)),
        }
    }
    // The destination is absent; sidecars of a lost DB may not be.
    teagarden_core::volume::metadata_snapshot::remove_db_files(db_path)?;
    std::fs::rename(&tmp, db_path).map_err(|e| file_err("rename into place", db_path, e))?;
    fsync_dir(dir)
}

/// Which file a metadata DB is: its device and inode number. A session
/// records it when it opens the DB, and a snapshot publish refuses to read a
/// different file at the same path (one put there while the session had the
/// DB open, such as an older copy restored from a backup).
///
/// While the session's connection is open its file cannot be freed, so a file
/// put at the path in the meantime has another inode number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbFileId {
    dev: u64,
    ino: u64,
}

impl DbFileId {
    /// The identity of the file at `db_path` (which must exist).
    pub fn of(db_path: &Path) -> Result<Self, CoreError> {
        let m = std::fs::metadata(db_path).map_err(|e| file_err("stat", db_path, e))?;
        Ok(Self::of_metadata(&m))
    }

    /// The identity of an opened file, from its metadata.
    pub fn of_metadata(m: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        DbFileId {
            dev: m.dev(),
            ino: m.ino(),
        }
    }
}

impl std::fmt::Display for DbFileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "device {} inode {}", self.dev, self.ino)
    }
}

/// Whether `now` is the file `opened` names. The one comparison every
/// snapshot publish makes before it stamps or reads the DB.
pub fn same_db_file(opened: &DbFileId, now: &DbFileId) -> bool {
    opened == now
}

/// What the file system says about the main DB file: identity (device,
/// inode) and the traces any write leaves (size, mtime, ctime, in
/// nanoseconds). A session records it after each of its own writes to the
/// main file ([`SessionCheckpoints`]); any other writer (`cp backup
/// metadata.db`, a sync tool, a restore from a backup) changes it.
///
/// Under WAL, rows inside the DB cannot prove which file the main file is:
/// the rows a session writes sit in the WAL, which such a writer does not
/// touch. The fingerprint is outside the DB. It detects accidents, not
/// someone who forges mtime and ctime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbFingerprint {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_ns: i128,
    ctime_ns: i128,
}

impl DbFingerprint {
    /// The fingerprint of the file at `db_path` (which must exist).
    pub fn of(db_path: &Path) -> Result<Self, CoreError> {
        let m = std::fs::metadata(db_path).map_err(|e| file_err("stat", db_path, e))?;
        Ok(Self::of_metadata(&m))
    }

    /// The fingerprint of an opened file, from its metadata.
    pub fn of_metadata(m: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        let ns = |s: i64, n: i64| i128::from(s) * 1_000_000_000 + i128::from(n);
        DbFingerprint {
            dev: m.dev(),
            ino: m.ino(),
            size: m.size(),
            mtime_ns: ns(m.mtime(), m.mtime_nsec()),
            ctime_ns: ns(m.ctime(), m.ctime_nsec()),
        }
    }
}

impl std::fmt::Display for DbFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "device {} inode {}, {} bytes, mtime {} ns, ctime {} ns",
            self.dev, self.ino, self.size, self.mtime_ns, self.ctime_ns
        )
    }
}

/// How many WAL frames (pages) a session lets its WAL grow to before it
/// checkpoints it into the main file itself ([`SessionCheckpoints`]).
pub const SESSION_CHECKPOINT_PAGES: u64 = 1000;

/// Hand the checkpoints of `conn` to its session: SQLite never checkpoints
/// on its own through it (`PRAGMA wal_autocheckpoint=0`), nor when it
/// closes (`SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE`). Only
/// [`SessionCheckpoints::checkpoint`] writes the main file then.
pub fn own_checkpoints(conn: &Connection) -> rusqlite::Result<()> {
    let pages: i64 = conn.query_row("PRAGMA wal_autocheckpoint=0", [], |r| r.get(0))?;
    if pages != 0 {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "PRAGMA wal_autocheckpoint=0 left it at {pages}"
        )));
    }
    conn.set_db_config(
        rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
        true,
    )?;
    Ok(())
}

/// The WAL frames beside the DB `conn` has open, from the `-wal` file's size
/// (0 when there is none).
pub fn wal_frames(conn: &Connection, db_path: &Path) -> rusqlite::Result<u64> {
    let page: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    let len = match std::fs::metadata(side_path(db_path, "-wal")) {
        Ok(m) => m.len(),
        Err(_) => return Ok(0),
    };
    // A 32-byte WAL header, then frames of a 24-byte header and one page.
    let frame = u64::try_from(page).unwrap_or(4096) + 24;
    Ok(len.saturating_sub(32) / frame)
}

/// Why [`SessionCheckpoints::checkpoint`] did not checkpoint.
#[derive(Debug)]
pub enum CheckpointRefused {
    /// Another writer changed the main DB file since the session last wrote
    /// it: nothing was checkpointed over it, and the session's DB is no
    /// longer its current database.
    Foreign(String),
    /// The checkpoint itself failed (busy readers, I/O); the WAL keeps the
    /// frames, nothing is lost.
    Failed(CoreError),
}

impl std::fmt::Display for CheckpointRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckpointRefused::Foreign(why) => f.write_str(why),
            CheckpointRefused::Failed(e) => write!(f, "{e}"),
        }
    }
}

struct CheckpointState {
    /// The main file as the session last left it.
    fingerprint: DbFingerprint,
    /// Set once another writer was seen: never cleared.
    foreign: Option<String>,
}

/// A session's ownership of its DB's main file. While a session (a mount,
/// `revert`, `key rotate`) has the DB open, only it writes the main file:
/// its connections never checkpoint on their own ([`own_checkpoints`]), and
/// it checkpoints explicitly ([`SessionCheckpoints::checkpoint`]: when the
/// WAL grows past [`SESSION_CHECKPOINT_PAGES`], before its connection
/// closes, and before a publish), recording the main file's
/// [`DbFingerprint`] after each of its own writes. Before each checkpoint,
/// and first of all when it publishes, it compares the fingerprint: a
/// mismatch means another writer touched the main file, and the session
/// never checkpoints over it, nor publishes it.
pub struct SessionCheckpoints {
    db_path: std::path::PathBuf,
    state: std::sync::Mutex<CheckpointState>,
}

impl std::fmt::Debug for SessionCheckpoints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCheckpoints")
            .field("db_path", &self.db_path)
            .finish_non_exhaustive()
    }
}

impl SessionCheckpoints {
    /// Start owning the checkpoints of the DB `conn` has open at `db_path`:
    /// [`own_checkpoints`] on `conn`, checkpoint everything into the main
    /// file, record its fingerprint.
    pub fn start(
        conn: &Connection,
        db_path: &Path,
    ) -> Result<std::sync::Arc<SessionCheckpoints>, CoreError> {
        own_checkpoints(conn).map_err(|e| file_err("own the checkpoints of", db_path, e))?;
        checkpoint_fully(conn, db_path)?;
        Ok(std::sync::Arc::new(SessionCheckpoints {
            db_path: db_path.to_path_buf(),
            state: std::sync::Mutex::new(CheckpointState {
                fingerprint: DbFingerprint::of(db_path)?,
                foreign: None,
            }),
        }))
    }

    /// The DB file the session owns.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CheckpointState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The main file as the session last left it.
    pub fn fingerprint(&self) -> DbFingerprint {
        self.lock().fingerprint
    }

    /// Whether another writer was seen (and why).
    pub fn foreign(&self) -> Option<String> {
        self.lock().foreign.clone()
    }

    fn compare(&self, state: &mut CheckpointState) -> Result<(), String> {
        if let Some(why) = &state.foreign {
            return Err(why.clone());
        }
        let why = match DbFingerprint::of(&self.db_path) {
            Ok(now) if now == state.fingerprint => return Ok(()),
            Ok(now) => format!(
                "the main metadata database file {} was written by another program while the \
                 session had it open (the session left it as {}; it is now {}): for example \
                 `cp` of a backup over it, a sync tool, or a restore from a backup",
                self.db_path.display(),
                state.fingerprint,
                now
            ),
            Err(e) => format!(
                "the main metadata database file cannot be checked against what the session \
                 left there ({e})"
            ),
        };
        state.foreign = Some(why.clone());
        Err(why)
    }

    /// Compare the main file with what the session last left there. `Err`
    /// says what changed; once it fails it always fails.
    pub fn verify(&self) -> Result<(), String> {
        let mut state = self.lock();
        self.compare(&mut state)
    }

    /// Checkpoint the WAL of `conn` (the session's connection) into the
    /// main file, after comparing the main file's fingerprint; then record
    /// the new fingerprint. A mismatch checkpoints nothing
    /// ([`CheckpointRefused::Foreign`]).
    pub fn checkpoint(&self, conn: &Connection) -> Result<(), CheckpointRefused> {
        let mut state = self.lock();
        self.compare(&mut state)
            .map_err(CheckpointRefused::Foreign)?;
        let done = checkpoint_fully(conn, &self.db_path);
        // Even an incomplete checkpoint may have written the main file.
        match DbFingerprint::of(&self.db_path) {
            Ok(fp) => state.fingerprint = fp,
            Err(e) => return Err(CheckpointRefused::Failed(e)),
        }
        done.map_err(CheckpointRefused::Failed)
    }

    /// [`SessionCheckpoints::checkpoint`] when the WAL beside the DB holds
    /// more than `pages` frames; `Ok(false)` when it does not.
    pub fn checkpoint_past(
        &self,
        conn: &Connection,
        pages: u64,
    ) -> Result<bool, CheckpointRefused> {
        let frames = wal_frames(conn, &self.db_path).map_err(|e| {
            CheckpointRefused::Failed(file_err("size the WAL of", &self.db_path, e))
        })?;
        if frames <= pages {
            return Ok(false);
        }
        self.checkpoint(conn).map(|()| true)
    }

    /// The session's own write to the main file outside
    /// [`SessionCheckpoints::checkpoint`] (a publish's restamp, or putting
    /// the replaced stamp back): compare the fingerprint, and only then
    /// write and record the new one, all under the session's lock.
    pub fn own_write<T>(
        &self,
        write: impl FnOnce() -> Result<T, CoreError>,
    ) -> Result<T, CheckpointRefused> {
        let mut state = self.lock();
        self.compare(&mut state)
            .map_err(CheckpointRefused::Foreign)?;
        let out = write();
        match DbFingerprint::of(&self.db_path) {
            Ok(fp) => state.fingerprint = fp,
            Err(e) => return Err(CheckpointRefused::Failed(e)),
        }
        out.map_err(CheckpointRefused::Failed)
    }

    /// Record the main file as it is now, after the session's own write to
    /// it outside [`SessionCheckpoints::checkpoint`] (a publish's restamp).
    /// The caller compared it first. Refused once another writer was seen.
    pub fn record_own_write(&self) -> Result<(), String> {
        let mut state = self.lock();
        if let Some(why) = &state.foreign {
            return Err(why.clone());
        }
        state.fingerprint = DbFingerprint::of(&self.db_path).map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// File name prefix of the copies [`keep_replaced`] keeps of a replaced DB
/// that can be read and has a root directory: `metadata.db.replaced.<unix
/// time>` (`.<n>` appended when that name is taken), with its sidecars.
pub const REPLACED_PREFIX: &str = "metadata.db.replaced.";

/// File name prefix of the copies [`keep_replaced`] sets aside, unread, of a
/// replaced DB it could not read as a volume database (damaged, rootless, or
/// one that cannot be opened right now): `metadata.db.unreadable.<unix
/// time>`.
pub const UNREADABLE_PREFIX: &str = "metadata.db.unreadable.";

/// How many copies of each kind [`keep_replaced`] keeps; the oldest beyond
/// that are removed.
pub const KEPT_COPIES: usize = 3;

/// The lineage and journal position a rebuild (or the restore's install)
/// reproduces from Telegram: a DB carrying exactly these (and passing
/// `quick_check`) is reproducible, and is not kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reproduces {
    /// The stamp it would carry.
    pub stamp: DbStamp,
    /// The journal position (HEAD seq).
    pub seq: u64,
}

/// What [`keep_replaced`] did with the DB about to be replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kept {
    /// There was none (missing or zero-length).
    Nothing,
    /// It carries the lineage and journal position the replacement
    /// reproduces from Telegram ([`Reproduces`]): not kept.
    Reproducible,
    /// Readable, with a root directory, and not reproducible: kept at
    /// `path` (checkpointed first); `removed` are older copies dropped by the
    /// cap ([`KEPT_COPIES`]).
    Replaced {
        /// The kept copy.
        path: std::path::PathBuf,
        /// Older copies removed by the cap.
        removed: Vec<std::path::PathBuf>,
    },
    /// Not readable as a volume database (`why`): renamed aside unread to
    /// `path`, sidecars too; `removed` as for [`Kept::Replaced`].
    Unreadable {
        /// The renamed file.
        path: std::path::PathBuf,
        /// Why it could not be read as a volume database.
        why: String,
        /// Older copies removed by the cap.
        removed: Vec<std::path::PathBuf>,
    },
}

fn side_path(p: &Path, sfx: &str) -> std::path::PathBuf {
    let mut s = p.as_os_str().to_os_string();
    s.push(sfx);
    std::path::PathBuf::from(s)
}

/// `(seconds, n)` of a copy's file name `<prefix><seconds>[.<n>]`; `None`
/// for anything else (a sidecar, another file).
fn copy_order(name: &str, prefix: &str) -> Option<(u64, u64)> {
    let rest = name.strip_prefix(prefix)?;
    let mut parts = rest.split('.');
    let secs = parts.next()?.parse().ok()?;
    let n = match parts.next() {
        None => 0,
        Some(n) => n.parse().ok()?,
    };
    parts.next().is_none().then_some((secs, n))
}

/// Rename the DB at `db_path`, then its sidecars, to a new
/// `<prefix><time>` in its directory, fsync the directory, then remove the
/// oldest copies with that prefix beyond [`KEPT_COPIES`]. Returns the new
/// path and the removed ones. Never opens the DB.
fn rename_aside(
    db_path: &Path,
    prefix: &str,
) -> Result<(std::path::PathBuf, Vec<std::path::PathBuf>), CoreError> {
    let dir = db_path
        .parent()
        .ok_or_else(|| file_err("keep", db_path, "no parent directory"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // A new name after every existing copy, so the cap removes the oldest.
    let mut n = 0u64;
    let mut secs = now;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            if let Some((s, k)) = copy_order(&e.file_name().to_string_lossy(), prefix) {
                if (s, k) >= (secs, n) {
                    (secs, n) = (s, k + 1);
                }
            }
        }
    }
    let name = |secs: u64, n: u64| {
        if n == 0 {
            format!("{prefix}{secs}")
        } else {
            format!("{prefix}{secs}.{n}")
        }
    };
    let mut to = dir.join(name(secs, n));
    while to.exists() {
        n += 1;
        to = dir.join(name(secs, n));
    }
    std::fs::rename(db_path, &to).map_err(|e| file_err("rename", db_path, e))?;
    for sfx in ["-wal", "-shm", "-journal"] {
        let from = side_path(db_path, sfx);
        match std::fs::rename(&from, side_path(&to, sfx)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(file_err("rename", &from, e)),
        }
    }
    fsync_dir(dir)?;
    // The cap: the oldest copies beyond KEPT_COPIES go (sidecars first).
    let mut copies: Vec<((u64, u64), std::path::PathBuf)> = std::fs::read_dir(dir)
        .map_err(|e| file_err("list", dir, e))?
        .flatten()
        .filter_map(|e| copy_order(&e.file_name().to_string_lossy(), prefix).map(|o| (o, e.path())))
        .collect();
    copies.sort();
    let mut removed = Vec::new();
    while copies.len() > KEPT_COPIES {
        let (_, old) = copies.remove(0);
        for sfx in ["-wal", "-shm", "-journal"] {
            let p = side_path(&old, sfx);
            match std::fs::remove_file(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(file_err("remove", &p, e)),
            }
        }
        std::fs::remove_file(&old).map_err(|e| file_err("remove", &old, e))?;
        removed.push(old);
    }
    if !removed.is_empty() {
        fsync_dir(dir)?;
    }
    Ok((to, removed))
}

/// Before a rebuild, restore, auto-restore or share adoption replaces the DB
/// at `db_path` (the caller holds the volume's exclusive lock). Nothing that
/// cannot be reproduced from Telegram is deleted:
///
/// - absent (missing, zero-length): nothing to do ([`Kept::Nothing`]);
/// - readable, `quick_check` ok, and carrying exactly the stamp and journal
///   position the replacement reproduces (`reproduces`): not kept
///   ([`Kept::Reproducible`]); the caller replaces it;
/// - readable with a root directory otherwise: checkpointed and renamed with
///   its sidecars to `metadata.db.replaced.<time>` ([`Kept::Replaced`]);
/// - anything else (damaged, rootless, or a file that cannot be opened right
///   now): renamed aside UNREAD, sidecars too, to
///   `metadata.db.unreadable.<time>` ([`Kept::Unreadable`]).
///
/// Each kind keeps at most [`KEPT_COPIES`] copies, the oldest removed
/// first. Afterwards nothing is at `db_path` unless the DB is
/// [`Kept::Reproducible`].
pub fn keep_replaced(
    db_path: &Path,
    schema: &OpaqueSchema,
    reproduces: Option<&Reproduces>,
) -> Result<Kept, CoreError> {
    if check_absent(db_path)? {
        return Ok(Kept::Nothing);
    }
    let unreadable = |why: String| {
        rename_aside(db_path, UNREADABLE_PREFIX).map(|(path, removed)| Kept::Unreadable {
            path,
            why,
            removed,
        })
    };
    let content = match probe_db(db_path, schema) {
        Ok(DbProbe::Absent) => return Ok(Kept::Nothing),
        Ok(DbProbe::Damaged(why)) => return unreadable(why),
        Err(e) => return unreadable(e.to_string()),
        Ok(DbProbe::Readable(c)) => c,
    };
    if !content.tree.has_root {
        return unreadable("it has no root directory".into());
    }
    if let Some(r) = reproduces {
        if content.stamp.as_ref() == Some(&r.stamp) && content.session.map(|s| s.seq) == Some(r.seq)
        {
            return Ok(Kept::Reproducible);
        }
        // A publish stamped it (journal position 0) and did not finish: it
        // holds what the replacement reproduces under the stamp it replaced.
        if content.session.map(|s| s.seq) == Some(0)
            && content
                .stamp
                .as_ref()
                .is_some_and(|s| s.volume_id == r.stamp.volume_id)
            && content.replaced.as_ref() == Some(r)
        {
            return Ok(Kept::Reproducible);
        }
    }
    // A checkpoint that fails leaves the WAL beside the file; it moves with it.
    if let Ok(c) = open_existing(db_path) {
        let _ = checkpoint_fully(&c, db_path);
    }
    let (path, removed) = rename_aside(db_path, REPLACED_PREFIX)?;
    Ok(Kept::Replaced { path, removed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inode_store::InodeStore;
    use crate::migrations::initialize_database;
    use crate::schema::logical_tables;
    use teagarden_core::metadata::inode::Inode;

    fn schema() -> OpaqueSchema {
        OpaqueSchema::new(SymmetricKey::from_bytes([9; 32]), &logical_tables())
    }

    const VOL: &str = "0b1e5b43-6a43-4d8e-9a3a-5e1c3d8f0a11";

    fn expected(published: bool, lineage: Option<Lineage>) -> Expected {
        Expected {
            volume_id: VOL.into(),
            published_snapshot: published,
            lineage,
            head_unreadable: None,
            head_seq: None,
        }
    }

    fn stamp(lineage: Lineage) -> DbStamp {
        DbStamp {
            volume_id: VOL.into(),
            lineage,
        }
    }

    /// A DB with the schema, the root and one file (no stamp).
    fn db_with_a_file(db: &Path) {
        let c = Connection::open(db).unwrap();
        let (sch, meta) = (schema(), SymmetricKey::from_bytes([3; 32]));
        initialize_database(&c, &sch).unwrap();
        let s = InodeStore::new(&c, &sch, &meta);
        s.insert(&Inode::root()).unwrap();
        s.insert(&Inode::new_file(2, 1, "f".into(), 0o644, 1, 1))
            .unwrap();
    }

    fn state(dir: &Path, db: &Path, e: &Expected) -> LocalDb {
        local_db_state(dir, db, &schema(), e).unwrap()
    }

    fn needs_rebuild(s: LocalDb, what: &str) -> bool {
        matches!(s, LocalDb::NeedsRebuild(r) if r.contains(what))
    }

    #[test]
    fn openers_never_create_a_db() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("metadata.db");
        assert!(open_existing(&db).is_err());
        assert!(open_read_only(&db).is_err());
        assert!(stamp_db_file(&db, &schema(), None).is_err());
        assert!(!db.exists(), "an opener created the DB");
    }

    /// N5: only a DB file that does not exist (or is empty) is absent. A path
    /// that cannot be checked (here ENOTDIR: a regular file where the volume
    /// directory should be) is an error, never "absent" (which reads as a new
    /// volume, or as a lost DB to rebuild).
    #[test]
    fn a_db_path_that_cannot_be_checked_is_an_error_not_absent() {
        let dir = tempfile::tempdir().unwrap();
        let not_a_dir = dir.path().join("f");
        std::fs::write(&not_a_dir, b"x").unwrap();
        let db = not_a_dir.join("metadata.db");
        let sch = schema();
        assert!(
            tree_summary_of(&db, &sch).is_err(),
            "summary of an unreadable path"
        );
        for published in [false, true] {
            let r = local_db_state(dir.path(), &db, &sch, &expected(published, None));
            assert!(r.is_err(), "published {published}: {r:?}");
        }
    }

    /// B1 and observation b: a DB file that is not a readable database must be
    /// rebuilt when the volume has a published snapshot; without one there is
    /// nothing to rebuild from, and it is Unusable (set aside by the next
    /// mount), not an error.
    #[test]
    fn an_unreadable_db_is_rebuilt_when_published_and_unusable_otherwise() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("metadata.db");
        std::fs::write(&db, vec![0x5A; 8192]).unwrap();
        let l = Lineage::new(1);
        assert!(needs_rebuild(
            state(dir.path(), &db, &expected(true, Some(l))),
            "unreadable"
        ));
        assert!(matches!(
            state(dir.path(), &db, &expected(false, None)),
            LocalDb::Unusable(r) if r.contains("unreadable")
        ));
    }

    /// The stamp rule. Only a DB carrying exactly the HEAD's lineage, for this
    /// volume, is the volume's current DB; no emptiness rule is involved: a DB
    /// with files and no stamp, or an older stamp, must be rebuilt too.
    #[test]
    fn a_published_volumes_db_is_usable_only_with_the_heads_lineage() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("metadata.db");
        db_with_a_file(&db);
        let now = Lineage::new(4);
        let older = Lineage::new(3);
        let e = expected(true, Some(now));
        // Unstamped (an earlier build's DB, or a foreign one), with a file.
        assert!(needs_rebuild(
            state(dir.path(), &db, &e),
            "no lineage stamp"
        ));
        // An older copy of the volume's own DB.
        stamp_db_file(&db, &schema(), Some(&stamp(older))).unwrap();
        assert!(needs_rebuild(
            state(dir.path(), &db, &e),
            "not the volume's current"
        ));
        // Same version, another nonce (a second DB stamped at that version).
        stamp_db_file(
            &db,
            &schema(),
            Some(&stamp(Lineage {
                nonce: [7; 16],
                ..now
            })),
        )
        .unwrap();
        assert!(needs_rebuild(
            state(dir.path(), &db, &e),
            "not the volume's current"
        ));
        // The current stamp.
        let prev = stamp_db_file(&db, &schema(), Some(&stamp(now))).unwrap();
        assert_eq!(
            prev.unwrap().lineage.nonce,
            [7; 16],
            "the replaced stamp is returned"
        );
        assert_eq!(state(dir.path(), &db, &e), LocalDb::Usable);
        // ...but not under a HEAD that records no lineage (legacy, or missing).
        assert!(needs_rebuild(
            state(dir.path(), &db, &expected(true, None)),
            "records no lineage"
        ));
        // The current stamp under another volume's id (same version and nonce).
        let foreign = DbStamp {
            volume_id: "2f0f7c39-0000-4000-8000-000000000000".into(),
            lineage: now,
        };
        stamp_db_file(&db, &schema(), Some(&foreign)).unwrap();
        assert!(needs_rebuild(state(dir.path(), &db, &e), "another volume"));
        // Two rows: not a stamp.
        stamp_db_file(&db, &schema(), Some(&stamp(now))).unwrap();
        {
            let c = open_existing(&db).unwrap();
            let sch = schema();
            let t = sch.require_table("lineage").unwrap().to_string();
            c.execute_batch(&format!("INSERT INTO {t} SELECT * FROM {t};"))
                .unwrap();
            assert_eq!(read_stamp(&c, &schema()).unwrap(), None);
        }
        assert!(needs_rebuild(
            state(dir.path(), &db, &e),
            "no lineage stamp"
        ));
        // Removing the stamp.
        stamp_db_file(&db, &schema(), None).unwrap();
        assert!(needs_rebuild(
            state(dir.path(), &db, &e),
            "no lineage stamp"
        ));
        // The marker wins over the current stamp.
        stamp_db_file(&db, &schema(), Some(&stamp(now))).unwrap();
        rebuild_marker::mark(dir.path(), "test").unwrap();
        assert!(needs_rebuild(
            state(dir.path(), &db, &e),
            "marked to be rebuilt (test)"
        ));
    }

    #[test]
    fn summary_and_state_follow_the_db() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("metadata.db");
        let sch = schema();
        let l = Lineage::new(2);

        // Missing.
        assert_eq!(tree_summary_of(&db, &sch).unwrap(), TreeSummary::NOTHING);
        assert_eq!(
            state(dir.path(), &db, &expected(false, None)),
            LocalDb::Fresh
        );
        assert!(needs_rebuild(
            state(dir.path(), &db, &expected(true, Some(l))),
            "missing"
        ));
        assert!(!db.exists(), "deciding created the DB");

        // Schema only (what `Connection::open` + `initialize_database` leave).
        {
            let c = Connection::open(&db).unwrap();
            initialize_database(&c, &sch).unwrap();
        }
        assert_eq!(tree_summary_of(&db, &sch).unwrap(), TreeSummary::NOTHING);
        assert!(needs_rebuild(
            state(dir.path(), &db, &expected(true, Some(l))),
            "no root"
        ));
        assert!(matches!(
            state(dir.path(), &db, &expected(false, None)),
            LocalDb::Unusable(r) if r.contains("no root")
        ));
        metadata_snapshot_remove(&db);

        // Root and one file, read through a read-only connection of a WAL DB
        // whose writer has closed (no -wal/-shm left).
        db_with_a_file(&db);
        assert_eq!(
            tree_summary_of(&db, &sch).unwrap(),
            TreeSummary {
                has_root: true,
                entries: 1
            }
        );
        // No published snapshot: usable as it is, stamped or not; its marker
        // is ignored. Another volume's stamp makes it unusable.
        assert_eq!(
            state(dir.path(), &db, &expected(false, None)),
            LocalDb::Usable
        );
        rebuild_marker::mark(dir.path(), "forged").unwrap();
        assert_eq!(
            state(dir.path(), &db, &expected(false, None)),
            LocalDb::Usable
        );
        let foreign = DbStamp {
            volume_id: "2f0f7c39-0000-4000-8000-000000000000".into(),
            lineage: l,
        };
        stamp_db_file(&db, &sch, Some(&foreign)).unwrap();
        assert!(matches!(
            state(dir.path(), &db, &expected(false, None)),
            LocalDb::Unusable(r) if r.contains("another volume")
        ));
    }

    fn metadata_snapshot_remove(db: &Path) {
        teagarden_core::volume::metadata_snapshot::remove_db_files(db).unwrap();
    }

    /// The stamp is outside the journal: a session that records every table
    /// (as a journaled FUSE transaction does) sees no change when the stamp is
    /// written, and an inode change beside it yields a changeset that applies
    /// to a DB with another stamp without touching that stamp.
    #[test]
    fn writing_the_stamp_records_no_journal_change() {
        use rusqlite::session::Session;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("metadata.db");
        db_with_a_file(&db);
        let c = open_existing(&db).unwrap();
        let sch = schema();
        let changeset = |f: &dyn Fn(&Connection)| -> Vec<u8> {
            let mut session = Session::new(&c).unwrap();
            session.attach(None::<&str>).unwrap();
            f(&c);
            let mut out = Vec::new();
            session.changeset_strm(&mut out).unwrap();
            out
        };
        let only_stamp =
            changeset(&|c| write_stamp(c, &sch, Some(&stamp(Lineage::new(5)))).unwrap());
        assert!(
            only_stamp.is_empty(),
            "the stamp entered a changeset: {} bytes",
            only_stamp.len()
        );
        let with_inode = changeset(&|c| {
            write_stamp(c, &sch, Some(&stamp(Lineage::new(6)))).unwrap();
            let meta = SymmetricKey::from_bytes([3; 32]);
            InodeStore::new(c, &sch, &meta)
                .insert(&Inode::new_file(3, 1, "g".into(), 0o644, 1, 1))
                .unwrap();
        });
        assert!(!with_inode.is_empty());
        // Apply it to a copy stamped otherwise: the stamp stays.
        drop(c);
        let other = dir.path().join("other.db");
        db_with_a_file(&other);
        let keep = stamp(Lineage::new(9));
        stamp_db_file(&other, &sch, Some(&keep)).unwrap();
        let o = open_existing(&other).unwrap();
        o.apply_strm(
            &mut with_inode.as_slice(),
            None::<fn(&str) -> bool>,
            |_, _| rusqlite::session::ConflictAction::SQLITE_CHANGESET_ABORT,
        )
        .unwrap();
        assert_eq!(read_stamp(&o, &sch).unwrap(), Some(keep));
        assert_eq!(tree_summary(&o, &sch).unwrap().entries, 2);
    }

    /// 7a: the first DB is created whole or not at all: schema, root and
    /// stamp at once; no sidecar of a lost DB survives into it; a leftover
    /// `.creating` file is replaced.
    #[test]
    fn the_first_db_is_created_atomically_with_its_root_and_stamp() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("metadata.db");
        let sch = schema();
        // A stale -wal of a lost DB and a half-built temp file of a killed run.
        std::fs::write(dir.path().join("metadata.db-wal"), vec![0xA5; 4096]).unwrap();
        std::fs::write(dir.path().join("metadata.db.creating"), b"torn").unwrap();
        let st = stamp(Lineage::new(0));
        create_db_atomically(
            &db,
            &sch,
            &SymmetricKey::from_bytes([3; 32]),
            &Inode::root(),
            &st,
        )
        .unwrap();
        let mut names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["metadata.db"]);
        let c = open_read_only(&db).unwrap();
        assert_eq!(read_stamp(&c, &sch).unwrap(), Some(st));
        assert_eq!(
            tree_summary(&c, &sch).unwrap(),
            TreeSummary {
                has_root: true,
                entries: 0
            }
        );
    }

    #[test]
    fn set_aside_moves_the_db_and_its_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("metadata.db");
        std::fs::write(&db, b"torn").unwrap();
        std::fs::write(dir.path().join("metadata.db-wal"), b"w").unwrap();
        let aside = set_aside(&db).unwrap();
        assert!(!db.exists() && !dir.path().join("metadata.db-wal").exists());
        assert!(aside
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with(SET_ASIDE_PREFIX));
        assert_eq!(std::fs::read(&aside).unwrap(), b"torn");
        let mut wal = aside.as_os_str().to_os_string();
        wal.push("-wal");
        assert_eq!(std::fs::read(wal).unwrap(), b"w");
    }

    /// Round 12, the session record: additive (a DB without it, as an
    /// earlier build wrote it, is compared by stamp only), and a DB whose
    /// recorded journal position is not the HEAD's must be rebuilt.
    #[test]
    fn the_session_record_is_compared_with_the_heads_position_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("metadata.db");
        db_with_a_file(&db);
        let l = Lineage::new(4);
        let sch = schema();
        stamp_db_file(&db, &sch, Some(&stamp(l))).unwrap();
        let mut e = expected(true, Some(l));
        e.head_seq = Some(5);
        // No session record (an earlier build): the stamp decides.
        assert_eq!(state(dir.path(), &db, &e), LocalDb::Usable);
        {
            let c = open_existing(&db).unwrap();
            begin_session(&c, &sch, [1; 16], 4).unwrap();
        }
        assert!(needs_rebuild(
            state(dir.path(), &db, &e),
            "journal position 4"
        ));
        {
            let c = open_existing(&db).unwrap();
            set_session_seq(&c, &sch, 5).unwrap();
            assert_eq!(
                read_session(&c, &sch).unwrap(),
                Some(SessionRecord {
                    nonce: Some([1; 16]),
                    seq: 5
                })
            );
        }
        assert_eq!(state(dir.path(), &db, &e), LocalDb::Usable);
        // restamp: stamp and position in one step, the previous ones returned.
        let l2 = Lineage::new(9);
        let prev = restamp_db_file(&db, &sch, Some(&stamp(l2)), Some(0)).unwrap();
        assert_eq!(prev, (Some(stamp(l)), Some(5)));
        let back = restamp_db_file(&db, &sch, prev.0.as_ref(), prev.1).unwrap();
        assert_eq!(back, (Some(stamp(l2)), Some(0)));
        let c = open_read_only(&db).unwrap();
        assert_eq!(read_session(&c, &sch).unwrap().unwrap().seq, 5);
        assert_eq!(read_stamp(&c, &sch).unwrap(), Some(stamp(l)));
    }

    /// Round 12: damage SQLite reports (NOTADB, CORRUPT, quick_check) is
    /// "damaged"; a DB that cannot be opened now (mode 000) is an error.
    #[test]
    fn probe_tells_damage_from_cannot_open_now() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("metadata.db");
        let sch = schema();
        assert_eq!(probe_db(&db, &sch).unwrap(), DbProbe::Absent);
        std::fs::write(&db, vec![0x5a; 4096]).unwrap();
        assert!(matches!(probe_db(&db, &sch).unwrap(), DbProbe::Damaged(_)));
        std::fs::remove_file(&db).unwrap();
        db_with_a_file(&db);
        assert!(matches!(probe_db(&db, &sch).unwrap(), DbProbe::Readable(_)));
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o000)).unwrap();
        let r = probe_db(&db, &sch);
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
        // root ignores the mode: only an unprivileged run can check this.
        use std::os::unix::fs::MetadataExt as _;
        if std::fs::metadata(&db).unwrap().uid() == 0 {
            eprintln!("SKIP: running as root, mode 000 does not stop a read");
            return;
        }
        let e = r.expect_err("mode 000 is not damage");
        assert!(e.to_string().contains("cannot be opened"), "{e}");
    }

    /// Round 12, `keep_replaced`: a reproducible DB is not kept; a readable
    /// one is kept as `metadata.db.replaced.<t>`; a damaged one is renamed
    /// unread to `metadata.db.unreadable.<t>`; each kind is capped at
    /// `KEPT_COPIES`, oldest first.
    #[test]
    fn keep_replaced_keeps_what_is_not_reproducible_and_caps_the_copies() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("metadata.db");
        let sch = schema();
        assert_eq!(keep_replaced(&db, &sch, None).unwrap(), Kept::Nothing);
        db_with_a_file(&db);
        let l = Lineage::new(3);
        restamp_db_file(&db, &sch, Some(&stamp(l)), Some(2)).unwrap();
        let repro = Reproduces {
            stamp: stamp(l),
            seq: 2,
        };
        assert_eq!(
            keep_replaced(&db, &sch, Some(&repro)).unwrap(),
            Kept::Reproducible
        );
        assert!(db.exists(), "a reproducible DB is left for the caller");
        let other = Reproduces {
            stamp: stamp(l),
            seq: 3,
        };
        let mut kept = Vec::new();
        for i in 0..5 {
            if i > 0 {
                db_with_a_file(&db);
            }
            match keep_replaced(&db, &sch, Some(&other)).unwrap() {
                Kept::Replaced { path, removed } => {
                    assert_eq!(removed.len(), usize::from(i >= 3), "round {i}");
                    kept.push(path);
                }
                k => panic!("round {i}: {k:?}"),
            }
            assert!(!db.exists());
        }
        let left: Vec<_> = kept.iter().filter(|p| p.exists()).cloned().collect();
        assert_eq!(left, kept[2..].to_vec(), "the oldest went first");
        std::fs::write(&db, b"torn").unwrap();
        std::fs::write(dir.path().join("metadata.db-wal"), b"w").unwrap();
        match keep_replaced(&db, &sch, None).unwrap() {
            Kept::Unreadable { path, .. } => {
                assert!(path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(UNREADABLE_PREFIX));
                assert_eq!(std::fs::read(&path).unwrap(), b"torn");
                assert_eq!(std::fs::read(side_path(&path, "-wal")).unwrap(), b"w");
            }
            k => panic!("{k:?}"),
        }
        assert!(!db.exists() && !dir.path().join("metadata.db-wal").exists());
    }

    fn insert_filler(c: &Connection, rows: usize) {
        c.execute_batch("CREATE TABLE IF NOT EXISTS filler(x BLOB)")
            .unwrap();
        let fill = vec![0x11u8; 3000];
        for _ in 0..rows {
            c.execute("INSERT INTO filler VALUES (?1)", [&fill])
                .unwrap();
        }
    }

    /// Round 13 (D3): a DB a publish stamped and did not finish (stamp L2,
    /// position 0, replacing L at position 5) is reproducible by what
    /// `journal.head` still names (L, 5), and is not kept; the same DB is
    /// kept against anything else.
    #[test]
    fn a_db_a_publish_stamped_and_did_not_finish_is_reproducible() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("metadata.db");
        let sch = schema();
        let l = Lineage::new(4);
        let l2 = Lineage::new(5);
        let killed_publish = |db: &Path| {
            db_with_a_file(db);
            restamp_db_file(db, &sch, Some(&stamp(l)), Some(5)).unwrap();
            restamp_db_file(db, &sch, Some(&stamp(l2)), Some(0)).unwrap();
        };
        killed_publish(&db);
        let head = Reproduces {
            stamp: stamp(l),
            seq: 5,
        };
        {
            let c = open_read_only(&db).unwrap();
            assert_eq!(replaced_stamp(&c, &sch).unwrap(), Some(head.clone()));
        }
        for other in [
            Reproduces {
                stamp: stamp(l),
                seq: 4,
            },
            Reproduces {
                stamp: stamp(Lineage::new(4)),
                seq: 5,
            },
        ] {
            assert!(
                matches!(
                    keep_replaced(&db, &sch, Some(&other)).unwrap(),
                    Kept::Replaced { .. }
                ),
                "{other:?}"
            );
            killed_publish(&db);
        }
        assert_eq!(
            keep_replaced(&db, &sch, Some(&head)).unwrap(),
            Kept::Reproducible
        );
        // Once a session journals onto it (position 1), it is not.
        {
            let c = open_existing(&db).unwrap();
            set_session_seq(&c, &sch, 1).unwrap();
        }
        assert!(matches!(
            keep_replaced(&db, &sch, Some(&head)).unwrap(),
            Kept::Replaced { .. }
        ));
    }

    /// Round 13 (D1): only the session writes the main file while it has the
    /// DB open. Its connection does not auto-checkpoint (far past SQLite's
    /// default 1000 pages) and does not checkpoint when it closes; a
    /// read-only opener (`history`, `diff`, the publish checks) never
    /// checkpoints, not even as the last connection to close; the session's
    /// own checkpoint writes the main file and records its fingerprint.
    #[test]
    fn only_the_session_checkpoints_the_main_file() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("metadata.db");
        db_with_a_file(&db);
        let c = open_existing(&db).unwrap();
        let ck = SessionCheckpoints::start(&c, &db).unwrap();
        let main = std::fs::read(&db).unwrap();
        insert_filler(&c, 1500);
        let frames = wal_frames(&c, &db).unwrap();
        assert!(frames > 2 * SESSION_CHECKPOINT_PAGES, "{frames} frames");
        assert_eq!(
            std::fs::read(&db).unwrap(),
            main,
            "SQLite auto-checkpointed"
        );
        let count = |c: &Connection| -> i64 {
            c.query_row("SELECT COUNT(*) FROM filler", [], |r| r.get(0))
                .unwrap()
        };
        {
            let r = open_read_only(&db).unwrap();
            assert_eq!(count(&r), 1500);
        }
        assert_eq!(std::fs::read(&db).unwrap(), main, "a reader checkpointed");
        ck.verify().unwrap();
        drop(c);
        assert_eq!(std::fs::read(&db).unwrap(), main, "close checkpointed");
        {
            // Now the only, and so the last, connection to close.
            let r = open_read_only(&db).unwrap();
            assert_eq!(count(&r), 1500);
        }
        assert_eq!(
            std::fs::read(&db).unwrap(),
            main,
            "the last reader to close checkpointed"
        );
        ck.verify().unwrap();
        let c = open_existing(&db).unwrap();
        own_checkpoints(&c).unwrap();
        assert!(ck.checkpoint_past(&c, SESSION_CHECKPOINT_PAGES).unwrap());
        assert_ne!(std::fs::read(&db).unwrap(), main);
        assert_eq!(wal_frames(&c, &db).unwrap(), 0);
        ck.verify().unwrap();
        assert!(!ck.checkpoint_past(&c, SESSION_CHECKPOINT_PAGES).unwrap());
        assert_eq!(count(&c), 1500);
    }

    /// Round 13 (D1): `cp backup metadata.db` while the session has the DB
    /// open (same inode, here even the same bytes) is never checkpointed
    /// over: the session's checkpoint refuses, the main file keeps the
    /// other writer's bytes, and the session's verify and record refuse
    /// from then on.
    #[test]
    fn a_session_never_checkpoints_over_another_writers_file() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("metadata.db");
        db_with_a_file(&db);
        let c = open_existing(&db).unwrap();
        let ck = SessionCheckpoints::start(&c, &db).unwrap();
        let backup = std::fs::read(&db).unwrap();
        insert_filler(&c, 3);
        // File-system timestamps may be coarse (one clock tick): the
        // fingerprint relies on a later write changing mtime or ctime.
        std::thread::sleep(std::time::Duration::from_millis(20));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&db)
            .unwrap();
        f.write_all(&backup).unwrap();
        f.sync_all().unwrap();
        drop(f);
        match ck.checkpoint(&c) {
            Err(CheckpointRefused::Foreign(why)) => {
                assert!(why.contains("another program"), "{why}")
            }
            other => panic!("checkpointed over another writer's file: {other:?}"),
        }
        assert_eq!(std::fs::read(&db).unwrap(), backup, "checkpointed over it");
        assert!(ck.verify().is_err());
        assert!(ck.record_own_write().is_err());
        assert!(ck.foreign().is_some());
        assert!(matches!(
            ck.checkpoint(&c),
            Err(CheckpointRefused::Foreign(_))
        ));
    }

    /// FINAL REVIEW scratch: which changes that do not touch the bytes read as
    /// another writer.
    #[test]
    fn final_fp_metadata_only_changes() {
        use std::os::unix::fs::PermissionsExt as _;
        for how in [
            "read-only-open-and-read",
            "chmod-to-the-same-mode",
            "hard-link-made-and-removed",
            "rename-away-and-back",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let db = dir.path().join("metadata.db");
            db_with_a_file(&db);
            let c = open_existing(&db).unwrap();
            let ck = SessionCheckpoints::start(&c, &db).unwrap();
            let bytes = std::fs::read(&db).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(20));
            match how {
                "read-only-open-and-read" => {
                    let _ = std::fs::read(&db).unwrap();
                }
                "chmod-to-the-same-mode" => {
                    let m = std::fs::metadata(&db).unwrap().permissions().mode();
                    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(m)).unwrap();
                }
                "hard-link-made-and-removed" => {
                    let l = dir.path().join("link");
                    std::fs::hard_link(&db, &l).unwrap();
                    std::fs::remove_file(&l).unwrap();
                }
                _ => {
                    let t = dir.path().join("away");
                    std::fs::rename(&db, &t).unwrap();
                    std::fs::rename(&t, &db).unwrap();
                }
            }
            assert_eq!(std::fs::read(&db).unwrap(), bytes);
            eprintln!(
                "FP[{how}]: bytes unchanged; verify -> {:?}",
                ck.verify()
                    .map_err(|e| e.chars().take(90).collect::<String>())
            );
        }
    }

    /// RS3: a rootless DB (schema only) holds nothing a user could want: it
    /// is set aside as `metadata.db.unreadable.<t>`, never as a kept copy, so
    /// it can never push a kept copy out of the bounded set.
    #[test]
    fn a_rootless_db_never_takes_a_kept_copys_place() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("metadata.db");
        let sch = schema();
        {
            let c = Connection::open(&db).unwrap();
            initialize_database(&c, &sch).unwrap();
        }
        match keep_replaced(&db, &sch, None).unwrap() {
            Kept::Unreadable { path, why, .. } => {
                assert!(why.contains("no root directory"), "{why}");
                assert!(path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(UNREADABLE_PREFIX));
            }
            k => panic!("a rootless DB was {k:?}"),
        }
    }

    /// A DB whose `blocks` b-tree page is damaged in place still opens, and
    /// its tree, stamp and session record still read: only `PRAGMA
    /// quick_check` shows the damage. It is Damaged (a published volume's DB must be
    /// rebuilt; with no marker involved), and it is set aside unread.
    #[test]
    fn a_db_failing_only_quick_check_is_damaged() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("metadata.db");
        let sch = schema();
        db_with_a_file(&db);
        let l = Lineage::new(2);
        restamp_db_file(&db, &sch, Some(&stamp(l)), Some(0)).unwrap();
        let (root, page): (i64, i64) = {
            let c = open_read_only(&db).unwrap();
            let t = sch.require_table("blocks").unwrap().to_string();
            (
                c.query_row(
                    "SELECT rootpage FROM sqlite_master WHERE name = ?1",
                    [t],
                    |r| r.get(0),
                )
                .unwrap(),
                c.query_row("PRAGMA page_size", [], |r| r.get(0)).unwrap(),
            )
        };
        let mut bytes = std::fs::read(&db).unwrap();
        let off = usize::try_from((root - 1) * page).unwrap();
        bytes[off] = 0;
        bytes[off + 3] = 0xff;
        bytes[off + 4] = 0xff;
        std::fs::write(&db, &bytes).unwrap();
        {
            let c = open_read_only(&db).unwrap();
            assert_eq!(read_stamp(&c, &sch).unwrap(), Some(stamp(l)));
            assert!(tree_summary(&c, &sch).unwrap().has_root);
            // quick_check reports the damage (rows, or SQLITE_CORRUPT).
            assert!(!matches!(quick_check(&c), Ok(None)));
        }
        assert!(matches!(probe_db(&db, &sch).unwrap(), DbProbe::Damaged(_)));
        let mut e = expected(true, Some(l));
        e.head_seq = Some(0);
        assert!(needs_rebuild(state(dir.path(), &db, &e), "damaged"));
        assert!(matches!(
            keep_replaced(&db, &sch, None).unwrap(),
            Kept::Unreadable { .. }
        ));
    }
}
