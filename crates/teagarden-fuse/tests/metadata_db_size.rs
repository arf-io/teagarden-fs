//! How large the local metadata database (the thing a metadata snapshot
//! uploads) grows per file, measured through a real FUSE mount in the
//! production configuration: journal on, upload queue on, block integrity on.
//!
//! 10,000 small files are written with ordinary syscalls, the filesystem is
//! unmounted cleanly, and the size of `metadata.db` is divided by the file
//! count. The figure is printed (it is what docs/USER_GUIDE.md quotes) and
//! bounded, so a schema change that bloats the DB per file fails here. It also
//! reports how many such files fit under the snapshot upload limit.
//!
//! Requires an unprivileged FUSE mount; SKIPS without one unless
//! `TEAGARDEN_REQUIRE_FUSE` is set.

use std::path::Path;
use std::sync::Arc;

use rusqlite::Connection;
use teagarden_core::crypto::keys::SymmetricKey;
use teagarden_core::metadata::inode::Inode;
use teagarden_core::volume::journal_head::JournalHead;
use teagarden_core::volume::metadata_snapshot::encrypt_snapshot;
use teagarden_fuse::fs::CryptFs;
use teagarden_store::inode_store::InodeStore;
use teagarden_store::migrations::initialize_database;
use teagarden_store::opaque_schema::OpaqueSchema;
use teagarden_store::schema::logical_tables;
use teagarden_telegram::client::{BlockTransport, MAX_METADATA_UPLOAD_BYTES};
use teagarden_telegram::mock::MockTransport;

const FILES: usize = 10_000;
const FILE_BYTES: usize = 200;

fn fuse_available() -> bool {
    let which = |bin: &str| {
        std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).exists()))
            .unwrap_or(false)
    };
    Path::new("/dev/fuse").exists() && (which("fusermount3") || which("fusermount"))
}

fn force_unmount(mp: &Path) {
    for bin in ["fusermount3", "fusermount"] {
        let _ = std::process::Command::new(bin).arg("-u").arg(mp).output();
    }
}

#[test]
fn metadata_db_bytes_per_small_file() {
    let require = std::env::var_os("TEAGARDEN_REQUIRE_FUSE").is_some();
    if !fuse_available() {
        assert!(
            !require,
            "TEAGARDEN_REQUIRE_FUSE set but FUSE is unavailable"
        );
        eprintln!("SKIP: /dev/fuse or fusermount not available");
        return;
    }
    let key = |b: u8| SymmetricKey::from_bytes([b; 32]);
    let schema = || OpaqueSchema::new(key(0x42), &logical_tables());
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("metadata.db");
    let head_path = dir.path().join("journal.head");
    {
        let conn = Connection::open(&db_path).unwrap();
        initialize_database(&conn, &schema()).unwrap();
        let mut root = Inode::root();
        root.uid = unsafe { libc::getuid() };
        root.gid = unsafe { libc::getgid() };
        InodeStore::new(&conn, &schema(), &key(0x43))
            .insert(&root)
            .unwrap();
    }
    let empty_db = std::fs::metadata(&db_path).unwrap().len();
    let transport = Arc::new(MockTransport::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let base = encrypt_snapshot(&key(0x44), 1, &std::fs::read(&db_path).unwrap()).unwrap();
    let base_id = rt.block_on(transport.sync_metadata(&base)).unwrap();
    let head = JournalHead {
        seq: 0,
        parent_msg_id: base_id,
        base_snapshot_version: 1,
        base_snapshot_msg_id: base_id,
        base_snapshot_hash: *blake3::hash(&base).as_bytes(),
        last_hash: None,
        lineage: None,
    };
    head.store_atomic(&head_path, &key(0x48)).unwrap();

    let fs = CryptFs::new(
        Connection::open(&db_path).unwrap(),
        schema(),
        key(0x43),
        key(0x44),
        unsafe { libc::getuid() },
        unsafe { libc::getgid() },
    )
    .with_block_keys(key(0x45), key(0x46))
    .with_manifest_key(key(0x47))
    .with_block_integrity(true)
    .with_transport(transport.clone())
    .with_runtime(rt.handle().clone())
    .with_upload_queue()
    .with_journal(key(0x48), head_path.clone(), head);

    let mp_dir = tempfile::tempdir().unwrap();
    let mp = mp_dir.path().to_path_buf();
    let session = match fuser::spawn_mount2(
        fs,
        &mp,
        &[fuser::MountOption::FSName("teagarden-dbsize-test".into())],
    ) {
        Ok(s) => s,
        Err(e) => {
            assert!(!require, "TEAGARDEN_REQUIRE_FUSE set but mount failed: {e}");
            eprintln!("SKIP: spawn_mount2 failed: {e}");
            return;
        }
    };
    let started = std::time::Instant::now();
    let written = std::panic::catch_unwind(|| {
        for i in 0..FILES {
            // Distinct contents, so no two files dedup into one block.
            let mut body = format!("file {i:05} ").into_bytes();
            body.resize(FILE_BYTES, b'x');
            std::fs::write(mp.join(format!("document-{i:05}.txt")), &body).unwrap();
        }
        std::fs::read_dir(&mp).unwrap().count()
    });
    drop(session); // clean unmount: CryptFs and its DB connection are dropped
    force_unmount(&mp);
    let listed = written.expect("writing the files through the mount");
    assert_eq!(listed, FILES);

    let wal = dir.path().join("metadata.db-wal");
    let wal_len = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
    let db = std::fs::metadata(&db_path).unwrap().len() + wal_len;
    let per_file = (db - empty_db) as f64 / FILES as f64;
    let fit = (MAX_METADATA_UPLOAD_BYTES as f64 / per_file) as u64;
    eprintln!(
        "metadata DB: empty {empty_db} B, after {FILES} files of {FILE_BYTES} B: {db} B \
         (wal {wal_len} B) => {per_file:.0} B per file; the {MAX_METADATA_UPLOAD_BYTES} B \
         snapshot limit holds about {fit} such files; written in {:.1}s",
        started.elapsed().as_secs_f64()
    );
    // Regression bound: an order of magnitude above today's figure would mean
    // the per-file metadata (and therefore every snapshot) ballooned.
    assert!(per_file < 8192.0, "{per_file:.0} B of metadata per file");
}
