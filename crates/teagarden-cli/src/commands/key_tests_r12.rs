// Round 12: the round-11 review's findings (rev_r1, r2, r2c, r3, r4, r5, r8,
// r9, r12) as asserting regression tests, and the guards this round adds
// (included into key.rs `tests::r8::real_fuse::r10`, after
// `key_tests_r11.rs`).

/// The root-directory names of the metadata DB file at `p`.
fn names_at(v: &RotVol, p: &Path) -> std::result::Result<Vec<String>, String> {
    let r = v.open();
    let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
    let c = local_db::open_read_only(p).map_err(|e| format!("open: {e}"))?;
    let mut n: Vec<String> = InodeStore::new(&c, &schema, &r.hierarchy.meta)
        .list_children(1)
        .map_err(|e| format!("list: {e}"))?
        .into_iter()
        .map(|i| i.name)
        .collect();
    n.sort();
    Ok(n)
}

fn has_thesis(v: &RotVol, p: &Path) -> bool {
    names_at(v, p).is_ok_and(|n| n.iter().any(|x| x == "thesis"))
}

/// The names in the snapshot volume.json names (`Err` when it cannot be read).
fn snapshot_names(v: &RotVol) -> std::result::Result<Vec<String>, String> {
    let r = v.open();
    let id = r.config.metadata_snapshot_id.ok_or("no snapshot id")?;
    let blob = v.mock.get_raw(id).ok_or("snapshot not on channel")?;
    let (_, db) = metadata_snapshot::decrypt_snapshot(&r.hierarchy.data, &blob)
        .map_err(|e| format!("decrypt: {e}"))?;
    let p = v.dir.path().join(format!("r12names-{id}.db"));
    std::fs::write(&p, db).unwrap();
    let n = names_at(v, &p);
    let _ = metadata_snapshot::remove_db_files(&p);
    n
}

fn ino_of(p: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(p).unwrap().ino()
}

fn sidecar(p: &Path, sfx: &str) -> std::path::PathBuf {
    let mut s = p.as_os_str().to_os_string();
    s.push(sfx);
    std::path::PathBuf::from(s)
}

/// `cp backup metadata.db`: truncate the file and write `bytes` into the
/// SAME inode, then sync it.
fn overwrite_in_place(p: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(p)
        .unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}

/// The kept copies of replaced DBs in the volume directory (main files
/// only), oldest first.
fn kept_copies(v: &RotVol) -> Vec<std::path::PathBuf> {
    kept_copy_paths(v)
}

/// Whether some kept copy holds `thesis`.
fn thesis_kept(v: &RotVol) -> bool {
    kept_copies(v).iter().any(|p| has_thesis(v, p))
}

/// The copies of DBs set aside unread (main files only).
fn unreadable_copies(v: &RotVol) -> Vec<std::path::PathBuf> {
    let base = v.open().paths.base_dir;
    ls_dir(v)
        .into_iter()
        .filter(|n| n.starts_with("metadata.db.unreadable."))
        .filter(|n| !n.ends_with("-wal") && !n.ends_with("-shm") && !n.ends_with("-journal"))
        .map(|n| base.join(n))
        .collect()
}

/// After a refused publish: the stale-metadata report must not say the
/// local DB is intact, and must say the next mount rebuilds it.
fn assert_refusal_says_rebuild(v: &RotVol, msg: &str, when: &str) {
    assert!(!msg.contains("intact"), "{when}: the refusal says intact: {msg}");
    assert!(msg.contains("next mount rebuilds"), "{when}: {msg}");
    let status = crate::commands::volume::snapshot_publish_status(&v.open().paths.base_dir)
        .expect_err("a refused publish is recorded");
    let status = format!("{status:#}");
    assert!(!status.contains("intact"), "{when}: status says intact: {status}");
    assert!(status.contains("next mount rebuilds"), "{when}: {status}");
}

// ── B1: a publish proves by content what it uploads ─────────────────────────

/// rev_r1: during a session the user puts an older copy back the way `cp
/// backup metadata.db` does it: truncated and rewritten IN PLACE (same
/// inode), with the sidecars kept or removed, before or after SQLite's own
/// WAL auto-checkpoint has folded `thesis` into the main file. Every variant
/// must end with the publish REFUSED (HEAD seq > 0, nothing uploaded, the
/// next mount lists `thesis`) or with a published snapshot that holds
/// `thesis`.
#[test]
fn r12_b1_an_in_place_overwrite_never_publishes_a_wrong_or_malformed_db() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    for how in [
        "keep-sidecars",
        "rm-sidecars",
        "after-autocheckpoint",
        "after-autocheckpoint-rm-sidecars",
    ] {
        let v = rot_volume(&rt);
        own_root(&v);
        clean_unmount(&rt, &v);
        let db = v.open().paths.db_path.clone();
        let backup = std::fs::read(&db).unwrap();
        let (mut r, s) = prep_ok(&rt, &v, "B1: session");
        let ino = ino_of(&db);
        let mut checkpointed = false;
        if with_mount(&rt, &v, |mp| {
            write_synced(mp, "thesis", b"a month of work");
            if how.starts_with("after-autocheckpoint") {
                // Write until SQLite's WAL auto-checkpoint has folded
                // `thesis` into the main file.
                let probe = v.dir.path().join("r12-probe.db");
                for i in 0..3000 {
                    write_synced(mp, &format!("f{i}"), b"x");
                    if i % 20 == 19 {
                        std::fs::copy(&db, &probe).unwrap();
                        let has = has_thesis(&v, &probe);
                        let _ = metadata_snapshot::remove_db_files(&probe);
                        if has {
                            checkpointed = true;
                            break;
                        }
                    }
                }
                assert!(checkpointed, "B1[{how}]: no auto-checkpoint seen");
            }
            overwrite_in_place(&db, &backup);
            if how.ends_with("rm-sidecars") {
                for sfx in ["-wal", "-shm"] {
                    let _ = std::fs::remove_file(sidecar(&db, sfx));
                }
            }
        })
        .is_none()
        {
            return;
        }
        assert_eq!(ino_of(&db), ino, "B1[{how}]: the overwrite kept the inode");
        let seq_before = head_of(&v).seq;
        assert!(seq_before > 0, "B1[{how}]");
        let msgs = v.mock.message_count();
        let res = unmount_publish(&rt, &v, &mut r, s);
        let outcome = match &res {
            Ok(()) => "published".to_string(),
            Err(e) => format!("REFUSED: {e:#}"),
        };
        eprintln!(
            "B1[{how}]: auto-checkpoint seen {checkpointed}; unmount publish -> {outcome}; \
             uploaded {}; HEAD seq {} -> {}; snapshot {:?}",
            v.mock.message_count() - msgs,
            seq_before,
            head_of(&v).seq,
            snapshot_names(&v).map(|n| n.iter().any(|x| x == "thesis"))
        );
        match res {
            Ok(()) => assert!(
                snapshot_names(&v).is_ok_and(|n| n.iter().any(|x| x == "thesis")),
                "B1[{how}]: published a snapshot without thesis: {:?}",
                snapshot_names(&v)
            ),
            Err(e) => {
                assert_eq!(v.mock.message_count(), msgs, "B1[{how}]: a refusal uploaded");
                assert_eq!(head_of(&v).seq, seq_before, "B1[{how}]: the HEAD moved");
                assert_refusal_says_rebuild(&v, &format!("{e:#}"), &format!("B1[{how}]"));
            }
        }
        let (_, next) = prep_ok(&rt, &v, &format!("B1[{how}]: next mount"));
        eprintln!("B1[{how}]: next mount rebuilt {}", next.rebuilt);
        assert!(
            local_names(&v).iter().any(|x| x == "thesis"),
            "B1[{how}]: the next mount does not list thesis: {:?}",
            names_at(&v, &db)
        );
    }
}

/// rev_r8: journal.head is deleted during a session and an older copy with
/// another stamp is copied over metadata.db in place. The session started
/// with a HEAD, so its publish refuses (nothing uploaded); the snapshot
/// volume.json names still holds `thesis`.
#[test]
fn r12_b1_a_head_deleted_during_the_session_refuses_the_publish() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    own_root(&v);
    clean_unmount(&rt, &v);
    let db = v.open().paths.db_path.clone();
    let older = std::fs::read(&db).unwrap();
    if with_mount(&rt, &v, |mp| write_synced(mp, "thesis", b"a month of work")).is_none() {
        return;
    }
    let (mut r, s) = prep_ok(&rt, &v, "R8: session 2");
    unmount_publish(&rt, &v, &mut r, s).expect("R8: unmount");
    let (mut r, s) = prep_ok(&rt, &v, "R8: session 3");
    let hp = journal_head_path(&v.open());
    with_mount(&rt, &v, |_mp| {
        std::fs::remove_file(&hp).unwrap();
        overwrite_in_place(&db, &older);
    })
    .unwrap();
    let msgs = v.mock.message_count();
    let e = unmount_publish(&rt, &v, &mut r, s).expect_err("R8: published");
    eprintln!("R8: {e:#}");
    assert!(format!("{e:#}").contains("journal.head"), "{e:#}");
    assert_eq!(v.mock.message_count(), msgs, "R8: uploaded");
    assert!(
        snapshot_names(&v).unwrap().iter().any(|x| x == "thesis"),
        "R8: the snapshot volume.json names lost thesis"
    );
    assert!(!hp.exists(), "R8: the refusal wrote a HEAD");
    // Without a HEAD the refusal writes no rebuild marker (which would make
    // the next mount restore the snapshot over the DB): the next mount
    // refuses and names both ways out instead.
    assert!(!marker(&v), "R8: a marker without a HEAD");
    assert_mount_refuses_naming_both_ways_out(&rt, &v, "R8: next mount");
}

/// A DB put back in place from another session of the same lineage, at the
/// same journal position (seq 0), and identical apart from that: only the
/// session nonce shows it is not this session's database. Refused.
#[test]
fn r12_b1_another_sessions_db_at_the_same_position_is_refused_by_its_nonce() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    let db = v.open().paths.db_path.clone();
    let (_r1, _s1) = prep_ok(&rt, &v, "nonce: session 1");
    let other = std::fs::read(&db).unwrap();
    let (mut r2, s2) = prep_ok(&rt, &v, "nonce: session 2");
    overwrite_in_place(&db, &other);
    for sfx in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(sidecar(&db, sfx));
    }
    let msgs = v.mock.message_count();
    let e = unmount_publish(&rt, &v, &mut r2, s2).expect_err("nonce: published");
    eprintln!("nonce: {e:#}");
    assert!(format!("{e:#}").contains("session"), "{e:#}");
    assert_eq!(v.mock.message_count(), msgs);
    assert_refusal_says_rebuild(&v, &format!("{e:#}"), "nonce");
    // Its stamp and journal position are the HEAD's, but the refused file is
    // not served as it is: the next mount rebuilds it.
    assert!(matches!(
        local_db_state(&v.open()).unwrap(),
        LocalDb::NeedsRebuild(_)
    ));
    let (_, next) = prep_ok(&rt, &v, "nonce: next mount");
    assert!(next.rebuilt, "nonce: the next mount served the refused file");
    assert_files_exact(&rt, &v, "nonce: after the rebuild");
}

/// T2 at journal position 0: a byte copy of the session's own DB renamed
/// into place (another inode, same nonce, stamp and position). Refused by
/// identity, and the next mount rebuilds it rather than serve it.
#[test]
fn r12_b1_a_db_renamed_into_place_at_seq_0_is_refused_and_rebuilt() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    let db = v.open().paths.db_path.clone();
    let (mut r, s) = prep_ok(&rt, &v, "rename: session");
    let tmp = v.dir.path().join("copy.db");
    std::fs::copy(&db, &tmp).unwrap();
    std::fs::rename(&tmp, &db).unwrap();
    // The fingerprint (checked first) is told the file is the session's,
    // as a coarse timestamp or a forged mtime would: the secondary check
    // must still refuse.
    s.db.checkpoints.record_own_write().unwrap();
    let msgs = v.mock.message_count();
    let e = unmount_publish(&rt, &v, &mut r, s).expect_err("rename: published");
    assert!(format!("{e:#}").contains("not the metadata database this session opened"), "{e:#}");
    assert_eq!(v.mock.message_count(), msgs);
    assert_refusal_says_rebuild(&v, &format!("{e:#}"), "rename");
    let (_, next) = prep_ok(&rt, &v, "rename: next mount");
    assert!(next.rebuilt, "rename: the next mount served the refused file");
    assert_files_exact(&rt, &v, "rename: after the rebuild");
}

/// A copy of this session's own DB from before its journaled write, put
/// back in place after the FUSE session closed: same nonce, same stamp, but
/// its journal position is behind the HEAD's. Refused; the next mount
/// replays the journal and lists `thesis`.
#[test]
fn r12_b1_this_sessions_older_db_is_refused_by_its_journal_position() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    own_root(&v);
    clean_unmount(&rt, &v);
    let db = v.open().paths.db_path.clone();
    let (mut r, s) = prep_ok(&rt, &v, "seq: session");
    let early = std::fs::read(&db).unwrap();
    if with_mount(&rt, &v, |mp| write_synced(mp, "thesis", b"a month of work")).is_none() {
        return;
    }
    overwrite_in_place(&db, &early);
    for sfx in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(sidecar(&db, sfx));
    }
    let seq = head_of(&v).seq;
    assert!(seq > 0);
    // The fingerprint (checked first) is told the file is the session's,
    // as a coarse timestamp or a forged mtime would: the secondary check
    // must still refuse.
    s.db.checkpoints.record_own_write().unwrap();
    let msgs = v.mock.message_count();
    let e = unmount_publish(&rt, &v, &mut r, s).expect_err("seq: published");
    eprintln!("seq: {e:#}");
    assert!(format!("{e:#}").contains("journal position"), "{e:#}");
    assert_eq!(v.mock.message_count(), msgs);
    assert_eq!(head_of(&v).seq, seq);
    assert_refusal_says_rebuild(&v, &format!("{e:#}"), "seq");
    let (_, next) = prep_ok(&rt, &v, "seq: next mount");
    assert!(next.rebuilt);
    assert_eq!(local_names(&v), ["a", "b", "h", "thesis"]);
}

/// Damage the b-tree page of the `inodes` table of the DB at `p` (in place):
/// the session and lineage tables still read, `PRAGMA quick_check` does not.
fn damage_inodes_page(v: &RotVol, p: &Path) {
    let r = v.open();
    let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
    let t = schema.require_table("inodes").unwrap().to_string();
    let (root, page_size): (i64, i64) = {
        let c = local_db::open_read_only(p).unwrap();
        (
            c.query_row(
                "SELECT rootpage FROM sqlite_master WHERE name = ?1",
                [&t],
                |r| r.get(0),
            )
            .unwrap(),
            c.query_row("PRAGMA page_size", [], |r| r.get(0)).unwrap(),
        )
    };
    assert!(root > 1);
    let mut bytes = std::fs::read(p).unwrap();
    let off = ((root - 1) * page_size) as usize;
    bytes[off] = 0x00; // not a b-tree page type
    bytes[off + 3] = 0xff;
    bytes[off + 4] = 0xff;
    overwrite_in_place(p, &bytes);
}

/// A DB that fails `PRAGMA quick_check` (its inodes page damaged in place)
/// is never published, even with this session's nonce and the HEAD's
/// journal position; the next mount rebuilds it, setting the damaged file
/// aside unread (`metadata.db.unreadable.<time>`, byte-identical).
#[test]
fn r12_b1_a_db_failing_quick_check_is_refused_and_set_aside_by_the_rebuild() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    let db = v.open().paths.db_path.clone();
    let (mut r, s) = prep_ok(&rt, &v, "qc: session");
    for sfx in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(sidecar(&db, sfx));
    }
    damage_inodes_page(&v, &db);
    let damaged = std::fs::read(&db).unwrap();
    // The fingerprint (checked first) is told the file is the session's,
    // as a coarse timestamp or a forged mtime would: the secondary check
    // must still refuse.
    s.db.checkpoints.record_own_write().unwrap();
    let msgs = v.mock.message_count();
    let e = unmount_publish(&rt, &v, &mut r, s).expect_err("qc: published");
    eprintln!("qc: {e:#}");
    assert!(format!("{e:#}").contains("quick_check"), "{e:#}");
    assert_eq!(v.mock.message_count(), msgs);
    assert_refusal_says_rebuild(&v, &format!("{e:#}"), "qc");
    // The next mount must not serve it.
    assert!(
        matches!(local_db_state(&v.open()).unwrap(), LocalDb::NeedsRebuild(_)),
        "qc: a damaged DB is usable"
    );
    let (_, next) = prep_ok(&rt, &v, "qc: next mount");
    assert!(next.rebuilt);
    assert_files_exact(&rt, &v, "qc: after the rebuild");
    let aside = unreadable_copies(&v);
    assert_eq!(aside.len(), 1, "qc: {:?}", ls_dir(&v));
    assert_eq!(std::fs::read(&aside[0]).unwrap(), damaged, "qc: the copy changed");
}

// ── B2: "cannot open right now" is never "worthless" ────────────────────────

/// rev_r3: with no journal.head, a DB that cannot be opened right now (mode
/// 000; another process holding it in exclusive locking mode) is never
/// rebuilt over: the mount refuses and names the cause, metadata.db stays
/// byte-identical and nothing is uploaded.
#[test]
fn r12_b2_a_db_that_cannot_be_opened_now_is_refused_not_replaced() {
    use std::os::unix::fs::PermissionsExt as _;
    let rt = tokio::runtime::Runtime::new().unwrap();
    for how in ["chmod-000", "exclusive-lock"] {
        let Some(v) = crashed_with_thesis(&rt) else { return };
        let r = v.open();
        let db = r.paths.db_path.clone();
        std::fs::remove_file(journal_head_path(&r)).unwrap();
        let before = std::fs::read(&db).unwrap();
        let files_before = ls_dir(&v);
        let mut locker = None;
        match how {
            "chmod-000" => {
                std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o000)).unwrap()
            }
            _ => {
                let c = rusqlite::Connection::open(&db).unwrap();
                c.execute_batch("PRAGMA locking_mode=EXCLUSIVE; BEGIN IMMEDIATE;")
                    .unwrap();
                locker = Some(c);
            }
        }
        let msgs = v.mock.message_count();
        let (_, s) = prep(&rt, &v);
        let out = match &s {
            Ok(s) => format!("WENT ON (rebuilt {})", s.rebuilt),
            Err(e) => format!("refused: {e:#}"),
        };
        drop(s);
        drop(locker);
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
        eprintln!("R3[{how}]: mount -> {out}");
        assert!(out.starts_with("refused"), "R3[{how}]: {out}");
        assert!(out.contains("refus"), "R3[{how}]: {out}");
        assert!(out.contains("Nothing was changed"), "R3[{how}]: {out}");
        assert_eq!(v.mock.message_count(), msgs, "R3[{how}]: uploaded");
        assert!(std::fs::read(&db).unwrap() == before, "R3[{how}]: metadata.db changed");
        let after: Vec<String> = ls_dir(&v)
            .into_iter()
            .filter(|n| !n.ends_with("-shm") && !n.ends_with("-wal"))
            .collect();
        let before_files: Vec<String> = files_before
            .into_iter()
            .filter(|n| !n.ends_with("-shm") && !n.ends_with("-wal"))
            .collect();
        assert_eq!(after, before_files, "R3[{how}]: files appeared or went");
        assert_eq!(local_names(&v), ["a", "b", "h", "thesis"], "R3[{how}]");
    }
}

/// `local_db_state` tells "corrupt" from "cannot be opened now": the second
/// is an error (never NeedsRebuild), with HEAD or without.
#[test]
fn r12_b2_local_db_state_errs_on_a_db_it_cannot_open_now() {
    use std::os::unix::fs::PermissionsExt as _;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    let db = v.open().paths.db_path.clone();
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o000)).unwrap();
    let st = local_db_state(&v.open());
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
    let e = st.expect_err("a DB that cannot be opened is not NeedsRebuild");
    eprintln!("B2 state, mode 000: {e:#}");
    assert!(format!("{e:#}").contains("cannot be opened"), "{e:#}");
    // Corrupt (not a database at all) still means rebuild.
    std::fs::write(&db, vec![0x5au8; 8192]).unwrap();
    assert!(matches!(
        local_db_state(&v.open()).unwrap(),
        LocalDb::NeedsRebuild(_)
    ));
}

/// A `volume restore` over a DB it cannot open renames it aside unread
/// (`metadata.db.unreadable.<time>`, byte-identical) before installing.
#[test]
fn r12_b2_a_restore_sets_an_unopenable_db_aside_unread() {
    use std::os::unix::fs::PermissionsExt as _;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    let db = v.open().paths.db_path.clone();
    let before = std::fs::read(&db).unwrap();
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o000)).unwrap();
    let res = restore(&rt, &v);
    for p in unreadable_copies(&v) {
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    res.expect("restore over a mode-000 DB");
    let aside = unreadable_copies(&v);
    assert_eq!(aside.len(), 1, "{:?}", ls_dir(&v));
    assert_eq!(std::fs::read(&aside[0]).unwrap(), before);
    assert_files_exact(&rt, &v, "B2: after the restore");
}

// ── N1: replaced DBs are kept, bounded, and reproducible ones are not ───────

/// rev_r2: after `volume restore` keeps the DB holding `thesis`, (a) an
/// ordinary later crash recovery and (b) a rebuild under a restore marker
/// still standing must not evict it.
#[test]
fn r12_n1_a_routine_rebuild_never_evicts_the_kept_copy() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    for how in ["later-crash-recovery", "marker-left-by-restore"] {
        let Some(v) = crashed_with_thesis(&rt) else { return };
        std::fs::remove_file(journal_head_path(&v.open())).unwrap();
        restore(&rt, &v).expect("R2: volume restore");
        assert!(thesis_kept(&v), "R2[{how}]: the restore kept no copy with thesis");
        match how {
            "later-crash-recovery" => {
                let (_, _s) = prep_ok(&rt, &v, "R2: session after restore");
                with_mount(&rt, &v, |mp| write_synced(mp, "notes", b"x")).unwrap();
                assert!(head_of(&v).seq > 0);
            }
            _ => teagarden_core::volume::rebuild_marker::mark(
                &v.open().paths.base_dir,
                "volume restore in progress",
            )
            .unwrap(),
        }
        let (_, s) = prep_ok(&rt, &v, "R2: next mount");
        assert!(s.rebuilt);
        eprintln!("R2[{how}]: kept copies {:?}", kept_copies(&v));
        assert!(thesis_kept(&v), "R2[{how}]: the copy with thesis was evicted");
    }
}

/// rev_r2c: the way back the keep message prints works: copy the kept file
/// over metadata.db, then `volume republish --from-local-db
/// --replace-newer-metadata` (`--force` alone refuses).
#[test]
fn r12_n1_the_way_back_from_a_kept_copy_works() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let Some(v) = crashed_with_thesis(&rt) else { return };
    std::fs::remove_file(journal_head_path(&v.open())).unwrap();
    restore(&rt, &v).expect("R2c: volume restore");
    let kept: Vec<_> = kept_copies(&v)
        .into_iter()
        .filter(|p| has_thesis(&v, p))
        .collect();
    assert_eq!(kept.len(), 1, "R2c: {:?}", ls_dir(&v));
    let r = v.open();
    metadata_snapshot::remove_db_files(&r.paths.db_path).unwrap();
    std::fs::copy(&kept[0], &r.paths.db_path).unwrap();
    let republish = |newer: bool| {
        rt.block_on(crate::commands::volume::republish_core(
            v.open(),
            v.mock.as_ref(),
            "rot",
            true,
            newer,
            &mut |_: &str| panic!("--force asks nothing"),
        ))
    };
    let e = republish(false).expect_err("R2c: --force alone republished");
    assert!(format!("{e:#}").contains("--replace-newer-metadata"), "{e:#}");
    assert!(republish(true).expect("R2c: republish"));
    assert_eq!(snapshot_names(&v).unwrap(), ["a", "b", "h", "thesis"]);
    let (_, s) = prep_ok(&rt, &v, "R2c: mount");
    assert!(!s.rebuilt);
    assert_eq!(local_names(&v), ["a", "b", "h", "thesis"]);
}

fn kill_restore_at(
    rt: &tokio::runtime::Runtime,
    v: &RotVol,
    step: crate::commands::volume::RestoreStep,
) {
    let killed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(crate::commands::volume::restore_core_at(
            v.open(),
            v.mock.as_ref(),
            "rot",
            None,
            true,
            true,
            &|s| {
                if s == step {
                    panic!("simulated kill at {s:?}");
                }
            },
        ))
    }));
    assert!(killed.is_err(), "restore never reached {step:?}");
}

/// rev_r9: after the no-HEAD refusal the user runs `volume restore`, and
/// then runs it again, or that first restore was killed at each of its
/// steps and the next mount finishes the job: `thesis` is still in a kept
/// copy at the end of every variant.
#[test]
fn r12_n1_a_second_or_killed_restore_never_evicts_the_kept_copy() {
    use crate::commands::volume::RestoreStep;
    let rt = tokio::runtime::Runtime::new().unwrap();
    for how in [
        "restore-twice",
        "MarkerWritten",
        "LocalDbRemoved",
        "HeadReset",
        "DbInstalled",
    ] {
        let Some(v) = crashed_with_thesis(&rt) else { return };
        std::fs::remove_file(journal_head_path(&v.open())).unwrap();
        match how {
            "restore-twice" => {
                restore(&rt, &v).expect("R9: restore 1");
                restore(&rt, &v).expect("R9: restore 2");
            }
            step => {
                let step = match step {
                    "MarkerWritten" => RestoreStep::MarkerWritten,
                    "LocalDbRemoved" => RestoreStep::LocalDbRemoved,
                    "HeadReset" => RestoreStep::HeadReset,
                    _ => RestoreStep::DbInstalled,
                };
                kill_restore_at(&rt, &v, step);
                let (_, s) = prep(&rt, &v);
                eprintln!(
                    "R9[{how}]: next mount -> {}",
                    match &s {
                        Ok(s) => format!("ok rebuilt {}", s.rebuilt),
                        Err(e) => format!("ERR {e:#}"),
                    }
                );
            }
        }
        eprintln!("R9[{how}]: files {:?}", ls_dir(&v));
        assert!(
            thesis_kept(&v) || has_thesis(&v, &v.open().paths.db_path),
            "R9[{how}]: thesis is gone: {:?}",
            ls_dir(&v)
        );
        assert!(thesis_kept(&v), "R9[{how}]: no kept copy holds thesis");
    }
}

/// The kept copies are bounded: at most three, the oldest removed first.
#[test]
fn r12_n1_kept_copies_are_capped_at_three_oldest_first() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    let r = v.open();
    let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
    let mut made = Vec::new();
    for i in 0..5u64 {
        // An older copy (another lineage), one entry more each round, so
        // every copy is distinguishable.
        {
            let c = local_db::open_existing(&r.paths.db_path).unwrap();
            InodeStore::new(&c, &schema, &r.hierarchy.meta)
                .insert(&Inode::new_file(50 + i, 1, format!("k{i}"), 0o644, 1, 1))
                .unwrap();
        }
        let other = local_db::DbStamp {
            volume_id: v.id.clone(),
            lineage: Lineage::new(1000 + i),
        };
        local_db::stamp_db_file(&r.paths.db_path, &schema, Some(&other)).unwrap();
        made.push(format!("k{i}"));
        let (_, s) = prep_ok(&rt, &v, "cap: rebuild");
        assert!(s.rebuilt);
    }
    let kept = kept_copies(&v);
    eprintln!("cap: {:?}", ls_dir(&v));
    assert_eq!(kept.len(), 3, "cap: {:?}", ls_dir(&v));
    // The newest three: they hold k2, k3, k4 (each the last one written).
    for (p, want) in kept.iter().zip(["k2", "k3", "k4"]) {
        let n = names_at(&v, p).unwrap();
        assert!(n.iter().any(|x| x == want), "cap: {p:?} holds {n:?}, want {want}");
    }
}

// ── N2: republish of an unstamped copy needs --replace-newer-metadata ───────

/// rev_r4: an UNSTAMPED older copy while journal.head records a lineage:
/// `--force` alone refuses (nothing uploaded, the newest snapshot keeps
/// `thesis`); `--replace-newer-metadata` publishes it.
#[test]
fn r12_n2_republish_of_an_unstamped_copy_needs_replace_newer() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    own_root(&v);
    clean_unmount(&rt, &v);
    let r = v.open();
    let db = r.paths.db_path.clone();
    let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
    let bak = v.dir.path().join("old-backup.db");
    std::fs::copy(&db, &bak).unwrap();
    local_db::stamp_db_file(&bak, &schema, None).unwrap();
    let backup = std::fs::read(&bak).unwrap();
    if with_mount(&rt, &v, |mp| write_synced(mp, "thesis", b"a month of work")).is_none() {
        return;
    }
    let (mut r, s) = prep_ok(&rt, &v, "R4: session 2");
    unmount_publish(&rt, &v, &mut r, s).expect("R4: unmount");
    assert!(head_of(&v).lineage.is_some());
    metadata_snapshot::remove_db_files(&db).unwrap();
    std::fs::write(&db, &backup).unwrap();
    let msgs = v.mock.message_count();
    let republish = |newer: bool| {
        rt.block_on(crate::commands::volume::republish_core(
            v.open(),
            v.mock.as_ref(),
            "rot",
            true,
            newer,
            &mut |_: &str| panic!("--force asks nothing"),
        ))
    };
    let out = match republish(false) {
        Ok(b) => format!("PUBLISHED ({b})"),
        Err(e) => format!("refused: {e:#}"),
    };
    eprintln!("R4: republish --force -> {out}");
    assert!(out.starts_with("refused"), "R4: {out}");
    assert!(out.contains("--replace-newer-metadata"), "R4: {out}");
    assert_eq!(v.mock.message_count(), msgs, "R4: uploaded");
    assert_eq!(snapshot_names(&v).unwrap(), ["a", "b", "h", "thesis"]);
    assert!(republish(true).expect("R4: --replace-newer-metadata"));
    assert_eq!(snapshot_names(&v).unwrap(), ["a", "b", "h"]);
}

// ── N3: a share's refusals name what works on a share ───────────────────────

/// rev_r5: (a) an unreadable journal.head on a share: the mount and the
/// offline check name `volume restore --discard-journal` (which works on a
/// share), never republish or a raw serialization message; (b) the owner's
/// snapshot gone while the share's DB must be rebuilt: the mount names the
/// re-import procedure, never republish.
#[test]
fn r12_n3_share_refusals_name_what_works_on_a_share() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let owner = rot_volume(&rt);
    let share = read_only_share_of(&owner);
    mount_session(&rt, &share, "R5a: first mount").unwrap();
    std::fs::write(journal_head_path(&share.open()), b"{not a head").unwrap();
    let (_, s) = prep(&rt, &share);
    let e = format!("{:#}", s.err().expect("R5a: the mount went on"));
    eprintln!("R5a: mount: {e}");
    assert!(!e.contains("republish"), "R5a: {e}");
    assert!(e.contains("teagarden volume restore rot --discard-journal"), "R5a: {e}");
    let off = crate::commands::volume::offline_mount_check(&share.open(), "rot", true)
        .expect_err("R5a: offline went on");
    let off = format!("{off:#}");
    eprintln!("R5a: offline: {off}");
    assert!(!off.contains("republish"), "R5a: {off}");
    assert!(!off.starts_with("serialization error"), "R5a: {off}");
    assert!(off.contains("journal HEAD"), "R5a: {off}");
    assert!(off.contains("--discard-journal"), "R5a: {off}");
    restore(&rt, &share).expect("R5a: restore --discard-journal on the share");
    let (_, s) = prep(&rt, &share);
    s.expect("R5a: mount after restore");
    // (b)
    let owner = rot_volume(&rt);
    let share = read_only_share_of(&owner);
    mount_session(&rt, &share, "R5b: first mount").unwrap();
    let snap = share.open().config.metadata_snapshot_id.unwrap();
    metadata_snapshot::remove_db_files(&share.open().paths.db_path).unwrap();
    owner.mock.drop_message(snap);
    let (_, s) = prep(&rt, &share);
    let e = format!("{:#}", s.err().expect("R5b: the mount went on"));
    eprintln!("R5b: mount: {e}");
    assert!(!e.contains("republish"), "R5b: {e}");
    assert!(e.contains("ask the owner for a new grant"), "R5b: {e}");
    assert!(e.contains("--local-only"), "R5b: {e}");
    assert!(e.contains("share import"), "R5b: {e}");
}

// ── B3: every share is read-only ────────────────────────────────────────────

/// rev_r12: a share whose shared_origin.json says read-write (as `share
/// grant`'s old default made it) is a read-only share: its mounts upload
/// nothing into the owner's topic and journal nothing, and its `key rotate`,
/// revert, republish and publish refuse; none of the owner's block messages
/// is deleted and the owner reads every file back.
#[test]
fn r12_b3_a_read_write_share_on_disk_never_writes_into_the_owners_topic() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let owner = rot_volume(&rt);
    clean_unmount(&rt, &owner);
    let mut share = read_only_share_of(&owner);
    teagarden_core::volume::shared::SharedOrigin {
        derivation: teagarden_core::volume::shared::SharedDerivation::HierarchyRootV1,
        access_level: "read-write".into(),
        granted_by: "owner".into(),
        volume_id: owner.id.clone(),
    }
    .save(&share.dir.path().join(&share.id))
    .unwrap();
    share.pre_rotation_msgs = owner.pre_rotation_msgs.clone();
    let before = owner.mock.message_count();
    for session in ["first", "second"] {
        let journal = mount_session(&rt, &share, &format!("R12: {session} mount"))
            .unwrap_or_else(|e| panic!("R12: {session} mount: {e:#}"));
        assert!(!journal, "R12: the rw share's {session} mount journals");
        assert_eq!(
            owner.mock.message_count(),
            before,
            "R12: the rw share's {session} session uploaded into the owner's topic"
        );
    }
    assert_files_exact(&rt, &share, "R12: the share reads the owner's files");
    let gone = |o: &RotVol| {
        o.pre_rotation_msgs
            .iter()
            .filter(|id| o.mock.get_raw(**id).is_none())
            .count()
    };
    let gone_before = gone(&owner);
    let e = rotate_with(&rt, &share, &|_| {}).expect_err("R12: the rw share rotated");
    assert!(format!("{e:#}").contains("`teagarden key rotate`"), "{e:#}");
    let gone_after = gone(&owner);
    eprintln!(
        "R12: owner's block messages gone {gone_before} -> {gone_after} of {}",
        owner.pre_rotation_msgs.len()
    );
    assert_eq!((gone_before, gone_after), (0, 0));
    let e = rt
        .block_on(crate::commands::volume::revert_core(
            share.open(),
            share.transport(),
            "/h",
            1,
        ))
        .expect_err("R12: the rw share reverted");
    assert!(format!("{e:#}").contains("`teagarden volume revert`"), "{e:#}");
    let e = rt
        .block_on(crate::commands::volume::republish_core(
            share.open(),
            share.mock.as_ref(),
            "rot",
            true,
            true,
            &mut |_: &str| Ok(true),
        ))
        .expect_err("R12: the rw share republished");
    assert!(format!("{e:#}").contains("`teagarden volume republish`"), "{e:#}");
    let mut r = share.open();
    rt.block_on(crate::commands::volume::publish_as_new_session(
        &mut r,
        share.mock.as_ref(),
    ))
    .expect_err("R12: the rw share published");
    assert_eq!(owner.mock.message_count(), before, "R12: uploaded");
    let (_, s) = prep_ok(&rt, &owner, "R12: owner mount");
    assert!(!s.rebuilt);
    assert_files_exact(&rt, &owner, "R12: the owner after the share's commands");
}

/// The way back copies only the kept main file, so a kept copy must be
/// self-contained: a replaced DB whose newest rows are still only in its WAL
/// (a crash before any checkpoint) is checkpointed before it is kept.
#[test]
fn r12_n1_a_kept_copy_holds_what_was_only_in_the_wal() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let Some(v) = crashed_with_thesis(&rt) else { return };
    let r = v.open();
    let db = r.paths.db_path.clone();
    let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
    let (main, wal) = {
        let c = local_db::open_existing(&db).unwrap();
        c.execute_batch("PRAGMA wal_autocheckpoint=0;").unwrap();
        InodeStore::new(&c, &schema, &r.hierarchy.meta)
            .insert(&Inode::new_file(77, 1, "walonly".into(), 0o644, 1000, 1000))
            .unwrap();
        (std::fs::read(&db).unwrap(), std::fs::read(sidecar(&db, "-wal")).unwrap())
    };
    // The process "crashed": the main file without the row, the WAL with it.
    std::fs::write(&db, &main).unwrap();
    std::fs::write(sidecar(&db, "-wal"), &wal).unwrap();
    let _ = std::fs::remove_file(sidecar(&db, "-shm"));
    assert!(names_at(&v, &db).unwrap().iter().any(|n| n == "walonly"));
    restore(&rt, &v).expect("WAL: restore --discard-journal");
    let kept: Vec<_> = kept_copies(&v)
        .into_iter()
        .filter(|p| names_at(&v, p).is_ok_and(|n| n.iter().any(|x| x == "walonly")))
        .collect();
    assert_eq!(kept.len(), 1, "WAL: {:?}", ls_dir(&v));
    // The main file alone, as the way back copies it.
    let alone = v.dir.path().join("kept-main-only.db");
    std::fs::copy(&kept[0], &alone).unwrap();
    let n = names_at(&v, &alone).unwrap();
    eprintln!("WAL: the kept main file alone holds {n:?}");
    assert!(n.iter().any(|x| x == "walonly"), "WAL: the kept copy is not self-contained");
    assert!(n.iter().any(|x| x == "thesis"));
}

/// A session that started with a journal HEAD refuses to publish when the
/// HEAD is gone at publish time, even with its own database untouched: no
/// journal position can be proven (the D3 exception rev_r8 used).
#[test]
fn r12_b1_a_session_that_started_with_a_head_refuses_without_one() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    let (mut r, s) = prep_ok(&rt, &v, "no HEAD: session");
    std::fs::remove_file(journal_head_path(&v.open())).unwrap();
    let msgs = v.mock.message_count();
    let e = unmount_publish(&rt, &v, &mut r, s).expect_err("no HEAD: published");
    eprintln!("no HEAD: {e:#}");
    assert!(format!("{e:#}").contains("journal.head) was removed"), "{e:#}");
    assert_eq!(v.mock.message_count(), msgs);
    assert!(!journal_head_path(&v.open()).exists());
}

/// Routine crash recoveries replace a DB at the HEAD's lineage and journal
/// position, which the replay reproduces: they keep no copy, so they never
/// use up the bounded copies (the one holding `thesis` survives any number
/// of them).
#[test]
fn r12_n1_routine_crash_recoveries_keep_no_copy() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let Some(v) = crashed_with_thesis(&rt) else { return };
    std::fs::remove_file(journal_head_path(&v.open())).unwrap();
    restore(&rt, &v).expect("routine: restore");
    assert_eq!(kept_copies(&v).len(), 1);
    for i in 0..4 {
        let (_, _s) = prep_ok(&rt, &v, "routine: session");
        with_mount(&rt, &v, |mp| write_synced(mp, &format!("n{i}"), b"x")).unwrap();
        assert!(head_of(&v).seq > 0);
        let (_, s) = prep_ok(&rt, &v, "routine: crash recovery");
        assert!(s.rebuilt);
    }
    eprintln!("routine: {:?}", ls_dir(&v));
    assert_eq!(kept_copies(&v).len(), 1, "routine: {:?}", ls_dir(&v));
    assert!(thesis_kept(&v));
}

/// RD1u (round-11 survivor): the no-HEAD refusal holds for a readable DB
/// with only three entries below the root (every earlier test had four).
#[test]
fn r12_d1_a_small_readable_db_without_a_head_is_refused() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    std::fs::remove_file(journal_head_path(&v.open())).unwrap();
    assert_eq!(local_tree(&v).entries, 3);
    assert_mount_refuses_naming_both_ways_out(&rt, &v, "D1 (3 entries)");
}

/// rev_r14 (RD2v): republish refuses a DB stamped as another volume's, with
/// every flag, with and without journal.head; nothing is uploaded.
#[test]
fn r12_republish_refuses_another_volumes_stamp() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    for with_head in [true, false] {
        let v = rot_volume(&rt);
        let r = v.open();
        let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
        let other = local_db::DbStamp {
            volume_id: "00000000-0000-4000-8000-000000000000".into(),
            lineage: head_of(&v).lineage.unwrap(),
        };
        local_db::stamp_db_file(&r.paths.db_path, &schema, Some(&other)).unwrap();
        if !with_head {
            std::fs::remove_file(journal_head_path(&r)).unwrap();
        }
        let msgs = v.mock.message_count();
        let e = rt
            .block_on(crate::commands::volume::republish_core(
                v.open(),
                v.mock.as_ref(),
                "rot",
                true,
                true,
                &mut |_: &str| Ok(true),
            ))
            .expect_err("R14: republished another volume's DB");
        eprintln!("R14[head {with_head}]: {e:#}");
        assert!(format!("{e:#}").contains("another volume"), "{e:#}");
        assert_eq!(v.mock.message_count(), msgs, "R14[head {with_head}]: uploaded");
    }
}

/// RD3h (round-11 survivor): journal.head damaged during the session: the
/// publish refuses and uploads nothing.
#[test]
fn r12_b1_a_head_damaged_during_the_session_refuses_the_publish() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    let (mut r, s) = prep_ok(&rt, &v, "damaged HEAD: session");
    std::fs::write(journal_head_path(&v.open()), b"{not a head").unwrap();
    let msgs = v.mock.message_count();
    let e = unmount_publish(&rt, &v, &mut r, s).expect_err("damaged HEAD: published");
    eprintln!("damaged HEAD: {e:#}");
    assert!(format!("{e:#}").contains("journal HEAD cannot be read"), "{e:#}");
    assert_eq!(v.mock.message_count(), msgs);
}

/// RO1 (round-11 survivor): a share whose HEAD has entries past its base
/// (as an earlier build's share mount could leave it), with a DB at that
/// same position, never mounts offline.
#[test]
fn r12_a_share_with_journal_entries_never_mounts_offline() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let owner = rot_volume(&rt);
    let share = read_only_share_of(&owner);
    mount_session(&rt, &share, "RO1: first mount").unwrap();
    let r = share.open();
    let mut h = head_of(&share);
    h.seq = 3;
    h.store_atomic(&journal_head_path(&r), &r.hierarchy.integrity)
        .unwrap();
    {
        let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
        let c = local_db::open_existing(&r.paths.db_path).unwrap();
        local_db::set_session_seq(&c, &schema, 3).unwrap();
    }
    assert_eq!(local_db_state(&share.open()).unwrap(), LocalDb::Usable);
    let e = crate::commands::volume::offline_mount_check(&share.open(), "rot", true)
        .expect_err("RO1: offline with journal entries");
    assert!(format!("{e:#}").contains("journaled"), "{e:#}");
}

/// RD3r (round-11 survivor): a file renamed into place after the publish's
/// checks and stamp, right before it reads the snapshot's bytes, is caught
/// by the identity check on the read handle: nothing is uploaded.
#[test]
fn r12_b1_a_db_swapped_right_before_the_read_is_not_published() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    let db = v.open().paths.db_path.clone();
    let (mut r, s) = prep_ok(&rt, &v, "swap: session");
    let copy = std::fs::read(&db).unwrap();
    let tmp = v.dir.path().join("swap.db");
    let (db2, tmp2) = (db.clone(), tmp.clone());
    crate::commands::volume::BEFORE_SNAPSHOT_READ.with(|h| {
        *h.borrow_mut() = Some(Box::new(move || {
            std::fs::write(&tmp2, &copy).unwrap();
            std::fs::rename(&tmp2, &db2).unwrap();
        }))
    });
    let msgs = v.mock.message_count();
    let e = unmount_publish(&rt, &v, &mut r, s).expect_err("swap: published");
    eprintln!("swap: {e:#}");
    assert!(format!("{e:#}").contains("not the metadata database this session opened"), "{e:#}");
    assert_eq!(v.mock.message_count(), msgs, "swap: uploaded");
    assert!(!tmp.exists());
}
