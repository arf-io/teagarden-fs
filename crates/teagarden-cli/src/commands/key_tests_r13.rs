// Round 13: the round-12 review's findings (rvw_f1, rvw_f1b, rvw_f2, rvw_f3)
// as asserting regression tests, and its no-false-positive check (rvw_f4)
// (included into key.rs `tests::r8::real_fuse::r10`, after
// `key_tests_r12.rs`).

/// Whether the main DB file's bytes differ from `start`.
fn r13_main_differs(db: &Path, start: &[u8]) -> bool {
    std::fs::read(db).unwrap() != start
}

/// Rewrite `name` in place (same length; truncated first when `truncate`)
/// and fsync it: an acknowledged write.
fn r13_rewrite(mp: &Path, name: &str, data: &[u8], truncate: bool) {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(truncate)
        .open(mp.join(name))
        .unwrap();
    f.write_all(data).unwrap();
    f.sync_all().unwrap();
}

fn r13_outcome(res: &Result<()>) -> String {
    match res {
        Ok(()) => "PUBLISHED".to_string(),
        Err(e) => format!("REFUSED: {e:#}"),
    }
}

/// What reading `thesis` through the next mount gave, against the
/// acknowledged bytes.
fn r13_verdict(got: &std::io::Result<Vec<u8>>, acknowledged: &[u8]) -> String {
    match got {
        Ok(b) if b == acknowledged => "the acknowledged bytes".to_string(),
        Ok(b) => format!(
            "{} bytes, NOT the acknowledged {} (first 8: {:?})",
            b.len(),
            acknowledged.len(),
            &b[..b.len().min(8)]
        ),
        Err(e) => format!("READ ERROR: {e}"),
    }
}

/// The round-12 review's F1: `cp backup metadata.db` in place, mid-session,
/// after the main file was checkpointed (the session's WAL then holds this
/// session's nonce and the HEAD's seq, the main file a same-lineage backup).
/// Every variant must end REFUSED (HEAD seq > 0 left as it was, nothing
/// uploaded, the next mount rebuilds) or published, and either way `thesis`
/// must read back the last acknowledged bytes through the next mount.
#[test]
fn r13_rvw_f1_inplace_cp_after_a_checkpoint_never_loses_acknowledged_bytes() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut failures = Vec::new();
    for how in [
        "backup-in-session/notrunc",
        "backup-before-mount/notrunc",
        "backup-in-session/trunc",
        "backup-before-mount/trunc",
    ] {
        let truncate = how.ends_with("/trunc");
        let v = rot_volume(&rt);
        own_root(&v);
        clean_unmount(&rt, &v);
        let db = v.open().paths.db_path.clone();
        // Session A: thesis v0 exists and is published.
        let v0 = vec![b'0'; 6000];
        let (mut r, s) = prep_ok(&rt, &v, "F1: session A");
        if with_mount(&rt, &v, |mp| {
            write_synced(mp, "thesis", &v0);
            write_synced(mp, "mine", b"m");
        })
        .is_none()
        {
            return;
        }
        unmount_publish(&rt, &v, &mut r, s).expect("F1: session A unmount");
        let before_mount = std::fs::read(&db).unwrap();
        // Session B.
        let (mut r, s) = prep_ok(&rt, &v, "F1: session B");
        let in_session = std::fs::read(&db).unwrap();
        let backup = if how.starts_with("backup-in-session") {
            in_session.clone()
        } else {
            before_mount
        };
        let mut last = v0.clone();
        let mut rewrites = 0;
        let mut checkpointed = false;
        with_mount(&rt, &v, |mp| {
            for i in 0..3000u32 {
                last = vec![b'a' + (i % 26) as u8; 6000];
                r13_rewrite(mp, "thesis", &last, truncate);
                rewrites += 1;
                if r13_main_differs(&db, &in_session) {
                    checkpointed = true;
                    break;
                }
            }
            // One unrelated journaled change after the checkpoint.
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(mp.join("mine"), std::fs::Permissions::from_mode(0o600))
                .unwrap();
            // The user restores the backup the way `cp` does.
            overwrite_in_place(&db, &backup);
        })
        .unwrap();
        assert!(
            checkpointed,
            "F1[{how}]: the main file was never checkpointed in {rewrites} rewrites"
        );
        let seq_before = head_of(&v).seq;
        let msgs = v.mock.message_count();
        let res = unmount_publish(&rt, &v, &mut r, s);
        let uploaded = v.mock.message_count() - msgs;
        let seq_now = head_of(&v).seq;
        eprintln!(
            "F1[{how}]: rewrites {rewrites}; main file checkpointed {checkpointed}; HEAD seq \
             before {seq_before}; unmount publish -> {}; uploaded {uploaded}; HEAD seq now \
             {seq_now}",
            r13_outcome(&res)
        );
        let (_r2, next) = prep_ok(&rt, &v, "F1: next mount");
        let mut got = None;
        with_mount(&rt, &v, |mp| got = Some(std::fs::read(mp.join("thesis")))).unwrap();
        let got = got.unwrap();
        eprintln!(
            "F1[{how}]: next mount rebuilt {}; thesis reads -> {}",
            next.rebuilt,
            r13_verdict(&got, &last)
        );
        let safe_refusal =
            res.is_err() && uploaded == 0 && seq_before > 0 && seq_now == seq_before && next.rebuilt;
        let ok = matches!(&got, Ok(b) if *b == last) && (res.is_ok() || safe_refusal);
        eprintln!("F1[{how}]: RESULT {}", if ok { "SAFE" } else { "DATA LOSS" });
        if !ok {
            failures.push(how);
        }
    }
    assert!(failures.is_empty(), "F1: data loss in {failures:?}");
}

/// The round-12 review's F1b: no auto-checkpoint needed. A backup taken after
/// a clean unmount; a session writes `thesis` and crashes; the next session
/// replays the journal, makes one small change (or none), and the backup is
/// copied over metadata.db in place.
#[test]
fn r13_rvw_f1b_inplace_cp_after_a_crash_recovery_never_loses_acknowledged_bytes() {
    use std::os::unix::fs::PermissionsExt as _;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut failures = Vec::new();
    for how in ["chmod-mine", "write-notes", "no-change"] {
        let v = rot_volume(&rt);
        own_root(&v);
        clean_unmount(&rt, &v);
        let db = v.open().paths.db_path.clone();
        let (mut r0, s0) = prep_ok(&rt, &v, "F1b: session 0");
        if with_mount(&rt, &v, |mp| write_synced(mp, "mine", b"m")).is_none() {
            return;
        }
        unmount_publish(&rt, &v, &mut r0, s0).expect("F1b: session 0 unmount");
        // The backup: metadata.db as the clean unmount left it.
        let backup = std::fs::read(&db).unwrap();
        let thesis: Vec<u8> = (0..6000u32).map(|i| (i % 251) as u8).collect();
        // Session 1: writes thesis (acknowledged, journaled), then crashes.
        let (_r, _s) = prep_ok(&rt, &v, "F1b: session 1");
        with_mount(&rt, &v, |mp| write_synced(mp, "thesis", &thesis)).unwrap();
        assert!(head_of(&v).seq > 0);
        // Session 2: crash recovery, a small change, then `cp backup metadata.db`.
        let (mut r, s) = prep_ok(&rt, &v, "F1b: session 2");
        assert!(s.rebuilt);
        let mut read_in_session = None;
        with_mount(&rt, &v, |mp| {
            read_in_session = Some(std::fs::read(mp.join("thesis")).map(|b| b == thesis));
            match how {
                "chmod-mine" => std::fs::set_permissions(
                    mp.join("mine"),
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap(),
                "write-notes" => write_synced(mp, "notes", b"x"),
                _ => {}
            }
            overwrite_in_place(&db, &backup);
        })
        .unwrap();
        assert!(
            matches!(read_in_session, Some(Ok(true))),
            "F1b[{how}]: thesis did not read back in session 2: {read_in_session:?}"
        );
        let seq_before = head_of(&v).seq;
        let msgs = v.mock.message_count();
        let res = unmount_publish(&rt, &v, &mut r, s);
        let uploaded = v.mock.message_count() - msgs;
        let seq_now = head_of(&v).seq;
        eprintln!(
            "F1b[{how}]: HEAD seq before {seq_before}; unmount publish -> {}; uploaded \
             {uploaded}; HEAD seq now {seq_now}",
            r13_outcome(&res)
        );
        let (_r2, next) = prep_ok(&rt, &v, "F1b: next mount");
        let mut got = None;
        with_mount(&rt, &v, |mp| got = Some(std::fs::read(mp.join("thesis")))).unwrap();
        let got = got.unwrap();
        eprintln!(
            "F1b[{how}]: next mount rebuilt {}; reading thesis -> {}",
            next.rebuilt,
            r13_verdict(&got, &thesis)
        );
        let safe_refusal =
            res.is_err() && uploaded == 0 && seq_before > 0 && seq_now == seq_before && next.rebuilt;
        let ok = matches!(&got, Ok(b) if *b == thesis) && (res.is_ok() || safe_refusal);
        eprintln!("F1b[{how}]: RESULT {}", if ok { "SAFE" } else { "DATA LOSS" });
        if !ok {
            failures.push(how);
        }
    }
    assert!(failures.is_empty(), "F1b: data loss in {failures:?}");
}

/// The round-12 review's F2: an in-place overwrite after the publish's
/// checks and stamp, before the snapshot's bytes are read. The publish must
/// upload nothing and leave the HEAD as it was; the next mount must hold
/// `thesis`.
#[test]
fn r13_rvw_f2_inplace_overwrite_before_the_snapshot_read_uploads_nothing() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut failures = Vec::new();
    for how in ["older-copy", "garbage"] {
        let v = rot_volume(&rt);
        own_root(&v);
        clean_unmount(&rt, &v);
        let db = v.open().paths.db_path.clone();
        let older = if how == "garbage" {
            vec![0x5au8; 8192]
        } else {
            std::fs::read(&db).unwrap()
        };
        let (mut r, s) = prep_ok(&rt, &v, "F2: session");
        if with_mount(&rt, &v, |mp| write_synced(mp, "thesis", b"a month of work")).is_none() {
            return;
        }
        let seq_before = head_of(&v).seq;
        let db2 = db.clone();
        crate::commands::volume::BEFORE_SNAPSHOT_READ.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || overwrite_in_place(&db2, &older)))
        });
        let msgs = v.mock.message_count();
        let res = unmount_publish(&rt, &v, &mut r, s);
        let uploaded = v.mock.message_count() - msgs;
        let seq_now = head_of(&v).seq;
        eprintln!(
            "F2[{how}]: HEAD seq before {seq_before}; unmount publish -> {}; uploaded \
             {uploaded}; HEAD seq now {seq_now}",
            r13_outcome(&res)
        );
        let (_r2, next) = prep_ok(&rt, &v, "F2: next mount");
        let mut got = None;
        with_mount(&rt, &v, |mp| got = Some(std::fs::read(mp.join("thesis")))).unwrap();
        let got = got.unwrap();
        eprintln!(
            "F2[{how}]: next mount rebuilt {}; thesis reads -> {}",
            next.rebuilt,
            r13_verdict(&got, b"a month of work")
        );
        let held = matches!(&got, Ok(b) if b == b"a month of work");
        let ok = res.is_err() && uploaded == 0 && seq_now == seq_before && next.rebuilt && held;
        eprintln!("F2[{how}]: RESULT {}", if ok { "SAFE" } else { "UNSAFE" });
        if !ok {
            failures.push(how);
        }
    }
    assert!(failures.is_empty(), "F2: unsafe in {failures:?}");
}

/// The round-12 review's F3: `volume restore` keeps the only copy holding
/// `thesis`; four unmounts are then killed during the snapshot upload (after
/// the stamp). The DB each leaves is reproducible from Telegram and must not
/// use up a kept copy, so `thesis` stays kept.
#[test]
fn r13_rvw_f3_killed_unmounts_never_evict_the_only_copy() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let Some(v) = crashed_with_thesis(&rt) else {
        return;
    };
    std::fs::remove_file(journal_head_path(&v.open())).unwrap();
    restore(&rt, &v).expect("F3: volume restore");
    eprintln!(
        "F3: after restore: kept {}; thesis kept {}",
        kept_copies(&v).len(),
        thesis_kept(&v)
    );
    assert!(thesis_kept(&v));
    for i in 0..4 {
        let (mut r, s) = prep_ok(&rt, &v, "F3: session");
        eprintln!(
            "F3: mount {i}: rebuilt {}; kept copies {}; thesis kept {}; local names {:?}",
            s.rebuilt,
            kept_copies(&v).len(),
            thesis_kept(&v),
            local_names(&v)
        );
        assert!(
            thesis_kept(&v),
            "F3: the only copy holding thesis was EVICTED after {i} killed unmount(s): {:?}",
            ls_dir(&v)
        );
        with_mount(&rt, &v, |mp| write_synced(mp, &format!("n{i}"), b"x")).unwrap();
        crate::commands::volume::BEFORE_SNAPSHOT_READ.with(|h| {
            *h.borrow_mut() = Some(Box::new(|| panic!("simulated kill during the snapshot upload")))
        });
        let killed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = unmount_publish(&rt, &v, &mut r, s);
        }));
        assert!(killed.is_err(), "F3: the kill hook did not run");
    }
    let (_r, s) = prep_ok(&rt, &v, "F3: mount after the fourth kill");
    eprintln!(
        "F3: after 4 killed unmounts: rebuilt {}; kept copies {}; thesis kept {}; local names \
         {:?}",
        s.rebuilt,
        kept_copies(&v).len(),
        thesis_kept(&v),
        local_names(&v)
    );
    assert!(thesis_kept(&v), "F3: thesis evicted: {:?}", ls_dir(&v));
    assert_eq!(local_names(&v), ["a", "b", "h", "n0", "n1", "n2", "n3"]);
    let mut got = vec![];
    with_mount(&rt, &v, |mp| {
        for i in 0..4 {
            got.push(std::fs::read(mp.join(format!("n{i}"))).unwrap());
        }
    })
    .unwrap();
    assert!(got.iter().all(|b| b == b"x"), "F3: n0..n3 read back {got:?}");
    drop(s);
    // The documented way back from the kept copy: copy it over metadata.db,
    // then `volume republish --from-local-db --replace-newer-metadata`.
    let kept = kept_copies(&v)
        .into_iter()
        .find(|p| has_thesis(&v, p))
        .unwrap();
    let db = v.open().paths.db_path.clone();
    metadata_snapshot::remove_db_files(&db).unwrap();
    std::fs::copy(&kept, &db).unwrap();
    rt.block_on(crate::commands::volume::republish_core(
        v.open(),
        v.mock.as_ref(),
        "rot",
        true,
        true,
        &mut |_: &str| panic!("--force asks nothing"),
    ))
    .expect("F3: republish of the kept copy");
    let (_r, back) = prep_ok(&rt, &v, "F3: mount after the way back");
    let mut thesis = None;
    with_mount(&rt, &v, |mp| thesis = Some(std::fs::read(mp.join("thesis")))).unwrap();
    let thesis = thesis.unwrap();
    eprintln!(
        "F3: after the way back: rebuilt {}; thesis reads -> {}",
        back.rebuilt,
        r13_verdict(&thesis, b"a month of work")
    );
    assert!(matches!(&thesis, Ok(b) if b == b"a month of work"));
}

/// rvw_f4's first-mount leg: a new volume's first mount (base snapshot
/// publish while the session's connection is open), writes through the
/// mount, its unmount publish goes through, and the next mount serves the
/// published DB without a rebuild, with the bytes written.
#[test]
fn r13_rvw_f4_a_first_mount_publishes() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = super::super::r9::new_volume();
    let (mut r, mut s) = prep_ok(&rt, &v, "F4: first mount");
    rt.block_on(journal_init_phase(&mut r, v.mock.as_ref(), &mut s.db))
        .unwrap_or_else(|e| panic!("F4: first mount's base publish: {e:#}"));
    let body: Vec<u8> = (0..20_000u32).map(|i| (i % 253) as u8).collect();
    if with_mount(&rt, &v, |mp| write_synced(mp, "first", &body)).is_none() {
        return;
    }
    unmount_publish(&rt, &v, &mut r, s).unwrap_or_else(|e| panic!("F4: first unmount: {e:#}"));
    let (_r, next) = prep_ok(&rt, &v, "F4: second mount");
    assert!(!next.rebuilt, "F4: the mount after a first mount rebuilt");
    let mut got = None;
    with_mount(&rt, &v, |mp| got = Some(std::fs::read(mp.join("first")))).unwrap();
    let got = got.unwrap();
    eprintln!("F4: first mount: file reads -> {}", r13_verdict(&got, &body));
    assert!(matches!(&got, Ok(b) if *b == body));
}

/// The round-12 review's F4: legitimate sessions never refuse their own
/// publish (two mounts in a row, a crash and remount with and without a
/// write, revert after a mount, rotate, a mount after rotate).
#[test]
fn r13_rvw_f4_legitimate_sessions_publish() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut v = rot_volume(&rt);
    own_root(&v);
    clean_unmount(&rt, &v);
    for i in 0..2 {
        let (mut r, s) = prep_ok(&rt, &v, "F4: mount");
        assert!(!s.rebuilt, "F4: clean mount {i} rebuilt");
        if with_mount(&rt, &v, |mp| write_synced(mp, &format!("m{i}"), b"x")).is_none() {
            return;
        }
        unmount_publish(&rt, &v, &mut r, s)
            .unwrap_or_else(|e| panic!("F4: mount {i} unmount: {e:#}"));
    }
    // A crash, then a remount that writes and unmounts cleanly.
    let (_r, _s) = prep_ok(&rt, &v, "F4: crashing session");
    with_mount(&rt, &v, |mp| write_synced(mp, "c", b"x")).unwrap();
    let (mut r, s) = prep_ok(&rt, &v, "F4: remount after crash");
    eprintln!("F4: remount after crash rebuilt {}", s.rebuilt);
    with_mount(&rt, &v, |mp| write_synced(mp, "d", b"x")).unwrap();
    unmount_publish(&rt, &v, &mut r, s).unwrap_or_else(|e| panic!("F4: after crash: {e:#}"));
    // A crash, then a remount with NO write, clean unmount.
    let (_r, _s) = prep_ok(&rt, &v, "F4: crashing session 2");
    with_mount(&rt, &v, |mp| write_synced(mp, "e", b"x")).unwrap();
    let (mut r, s) = prep_ok(&rt, &v, "F4: remount 2");
    unmount_publish(&rt, &v, &mut r, s)
        .unwrap_or_else(|e| panic!("F4: after crash 2, no write: {e:#}"));
    // Revert after a mount.
    rt.block_on(crate::commands::volume::revert_core(
        v.open(),
        v.transport(),
        "/h",
        1,
    ))
    .unwrap_or_else(|e| panic!("F4: revert: {e:#}"));
    v.expect.insert(4, v.h_versions[0].clone());
    // Rotate.
    rotate_with(&rt, &v, &|_| {}).unwrap_or_else(|e| panic!("F4: rotate: {e:#}"));
    let (mut r, s) = prep_ok(&rt, &v, "F4: mount after rotate");
    eprintln!("F4: mount after rotate rebuilt {}", s.rebuilt);
    assert!(!s.rebuilt, "F4: the mount after rotate rebuilt");
    with_mount(&rt, &v, |mp| write_synced(mp, "z", b"x")).unwrap();
    unmount_publish(&rt, &v, &mut r, s).unwrap_or_else(|e| panic!("F4: after rotate: {e:#}"));
    // And the next mount serves the published DB as it is.
    let (_r, s) = prep_ok(&rt, &v, "F4: last mount");
    assert!(!s.rebuilt, "F4: the last mount rebuilt");
    assert!(
        teagarden_core::volume::rebuild_marker::load(&v.open().paths.base_dir)
            .unwrap()
            .is_none(),
        "F4: a rebuild marker was left"
    );
    let mut names = local_names(&v);
    names.sort();
    eprintln!("F4: RESULT every legitimate publish went through; names {names:?}");
    assert_eq!(names, ["a", "b", "c", "d", "e", "h", "m0", "m1", "z"]);
}

/// A legitimate session long enough to fill the WAL past the session's own
/// checkpoint threshold: the session checkpoints the main file itself (the
/// main file changes mid-session) and its publish still goes through, the
/// next mount serves the published DB without a rebuild, and `thesis` reads
/// back the last acknowledged bytes.
#[test]
fn r13_a_long_session_checkpoints_itself_and_publishes() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    own_root(&v);
    clean_unmount(&rt, &v);
    let db = v.open().paths.db_path.clone();
    let (mut r, s) = prep_ok(&rt, &v, "long session");
    let start = std::fs::read(&db).unwrap();
    let mut last = vec![];
    let mut rewrites = 0;
    let mut checkpointed = false;
    if with_mount(&rt, &v, |mp| {
        write_synced(mp, "thesis", b"first");
        for i in 0..3000u32 {
            last = vec![b'a' + (i % 26) as u8; 6000];
            r13_rewrite(mp, "thesis", &last, true);
            rewrites += 1;
            if r13_main_differs(&db, &start) {
                checkpointed = true;
            }
            // A few more journaled writes after the checkpoint.
            if checkpointed && rewrites % 5 == 0 {
                break;
            }
        }
    })
    .is_none()
    {
        return;
    }
    eprintln!("long session: {rewrites} rewrites; main file checkpointed mid-session {checkpointed}");
    assert!(checkpointed, "the session never checkpointed the main file");
    unmount_publish(&rt, &v, &mut r, s).unwrap_or_else(|e| panic!("long session: {e:#}"));
    let (_r, next) = prep_ok(&rt, &v, "long session: next mount");
    assert!(!next.rebuilt, "the next mount rebuilt a legitimately published DB");
    let mut got = None;
    with_mount(&rt, &v, |mp| got = Some(std::fs::read(mp.join("thesis")))).unwrap();
    let got = got.unwrap();
    eprintln!("long session: thesis reads -> {}", r13_verdict(&got, &last));
    assert!(matches!(&got, Ok(b) if *b == last));
}

/// D2: the bytes uploaded are the bytes checked. An in-place overwrite after
/// the publish's content checks, before its upload, changes nothing that is
/// uploaded: the snapshot holds `thesis` (the bytes the publish read and
/// checked), and the next mount serves them.
#[test]
fn r13_an_overwrite_after_the_checks_is_not_what_is_uploaded() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut failures = Vec::new();
    for how in ["older-copy", "garbage"] {
        let v = rot_volume(&rt);
        own_root(&v);
        clean_unmount(&rt, &v);
        let db = v.open().paths.db_path.clone();
        let older = if how == "garbage" {
            vec![0x5au8; 8192]
        } else {
            std::fs::read(&db).unwrap()
        };
        let (mut r, s) = prep_ok(&rt, &v, "D2: session");
        if with_mount(&rt, &v, |mp| write_synced(mp, "thesis", b"a month of work")).is_none() {
            return;
        }
        let db2 = db.clone();
        crate::commands::volume::AFTER_SNAPSHOT_CHECK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || overwrite_in_place(&db2, &older)))
        });
        let res = unmount_publish(&rt, &v, &mut r, s);
        let names = snapshot_names(&v);
        eprintln!(
            "D2[{how}]: overwrite after the checks; unmount publish -> {}; the uploaded \
             snapshot's names {names:?}",
            r13_outcome(&res)
        );
        let (_r2, next) = prep_ok(&rt, &v, "D2: next mount");
        let mut got = None;
        with_mount(&rt, &v, |mp| got = Some(std::fs::read(mp.join("thesis")))).unwrap();
        let got = got.unwrap();
        eprintln!(
            "D2[{how}]: next mount rebuilt {}; thesis reads -> {}",
            next.rebuilt,
            r13_verdict(&got, b"a month of work")
        );
        let ok = res.is_ok()
            && names.as_ref().is_ok_and(|n| n.iter().any(|x| x == "thesis"))
            && matches!(&got, Ok(b) if b == b"a month of work");
        eprintln!("D2[{how}]: RESULT {}", if ok { "the checked bytes" } else { "NOT the checked bytes" });
        if !ok {
            failures.push(how);
        }
    }
    assert!(failures.is_empty(), "D2: uploaded other bytes than it checked in {failures:?}");
}

/// D1: the fingerprint is the publish's FIRST check. A publish that finds
/// the main file written by another program writes nothing at all: not the
/// version reservation in volume.json, not the stamp, and above all no
/// checkpoint of the session's WAL into the other program's file (the
/// restamp would checkpoint one). The file keeps the other program's bytes.
#[test]
fn r13_a_refused_publish_writes_nothing_into_the_other_programs_file() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    own_root(&v);
    clean_unmount(&rt, &v);
    let r0 = v.open();
    let (db, config) = (r0.paths.db_path.clone(), r0.paths.config_path.clone());
    drop(r0);
    let backup = std::fs::read(&db).unwrap();
    let (mut r, s) = prep_ok(&rt, &v, "refusal: session");
    if with_mount(&rt, &v, |mp| {
        write_synced(mp, "thesis", b"a month of work");
        overwrite_in_place(&db, &backup);
    })
    .is_none()
    {
        return;
    }
    let cfg_before = std::fs::read(&config).unwrap();
    let msgs = v.mock.message_count();
    let res = unmount_publish(&rt, &v, &mut r, s);
    eprintln!("refusal: unmount publish -> {}", r13_outcome(&res));
    assert!(res.is_err(), "published a file another program wrote");
    assert_eq!(v.mock.message_count(), msgs, "uploaded something");
    assert_eq!(std::fs::read(&config).unwrap(), cfg_before, "volume.json changed");
    assert!(
        std::fs::read(&db).unwrap() == backup,
        "the refused publish wrote into the other program's file"
    );
}
