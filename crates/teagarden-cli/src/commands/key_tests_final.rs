// FINAL REVIEW scratch tests (reviewer's; not the author's).

/// What a session after the publish `res` sees: (rebuilt, marker before,
/// thesis through the mount, the outcome of ITS unmount publish, thesis
/// through the mount after that).
fn fin_follow(
    rt: &tokio::runtime::Runtime,
    v: &RotVol,
    tag: &str,
    res: &Result<()>,
) -> bool {
    let head = head_of(v);
    eprintln!(
        "{tag}: unmount publish -> {}; HEAD seq {} ; rebuild marker {}",
        r13_outcome(res),
        head.seq,
        marker(v)
    );
    let (mut r2, next) = prep_ok(rt, v, "next mount");
    let rebuilt = next.rebuilt;
    let mut got = None;
    with_mount(rt, v, |mp| got = Some(std::fs::read(mp.join("thesis")))).unwrap();
    let got = got.unwrap();
    eprintln!(
        "{tag}: next mount rebuilt {rebuilt}; thesis reads -> {}",
        r13_verdict(&got, b"a month of work")
    );
    let res2 = unmount_publish(rt, v, &mut r2, next);
    eprintln!(
        "{tag}: that mount's unmount publish -> {}; HEAD seq now {}; snapshot names {:?}",
        r13_outcome(&res2),
        head_of(v).seq,
        snapshot_names(v)
    );
    let (_r3, third) = prep_ok(rt, v, "third mount");
    let mut got3 = None;
    with_mount(rt, v, |mp| got3 = Some(std::fs::read(mp.join("thesis")))).unwrap();
    let got3 = got3.unwrap();
    eprintln!(
        "{tag}: third mount rebuilt {}; thesis reads -> {}",
        third.rebuilt,
        r13_verdict(&got3, b"a month of work")
    );
    let ok = matches!(&got, Ok(b) if b == b"a month of work")
        && matches!(&got3, Ok(b) if b == b"a month of work");
    eprintln!("{tag}: RESULT {}", if ok { "acknowledged bytes kept" } else { "ACKNOWLEDGED BYTES LOST" });
    ok
}

/// F1: `cp backup metadata.db` in place while the snapshot is being uploaded,
/// and the upload then fails (Telegram down). The publish's `unstamp` writes
/// the HEAD's stamp and position into the other program's file.
#[test]
fn final_f1_overwrite_during_a_failed_upload() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut failures = Vec::new();
    for how in ["backup-before-mount", "backup-in-session"] {
        let v = rot_volume(&rt);
        own_root(&v);
        clean_unmount(&rt, &v);
        let db = v.open().paths.db_path.clone();
        let before = std::fs::read(&db).unwrap();
        let (mut r, s) = prep_ok(&rt, &v, "F1: session");
        let in_session = std::fs::read(&db).unwrap();
        if with_mount(&rt, &v, |mp| write_synced(mp, "thesis", b"a month of work")).is_none() {
            return;
        }
        let older = if how == "backup-in-session" { in_session } else { before };
        let db2 = db.clone();
        crate::commands::volume::AFTER_SNAPSHOT_CHECK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || overwrite_in_place(&db2, &older)))
        });
        v.mock.set_metadata_budget(Some(0));
        let res = unmount_publish(&rt, &v, &mut r, s);
        v.mock.set_metadata_budget(None);
        if !fin_follow(&rt, &v, &format!("F1[{how}]"), &res) {
            failures.push(how);
        }
    }
    assert!(failures.is_empty(), "F1: lost acknowledged bytes in {failures:?}");
}

/// F2: `cp backup metadata.db` in place between the publish's checks and
/// its restamp (the restamp checkpoints and the session then records the
/// fingerprint of whatever file is there).
#[test]
fn final_f2_overwrite_between_the_checks_and_the_restamp() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut failures = Vec::new();
    for how in ["backup-before-mount", "backup-in-session"] {
        let v = rot_volume(&rt);
        own_root(&v);
        clean_unmount(&rt, &v);
        let db = v.open().paths.db_path.clone();
        let before = std::fs::read(&db).unwrap();
        let (mut r, s) = prep_ok(&rt, &v, "F2: session");
        let in_session = std::fs::read(&db).unwrap();
        if with_mount(&rt, &v, |mp| write_synced(mp, "thesis", b"a month of work")).is_none() {
            return;
        }
        let older = if how == "backup-in-session" { in_session } else { before };
        let db2 = db.clone();
        crate::commands::volume::BEFORE_RESTAMP.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || overwrite_in_place(&db2, &older)))
        });
        let res = unmount_publish(&rt, &v, &mut r, s);
        if !fin_follow(&rt, &v, &format!("F2[{how}]"), &res) {
            failures.push(how);
        }
    }
    assert!(failures.is_empty(), "F2: lost acknowledged bytes in {failures:?}");
}

/// F1z: as F1, but the session made no change (HEAD seq 0, so the next mount
/// does not rebuild), and the backup is of an EARLIER lineage that does not
/// hold `thesis` (written and published by an earlier session).
#[test]
fn final_f1z_overwrite_during_a_failed_upload_of_a_session_without_changes() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    own_root(&v);
    clean_unmount(&rt, &v);
    let db = v.open().paths.db_path.clone();
    let backup = std::fs::read(&db).unwrap();
    let (mut ra, sa) = prep_ok(&rt, &v, "F1z: session A");
    if with_mount(&rt, &v, |mp| write_synced(mp, "thesis", b"a month of work")).is_none() {
        return;
    }
    unmount_publish(&rt, &v, &mut ra, sa).expect("F1z: session A clean unmount");
    eprintln!("F1z: session A wrote thesis and unmounted cleanly; snapshot names {:?}", snapshot_names(&v));
    let (mut r, s) = prep_ok(&rt, &v, "F1z: session B");
    let mut got = None;
    with_mount(&rt, &v, |mp| got = Some(std::fs::read(mp.join("thesis")))).unwrap();
    eprintln!("F1z: session B (reads only) thesis reads -> {}", r13_verdict(&got.unwrap(), b"a month of work"));
    let db2 = db.clone();
    crate::commands::volume::AFTER_SNAPSHOT_CHECK.with(|h| {
        *h.borrow_mut() = Some(Box::new(move || overwrite_in_place(&db2, &backup)))
    });
    v.mock.set_metadata_budget(Some(0));
    let res = unmount_publish(&rt, &v, &mut r, s);
    v.mock.set_metadata_budget(None);
    assert!(fin_follow(&rt, &v, "F1z", &res), "F1z: lost acknowledged bytes");
}

/// F2z: as F2, the backup of an earlier lineage, the session without changes.
#[test]
fn final_f2z_overwrite_before_the_restamp_earlier_lineage() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    own_root(&v);
    clean_unmount(&rt, &v);
    let db = v.open().paths.db_path.clone();
    let backup = std::fs::read(&db).unwrap();
    let (mut ra, sa) = prep_ok(&rt, &v, "F2z: session A");
    if with_mount(&rt, &v, |mp| write_synced(mp, "thesis", b"a month of work")).is_none() {
        return;
    }
    unmount_publish(&rt, &v, &mut ra, sa).expect("F2z: session A clean unmount");
    let (mut r, s) = prep_ok(&rt, &v, "F2z: session B");
    with_mount(&rt, &v, |_mp| {}).unwrap();
    let db2 = db.clone();
    crate::commands::volume::BEFORE_RESTAMP.with(|h| {
        *h.borrow_mut() = Some(Box::new(move || overwrite_in_place(&db2, &backup)))
    });
    let res = unmount_publish(&rt, &v, &mut r, s);
    assert!(fin_follow(&rt, &v, "F2z", &res), "F2z: lost acknowledged bytes");
}
