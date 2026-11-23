// Round 11: the round-10 review's findings (T1, T1b, T2, T3, T4) as asserting
// regression tests, and the guards this round adds (included into key.rs
// `tests::r8::real_fuse::r10`, after `key_tests_lineage.rs`).

/// Write `data` to `name` in the mounted volume and fsync it (the user's
/// acknowledged write).
fn write_synced(mp: &Path, name: &str, data: &[u8]) {
    use std::io::Write as _;
    let mut f = std::fs::File::create(mp.join(name)).unwrap();
    f.write_all(data).unwrap();
    f.sync_all().unwrap();
}

/// The names in the root directory of the local metadata DB.
fn local_names(v: &RotVol) -> Vec<String> {
    let r = v.open();
    let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
    let c = local_db::open_read_only(&r.paths.db_path).unwrap();
    let mut n: Vec<String> = InodeStore::new(&c, &schema, &r.hierarchy.meta)
        .list_children(1)
        .unwrap()
        .into_iter()
        .map(|i| i.name)
        .collect();
    n.sort();
    n
}

/// The bytes of every file of the volume's directory that a refusal must
/// leave alone: volume.json, journal.head (if any), metadata.db.
fn volume_files(v: &RotVol) -> Vec<(String, Option<Vec<u8>>)> {
    let r = v.open();
    [
        r.paths.config_path.clone(),
        journal_head_path(&r),
        r.paths.db_path.clone(),
    ]
    .into_iter()
    .map(|p| {
        (
            p.file_name().unwrap().to_string_lossy().into_owned(),
            std::fs::read(&p).ok(),
        )
    })
    .collect()
}

/// A volume (own root) whose last session wrote and fsynced `thesis` and then
/// died before its unmount publish: the HEAD has entries past its base, the
/// local DB holds the file. `None` without FUSE.
fn crashed_with_thesis(rt: &tokio::runtime::Runtime) -> Option<RotVol> {
    let v = rot_volume(rt);
    own_root(&v);
    clean_unmount(rt, &v);
    with_mount(rt, &v, |mp| write_synced(mp, "thesis", b"a month of work"))?;
    assert!(head_of(&v).seq > 0);
    assert_eq!(local_names(&v), ["a", "b", "h", "thesis"]);
    Some(v)
}

/// A mount's preparation that must refuse, changing nothing (no upload, the
/// volume's files byte-identical) and naming both ways out. Returns the text.
fn assert_mount_refuses_naming_both_ways_out(
    rt: &tokio::runtime::Runtime,
    v: &RotVol,
    when: &str,
) -> String {
    let msgs = v.mock.message_count();
    let files = volume_files(v);
    let (_, s) = prep(rt, v);
    let msg = format!(
        "{:#}",
        s.err()
            .unwrap_or_else(|| panic!("{when}: the mount went on (local tree now {:?})", local_tree(v)))
    );
    eprintln!("{when}: mount: {msg}");
    assert!(msg.contains("teagarden volume restore rot"), "{when}: {msg}");
    assert!(
        msg.contains("teagarden volume republish rot --from-local-db"),
        "{when}: {msg}"
    );
    assert!(msg.contains("Nothing was changed"), "{when}: {msg}");
    assert_eq!(v.mock.message_count(), msgs, "{when}: the mount uploaded");
    assert!(volume_files(v) == files, "{when}: the mount changed a file");
    msg
}

// ── D1: a missing journal.head never replaces a readable DB ─────────────────

/// T1: a session wrote and fsynced a file, then died; journal.head is lost.
/// The local DB holds the file, the snapshot volume.json names does not. The
/// mount must refuse (nothing changed, nothing uploaded), naming `volume
/// restore` (the snapshot wins) and `volume republish --from-local-db` (the
/// local DB wins); republish then keeps the file.
#[test]
fn t1_a_lost_journal_head_never_replaces_a_readable_db() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let Some(v) = crashed_with_thesis(&rt) else {
        return;
    };
    std::fs::remove_file(journal_head_path(&v.open())).unwrap();
    assert_mount_refuses_naming_both_ways_out(&rt, &v, "T1");
    assert_eq!(local_names(&v), ["a", "b", "h", "thesis"], "T1");
    // The local DB wins.
    rt.block_on(crate::commands::volume::republish_core(
        v.open(),
        v.mock.as_ref(),
        "rot",
        true,
        false,
        &mut |_: &str| panic!("--force asks nothing"),
    ))
    .expect("T1: republish --from-local-db");
    assert_eq!(latest_snapshot_names(&v), ["a", "b", "h", "thesis"], "T1");
    let (_, s) = prep_ok(&rt, &v, "T1: after republish");
    assert!(!s.rebuilt, "T1: the mount after republish rebuilt");
    assert_eq!(local_names(&v), ["a", "b", "h", "thesis"], "T1");
}

/// T1b: a pre-journal volume (no journal.head, unstamped DB) whose local DB
/// is one file ahead of the snapshot volume.json names (pre-journal builds
/// wrote only the local DB between snapshots). The mount refuses rather than
/// replace it; `volume restore` (the snapshot wins) then works too.
#[test]
fn t1b_a_pre_journal_volume_ahead_of_its_snapshot_is_refused_not_replaced() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    let r = v.open();
    let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
    std::fs::remove_file(journal_head_path(&r)).unwrap();
    local_db::stamp_db_file(&r.paths.db_path, &schema, None).unwrap();
    {
        let c = local_db::open_existing(&r.paths.db_path).unwrap();
        InodeStore::new(&c, &schema, &r.hierarchy.meta)
            .insert(&Inode::new_file(9, 1, "late".into(), 0o644, 1000, 1000))
            .unwrap();
        c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
    }
    assert_mount_refuses_naming_both_ways_out(&rt, &v, "T1b");
    assert_eq!(local_names(&v), ["a", "b", "h", "late"], "T1b");
    // The snapshot wins.
    restore(&rt, &v).expect("T1b: volume restore");
    assert_eq!(local_names(&v), ["a", "b", "h"], "T1b: after restore");
    let (_, s) = prep_ok(&rt, &v, "T1b: after restore");
    assert!(!s.rebuilt, "T1b: the mount after restore rebuilt");
    assert_files_exact(&rt, &v, "T1b: after restore");
}

/// S4 (version skew): an older build reports a 1.0 journal.head as tampered
/// (core: `journal_head::tests::a_round9_build_cannot_read_a_v3_head`), and a
/// user may delete it. A clean volume's 1.0 mount then refuses (nothing
/// changed) instead of replacing the DB; the mount does not go on.
#[test]
fn s4_deleting_journal_head_makes_the_mount_refuse_not_replace() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    // The local DB is ahead of the snapshot (a change an older build made
    // without journaling it, or any reason): it must survive.
    let r = v.open();
    let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
    {
        let c = local_db::open_existing(&r.paths.db_path).unwrap();
        InodeStore::new(&c, &schema, &r.hierarchy.meta)
            .insert(&Inode::new_file(9, 1, "late".into(), 0o644, 1000, 1000))
            .unwrap();
        c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
    }
    std::fs::remove_file(journal_head_path(&r)).unwrap();
    assert_mount_refuses_naming_both_ways_out(&rt, &v, "S4");
    assert_eq!(local_names(&v), ["a", "b", "h", "late"], "S4");
}

/// The auto-restore stays for a DB that is missing, unreadable or rootless
/// (and the volume has no journal.head): the mount restores the snapshot
/// volume.json names, and nothing else is in the way.
#[test]
fn a_missing_unreadable_or_rootless_db_without_a_head_is_still_auto_restored() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    for how in ["missing", "unreadable", "rootless"] {
        let v = rot_volume(&rt);
        let r = v.open();
        std::fs::remove_file(journal_head_path(&r)).unwrap();
        match how {
            "missing" => metadata_snapshot::remove_db_files(&r.paths.db_path).unwrap(),
            "unreadable" => {
                metadata_snapshot::remove_db_files(&r.paths.db_path).unwrap();
                std::fs::write(&r.paths.db_path, vec![0x5a; 8192]).unwrap();
            }
            _ => replace_with_empty_db(&v, false),
        }
        let (_, s) = prep_ok(&rt, &v, how);
        assert!(s.rebuilt, "{how}: not rebuilt");
        assert_files_exact(&rt, &v, how);
    }
}

// ── D1b: a readable DB is never destroyed ───────────────────────────────────

/// The order of a kept copy `metadata.db.replaced.<secs>[.<n>]` (`None`
/// for anything else, sidecars included).
fn kept_order(name: &str) -> Option<(u64, u64)> {
    let rest = name.strip_prefix(local_db::REPLACED_PREFIX)?;
    let mut parts = rest.split('.');
    let secs = parts.next()?.parse().ok()?;
    let n = match parts.next() {
        None => 0,
        Some(n) => n.parse().ok()?,
    };
    parts.next().is_none().then_some((secs, n))
}

/// The kept copies of replaced DBs (main files), oldest first.
fn kept_copy_paths(v: &RotVol) -> Vec<std::path::PathBuf> {
    let base = v.open().paths.base_dir;
    let mut k: Vec<((u64, u64), String)> = ls_dir(v)
        .into_iter()
        .filter_map(|n| kept_order(&n).map(|o| (o, n)))
        .collect();
    k.sort();
    k.into_iter().map(|(_, n)| base.join(n)).collect()
}

/// The tree and the stamp of the newest kept copy of a replaced DB.
fn replaced_slot(v: &RotVol) -> Option<(local_db::TreeSummary, Option<local_db::DbStamp>)> {
    let r = v.open();
    let p = kept_copy_paths(v).pop()?;
    let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
    let c = local_db::open_read_only(&p).unwrap();
    Some((
        local_db::tree_summary(&c, &schema).unwrap(),
        local_db::read_stamp(&c, &schema).unwrap(),
    ))
}

/// Every `metadata.db*` file in the volume directory.
fn db_files(v: &RotVol) -> Vec<String> {
    ls_dir(v)
        .into_iter()
        .filter(|n| n.starts_with("metadata.db"))
        .collect()
}

/// D1b (round 12: timestamped, capped copies): a rebuild (nv3b: an older copy
/// of the volume's own DB put back) and a `volume restore` each keep the
/// readable DB they replace as a new `metadata.db.replaced.<time>`; the
/// copies are bounded.
#[test]
fn d1b_a_rebuild_and_a_restore_keep_the_db_they_replace() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    own_root(&v);
    clean_unmount(&rt, &v);
    let db = v.open().paths.db_path.clone();
    let backup = std::fs::read(&db).unwrap();
    let old_stamp = db_stamp(&v);
    if with_mount(&rt, &v, |mp| write_synced(mp, "thesis", b"a month of work")).is_none() {
        return;
    }
    let (mut r, s) = prep_ok(&rt, &v, "D1b: session 2");
    unmount_publish(&rt, &v, &mut r, s).expect("D1b: session 2 unmount");
    // nv3b: the older copy is put back; the mount rebuilds.
    metadata_snapshot::remove_db_files(&db).unwrap();
    std::fs::write(&db, &backup).unwrap();
    let (_, s) = prep_ok(&rt, &v, "D1b: rebuild");
    assert!(s.rebuilt);
    let (tree, stamp) = replaced_slot(&v).expect("D1b: the rebuild kept no copy");
    eprintln!("D1b: after the rebuild: {:?}, slot {tree:?} {stamp:?}", db_files(&v));
    assert_eq!(tree.entries, 3, "D1b: the slot is not the older copy");
    assert_eq!(stamp, old_stamp, "D1b: the slot is not the older copy");
    assert_eq!(local_names(&v), ["a", "b", "h", "thesis"]);
    // A restore (`--discard-journal`) replaces the DB, one journaled file
    // ahead of the snapshot, and keeps it as a second copy. (A DB at the
    // HEAD's lineage and journal position is reproducible and not kept:
    // every change TeaGarden makes to it is journaled.)
    with_mount(&rt, &v, |mp| write_synced(mp, "late", b"x")).unwrap();
    assert!(head_of(&v).seq > 0);
    restore(&rt, &v).expect("D1b: restore");
    let (tree, _) = replaced_slot(&v).expect("D1b: the restore kept no copy");
    eprintln!("D1b: after the restore: {:?}, slot {tree:?}", db_files(&v));
    assert_eq!(tree.entries, 5, "D1b: the slot is not the DB the restore replaced");
    assert_eq!(local_names(&v), ["a", "b", "h", "thesis"]);
    assert_eq!(kept_copy_paths(&v).len(), 2, "D1b: {:?}", db_files(&v));
    for n in db_files(&v) {
        assert!(
            n == "metadata.db"
                || n.starts_with("metadata.db-")
                || n.starts_with(local_db::REPLACED_PREFIX),
            "D1b: an unexpected file {n}"
        );
    }
}

// ── D2: republish names and guard rails ─────────────────────────────────────

/// T3: an older copy of the volume's DB is in place and Telegram is
/// unreachable for one mount. The error must not name republish (it says to
/// check the connection and mount again), and republish refuses the older
/// copy (its stamp is not the HEAD's), with and without `--force`: the newer
/// snapshot stays the newest and nothing is uploaded.
#[test]
fn t3_a_transient_failure_names_no_republish_and_republish_refuses_an_older_copy() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    own_root(&v);
    clean_unmount(&rt, &v);
    let db = v.open().paths.db_path.clone();
    let backup = std::fs::read(&db).unwrap();
    if with_mount(&rt, &v, |mp| write_synced(mp, "thesis", b"a month of work")).is_none() {
        return;
    }
    let (mut r, s) = prep_ok(&rt, &v, "T3: session 2");
    unmount_publish(&rt, &v, &mut r, s).expect("T3: session 2 unmount");
    assert_eq!(latest_snapshot_names(&v), ["a", "b", "h", "thesis"]);
    let newest = v.open().config.metadata_snapshot_id.unwrap();
    metadata_snapshot::remove_db_files(&db).unwrap();
    std::fs::write(&db, &backup).unwrap();
    v.mock.set_connected(false);
    let (_, s) = prep(&rt, &v);
    let msg = format!("{:#}", s.err().expect("T3: the mount cannot fetch"));
    v.mock.set_connected(true);
    eprintln!("T3: mount while Telegram is unreachable: {msg}");
    assert!(!msg.contains("republish"), "T3: {msg}");
    assert!(msg.contains("mount again"), "T3: {msg}");
    let files = volume_files(&v);
    let msgs = v.mock.message_count();
    for force in [false, true] {
        let mut prompts: Vec<String> = vec![];
        let res = rt.block_on(crate::commands::volume::republish_core(
            v.open(),
            v.mock.as_ref(),
            "rot",
            force,
            false,
            &mut |p: &str| {
                prompts.push(p.to_string());
                Ok(true)
            },
        ));
        let e = format!(
            "{:#}",
            res.err()
                .unwrap_or_else(|| panic!("T3 (force {force}): republish published the older copy"))
        );
        eprintln!("T3: republish (force {force}): {e}");
        assert!(e.contains("--replace-newer-metadata"), "T3: {e}");
        assert!(prompts.is_empty(), "T3: asked before refusing");
        assert_eq!(v.mock.message_count(), msgs, "T3: uploaded");
        assert!(volume_files(&v) == files, "T3: a file changed");
    }
    assert_eq!(v.open().config.metadata_snapshot_id, Some(newest));
    assert_eq!(latest_snapshot_names(&v), ["a", "b", "h", "thesis"]);
    // The explicit override publishes the older copy, after saying what it
    // supersedes and that `volume restore` will refuse that snapshot; which
    // it then does.
    let newest_version = v.open().config.metadata_version;
    let mut prompts: Vec<String> = vec![];
    rt.block_on(crate::commands::volume::republish_core(
        v.open(),
        v.mock.as_ref(),
        "rot",
        false,
        true,
        &mut |p: &str| {
            prompts.push(p.to_string());
            Ok(true)
        },
    ))
    .expect("T3: republish --replace-newer-metadata");
    let prompt = prompts.concat();
    eprintln!("T3: --replace-newer-metadata asks:\n{prompt}");
    assert!(prompt.contains("is NOT the one journal.head records"), "{prompt}");
    assert!(
        prompt.contains(&format!(
            "supersedes the snapshot volume.json names, version {newest_version} \
             (message_id={newest})"
        )),
        "{prompt}"
    );
    assert!(
        prompt.contains("`volume restore` refuses the superseded snapshot"),
        "{prompt}"
    );
    assert_eq!(latest_snapshot_names(&v), ["a", "b", "h"]);
    let back = rt.block_on(crate::commands::volume::restore_core(
        v.open(),
        v.mock.as_ref(),
        "rot",
        Some(newest),
        true,
        true,
    ));
    let e = format!("{:#}", back.expect_err("T3: the superseded snapshot was restored"));
    eprintln!("T3: restore of the superseded snapshot: {e}");
    assert!(e.contains("rollback"), "{e}");
}

/// The republish summary of the volume's current database (stamp equal to
/// the HEAD's lineage) says so, and that it supersedes the current snapshot.
#[test]
fn republish_says_what_the_db_is_and_what_it_supersedes() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    let c = v.open().config;
    let mut prompt = String::new();
    rt.block_on(crate::commands::volume::republish_core(
        v.open(),
        v.mock.as_ref(),
        "rot",
        false,
        false,
        &mut |p: &str| {
            prompt = p.to_string();
            Ok(true)
        },
    ))
    .expect("republish of the current DB");
    eprintln!("republish asks:\n{prompt}");
    assert!(
        prompt.contains("is the one journal.head records: it is the volume's current database"),
        "{prompt}"
    );
    assert!(
        prompt.contains(&format!(
            "version {} (message_id={})",
            c.metadata_version,
            c.metadata_snapshot_id.unwrap()
        )),
        "{prompt}"
    );
    assert!(prompt.contains("anti-rollback floor"), "{prompt}");
    assert_lineage_agrees(&rt, &v, "after republish");
}

// ── S1: a failed publish puts the replaced stamp back ───────────────────────

/// After the snapshot is uploaded, saving volume.json fails (it is replaced
/// by a directory): the publish is an error, and the stamp it wrote is put
/// back, so the DB is the volume's current one again (no rebuild).
#[test]
fn s1_a_failed_volume_json_save_puts_the_stamp_back() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    let before = db_stamp(&v).unwrap();
    let cfg = v.open().paths.config_path.clone();
    let saved = std::sync::Arc::new(std::sync::Mutex::new(None::<Vec<u8>>));
    let (block, keep) = (cfg.clone(), saved.clone());
    v.mock.after_next_metadata_sync(move || {
        *keep.lock().unwrap() = Some(std::fs::read(&block).unwrap());
        std::fs::remove_file(&block).unwrap();
        std::fs::create_dir(&block).unwrap();
        std::fs::write(block.join("block-rename"), b"x").unwrap();
    });
    let mut r = v.open();
    let e = rt
        .block_on(crate::commands::volume::publish_as_new_session(
            &mut r,
            v.mock.as_ref(),
        ))
        .expect_err("saving volume.json must fail");
    eprintln!("S1 (volume.json): {e:#}");
    assert!(format!("{e:#}").contains("saving volume.json failed"), "{e:#}");
    std::fs::remove_dir_all(&cfg).unwrap();
    std::fs::write(&cfg, saved.lock().unwrap().take().unwrap()).unwrap();
    assert_eq!(db_stamp(&v), Some(before), "S1: the stamp was not put back");
    assert_eq!(local_db_state(&v.open()).unwrap(), LocalDb::Usable);
    let (_, s) = prep_ok(&rt, &v, "S1 (volume.json)");
    assert!(!s.rebuilt, "S1: the DB had to be rebuilt");
}

/// After the snapshot is uploaded and volume.json saved, the HEAD reset fails
/// (journal.head is replaced by a directory): the stamp is put back, so with
/// the HEAD back the DB is the volume's current one (no rebuild).
#[test]
fn s1_a_failed_head_reset_puts_the_stamp_back() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    let before = db_stamp(&v).unwrap();
    let hp = journal_head_path(&v.open());
    let saved = std::fs::read(&hp).unwrap();
    let block = hp.clone();
    v.mock.after_next_metadata_sync(move || {
        std::fs::remove_file(&block).unwrap();
        std::fs::create_dir(&block).unwrap();
        std::fs::write(block.join("block-rename"), b"x").unwrap();
    });
    let mut r = v.open();
    let e = rt
        .block_on(crate::commands::volume::publish_as_new_session(
            &mut r,
            v.mock.as_ref(),
        ))
        .expect_err("the HEAD reset must fail");
    eprintln!("S1 (HEAD): {e:#}");
    assert!(format!("{e:#}").contains("journal HEAD"), "{e:#}");
    std::fs::remove_dir_all(&hp).unwrap();
    std::fs::write(&hp, &saved).unwrap();
    assert_eq!(db_stamp(&v), Some(before), "S1: the stamp was not put back");
    assert_eq!(local_db_state(&v.open()).unwrap(), LocalDb::Usable);
    let (_, s) = prep_ok(&rt, &v, "S1 (HEAD)");
    assert!(!s.rebuilt, "S1: the DB had to be rebuilt");
}

// ── D3: the publish snapshots only the session's DB ─────────────────────────

/// T2: during a real FUSE session the file at metadata.db is replaced by an
/// older copy of the volume's own DB (same lineage stamp as the HEAD). The
/// unmount publish must refuse: volume.json and journal.head unchanged (HEAD
/// seq still past 0), nothing uploaded, the failure recorded; the next mount
/// replays the journal and shows the session's file.
#[test]
fn t2_a_db_replaced_during_a_session_is_not_published() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    own_root(&v);
    clean_unmount(&rt, &v);
    let db = v.open().paths.db_path.clone();
    let backup = std::fs::read(&db).unwrap();
    let (mut r, s) = prep_ok(&rt, &v, "T2: session");
    if with_mount(&rt, &v, |mp| {
        write_synced(mp, "thesis", b"a month of work");
        let tmp = db.with_extension("restore-tmp");
        std::fs::write(&tmp, &backup).unwrap();
        std::fs::rename(&tmp, &db).unwrap();
        for sfx in ["-wal", "-shm"] {
            let mut p = db.as_os_str().to_os_string();
            p.push(sfx);
            let _ = std::fs::remove_file(p);
        }
    })
    .is_none()
    {
        return;
    }
    assert!(head_of(&v).seq > 0);
    assert_eq!(db_stamp(&v).map(|s| s.lineage), head_of(&v).lineage);
    let files = volume_files(&v);
    let msgs = v.mock.message_count();
    let res = unmount_publish(&rt, &v, &mut r, s);
    let e = format!(
        "{:#}",
        res
            .expect_err("T2: the publish stamped and published the older copy")
    );
    eprintln!("T2: unmount publish: {e}");
    assert_eq!(v.mock.message_count(), msgs, "T2: uploaded");
    assert!(volume_files(&v) == files, "T2: a file changed");
    assert!(head_of(&v).seq > 0, "T2: the HEAD was reset");
    assert!(
        v.open()
            .paths
            .base_dir
            .join(crate::commands::volume::SNAPSHOT_FAILED_MARKER)
            .exists(),
        "T2: the failure is not recorded"
    );
    let (mut r, s) = prep_ok(&rt, &v, "T2: next mount");
    assert!(s.rebuilt, "T2: the next mount did not replay the journal");
    assert_eq!(local_names(&v), ["a", "b", "h", "thesis"]);
    unmount_publish(&rt, &v, &mut r, s).expect("T2: next unmount");
    assert_eq!(latest_snapshot_names(&v), ["a", "b", "h", "thesis"]);
}

/// D3: a DB whose stamp was changed in place during the session (same file,
/// so the identity check passes) is not overwritten by a publish while its
/// stamp is not the lineage journal.head records: nothing is written or
/// uploaded, the failure is recorded.
#[test]
fn d3_a_publish_refuses_a_db_whose_stamp_is_not_the_heads() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    let (mut r, s) = prep_ok(&rt, &v, "D3: session");
    let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
    let other = local_db::DbStamp {
        volume_id: v.id.clone(),
        lineage: Lineage::new(r.config.metadata_version),
    };
    local_db::stamp_db_file(&r.paths.db_path, &schema, Some(&other)).unwrap();
    let files = volume_files(&v);
    let msgs = v.mock.message_count();
    let e = format!(
        "{:#}",
        unmount_publish(&rt, &v, &mut r, s)
            
            .expect_err("D3: published a DB whose stamp is not the HEAD's")
    );
    eprintln!("D3: {e}");
    assert_eq!(v.mock.message_count(), msgs, "D3: uploaded");
    assert!(volume_files(&v) == files, "D3: a file changed");
    assert_eq!(db_stamp(&v), Some(other), "D3: the stamp was overwritten");
}

/// D3 at `key rotate`: the DB file is replaced (by an older copy) between
/// the rotation's reads and its publish. The publish refuses; nothing is
/// deleted, the epoch does not move, and every file stays readable.
#[test]
fn d3_a_rotation_never_publishes_a_db_replaced_under_it() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    let db = v.open().paths.db_path.clone();
    let backup = std::fs::read(&db).unwrap();
    let head_before = std::fs::read(journal_head_path(&v.open())).unwrap();
    let e = rotate_with(&rt, &v, &|s| {
        if s == RotateStep::AllBlocksDone {
            let tmp = db.with_extension("restore-tmp");
            std::fs::write(&tmp, &backup).unwrap();
            std::fs::rename(&tmp, &db).unwrap();
        }
    })
    .expect_err("D3: the rotation published a DB swapped under it");
    eprintln!("D3 rotate: {e:#}");
    assert_eq!(
        std::fs::read(journal_head_path(&v.open())).unwrap(),
        head_before,
        "D3 rotate: the HEAD moved"
    );
    assert_eq!(v.open().config.current_epoch, 0, "D3 rotate: the epoch moved");
    for id in &v.pre_rotation_msgs {
        assert!(v.mock.get_raw(*id).is_some(), "D3 rotate: message {id} deleted");
    }
    assert_files_exact(&rt, &v, "D3 rotate");
}

/// D3 at `volume revert`: the DB file is replaced (by an older copy) after
/// the revert's journal entry is uploaded. Its publish refuses; volume.json
/// and the HEAD (with the entry past its base) are left, nothing more is
/// uploaded, and the next mount replays the entry.
#[test]
fn d3_a_revert_never_publishes_a_db_replaced_under_it() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut v = rot_volume(&rt);
    let db = v.open().paths.db_path.clone();
    let backup = std::fs::read(&db).unwrap();
    let cfg_before = std::fs::read(v.open().paths.config_path).unwrap();
    let swap = db.clone();
    v.mock.after_next_metadata_sync(move || {
        let tmp = swap.with_extension("restore-tmp");
        std::fs::write(&tmp, &backup).unwrap();
        std::fs::rename(&tmp, &swap).unwrap();
    });
    let msgs = v.mock.message_count();
    let e = rt
        .block_on(crate::commands::volume::revert_core(
            v.open(),
            v.transport(),
            "/h",
            1,
        ))
        .expect_err("D3: the revert published a DB swapped under it");
    eprintln!("D3 revert: {e:#}");
    // Round 13: the fingerprint, compared first, catches the swap.
    assert!(
        format!("{e:#}").contains("written by another program"),
        "{e:#}"
    );
    assert_eq!(v.mock.message_count(), msgs + 1, "D3 revert: only its entry");
    assert_eq!(head_of(&v).seq, 1, "D3 revert: the HEAD was reset");
    assert_eq!(
        std::fs::read(v.open().paths.config_path).unwrap(),
        cfg_before,
        "D3 revert: volume.json changed"
    );
    let (_, s) = prep_ok(&rt, &v, "D3 revert: next mount");
    assert!(s.rebuilt, "D3 revert: the next mount did not replay");
    v.expect.insert(4, v.h_versions[0].clone());
    assert_files_exact(&rt, &v, "D3 revert: the reverted /h");
}

/// D3 at a first mount: the DB file the first mount created is replaced
/// before its base snapshot publish. The publish refuses; nothing is
/// reserved in volume.json, nothing uploaded, no HEAD written.
#[test]
fn d3_a_first_mount_never_publishes_a_db_replaced_under_it() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = super::super::r9::new_volume();
    let (mut r, s) = prep_ok(&rt, &v, "D3 first mount");
    let db = r.paths.db_path.clone();
    let copy = std::fs::read(&db).unwrap();
    let tmp = db.with_extension("restore-tmp");
    std::fs::write(&tmp, &copy).unwrap();
    std::fs::rename(&tmp, &db).unwrap();
    let cfg_before = std::fs::read(&r.paths.config_path).unwrap();
    let msgs = v.mock.message_count();
    let e = base_publish(&rt, &v, &mut r, s).expect_err("D3: published a swapped first DB");
    eprintln!("D3 first mount: {e:#}");
    assert_eq!(v.mock.message_count(), msgs, "D3 first mount: uploaded");
    assert_eq!(
        std::fs::read(&r.paths.config_path).unwrap(),
        cfg_before,
        "D3 first mount: volume.json changed (a reservation)"
    );
    assert!(!journal_head_path(&v.open()).exists(), "D3 first mount: a HEAD");
}

// ── S2: a read-only share never writes into the owner's topic ───────────────

/// The owner's volume as `share import` leaves it on the recipient's machine:
/// the owner's volume.json, a read-only `shared_origin.json`, no DB, no
/// journal.head (the tests open it with the owner's password; the shared
/// unlock path is not what is under test).
fn read_only_share_of(owner: &RotVol) -> RotVol {
    let dir = tempfile::tempdir().unwrap();
    let vdir = dir.path().join(&owner.id);
    std::fs::create_dir_all(&vdir).unwrap();
    std::fs::copy(owner.open().paths.config_path, vdir.join("volume.json")).unwrap();
    teagarden_core::volume::shared::SharedOrigin {
        derivation: teagarden_core::volume::shared::SharedDerivation::HierarchyRootV1,
        access_level: "read-only".into(),
        granted_by: "owner".into(),
        volume_id: owner.id.clone(),
    }
    .save(&vdir)
    .unwrap();
    RotVol {
        dir,
        id: owner.id.clone(),
        mock: owner.mock.clone(),
        expect: owner.expect.clone(),
        pre_rotation_msgs: vec![],
        h_versions: owner.h_versions.clone(),
    }
}

/// What `volume mount` does around the FUSE mount, through the functions it
/// calls: the preparation (phase 1), phase 2 (`activate_journal`: a base
/// snapshot when the volume has no HEAD) and the end of the session
/// (`end_session`: the unmount publish). Returns whether phase 2 attached a
/// journal.
fn mount_session(rt: &tokio::runtime::Runtime, v: &RotVol, when: &str) -> Result<bool> {
    let (mut r, s) = prep(rt, v);
    let s = s.unwrap_or_else(|e| panic!("{when}: mount: {e:#}"));
    let (head, mut db) = (s.head, s.db);
    drop(s.conn);
    let journal = rt.block_on(crate::commands::volume::activate_journal(
        &mut r,
        v.mock.as_ref(),
        head,
        &mut db,
    ))?;
    rt.block_on(crate::commands::volume::end_session(
        &mut r,
        v.mock.as_ref(),
        &db,
    ))?;
    Ok(journal.is_some())
}

/// T4, inverted: a read-only share's first mount, its unmount and its second
/// mount upload nothing into the owner's topic; the share's local DB is the
/// owner's snapshot; the owner's next publish and mount are unaffected.
#[test]
fn t4_a_read_only_share_never_publishes_into_the_owners_topic() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let owner = rot_volume(&rt);
    let share = read_only_share_of(&owner);
    let before = owner.mock.message_count();
    let owner_cfg = std::fs::read(owner.open().paths.config_path).unwrap();
    for session in ["first", "second"] {
        let r = mount_session(&rt, &share, &format!("T4: share {session} mount"));
        eprintln!(
            "T4: share {session} mount and unmount: {:?}; messages in the owner's topic {before} -> {}",
            r.as_ref().map_err(|e| format!("{e:#}")),
            owner.mock.message_count()
        );
        let journal = r.unwrap_or_else(|e| panic!("T4: share {session} session: {e:#}"));
        assert!(!journal, "T4: the share's {session} mount journals");
        assert_eq!(
            owner.mock.message_count(),
            before,
            "T4: the share's {session} session uploaded into the owner's topic"
        );
        assert_files_exact(&rt, &share, &format!("T4: share {session}"));
        // The share adopted the owner's snapshot under a local lineage.
        let head = head_of(&share);
        assert_eq!(head.seq, 0, "T4: {session}");
        assert_eq!(
            Some(head.base_snapshot_msg_id),
            owner.open().config.metadata_snapshot_id
        );
        assert_eq!(db_stamp(&share).map(|s| s.lineage), head.lineage);
        assert_eq!(local_db_state(&share.open()).unwrap(), LocalDb::Usable);
    }
    // Every other way to write into the owner's topic refuses on the share.
    let mut r = share.open();
    let e = rt
        .block_on(crate::commands::volume::publish_as_new_session(
            &mut r,
            share.mock.as_ref(),
        ))
        .expect_err("T4: a share published");
    assert!(format!("{e:#}").contains("read-only share"), "{e:#}");
    let e = rt
        .block_on(crate::commands::volume::revert_core(
            share.open(),
            share.transport(),
            "/h",
            1,
        ))
        .expect_err("T4: a share reverted");
    assert!(format!("{e:#}").contains("read-only share"), "{e:#}");
    let e = rt
        .block_on(crate::commands::volume::republish_core(
            share.open(),
            share.mock.as_ref(),
            "rot",
            true,
            true,
            &mut |_: &str| Ok(true),
        ))
        .expect_err("T4: a share republished");
    assert!(format!("{e:#}").contains("read-only share"), "{e:#}");
    let e = rotate_with(&rt, &share, &|_| {}).expect_err("T4: a share rotated");
    assert!(format!("{e:#}").contains("read-only share"), "{e:#}");
    assert_eq!(owner.mock.message_count(), before, "T4: uploaded");
    assert_eq!(std::fs::read(owner.open().paths.config_path).unwrap(), owner_cfg);
    clean_unmount(&rt, &owner);
    assert_files_exact(&rt, &owner, "T4: owner after the share's sessions");
    let (_, s) = prep_ok(&rt, &owner, "T4: owner mount");
    assert!(!s.rebuilt);
}

/// S2: a share's first mount killed after it installed and stamped the
/// owner's snapshot but before it wrote journal.head (here: the HEAD removed
/// afterwards) adopts again at the next mount, keeping the installed DB at
/// the slot, and uploads nothing.
#[test]
fn s2_a_share_adoption_killed_before_its_head_adopts_again() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let owner = rot_volume(&rt);
    let share = read_only_share_of(&owner);
    let before = owner.mock.message_count();
    mount_session(&rt, &share, "S2: first mount").unwrap();
    std::fs::remove_file(journal_head_path(&share.open())).unwrap();
    mount_session(&rt, &share, "S2: the mount after the kill").unwrap();
    assert_eq!(owner.mock.message_count(), before, "S2: uploaded");
    assert_eq!(head_of(&share).seq, 0);
    assert_eq!(db_stamp(&share).map(|s| s.lineage), head_of(&share).lineage);
    let (tree, _) = replaced_slot(&share).expect("S2: the installed DB was not kept");
    assert_eq!(tree.entries, 3);
    assert_files_exact(&rt, &share, "S2: after adopting again");
}

/// S2 (offline): a read-only share whose HEAD has no entries and whose DB is
/// the one the HEAD names may mount without a Telegram connection (it writes
/// nothing); before its first online mount, with entries past the HEAD's
/// base, or with a DB the HEAD does not name it may not. A journaled volume
/// that is not a read-only share never mounts offline.
#[test]
fn s2_only_a_read_only_share_whose_db_matches_its_head_mounts_offline() {
    use crate::commands::volume::offline_mount_check;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let owner = rot_volume(&rt);
    let share = read_only_share_of(&owner);
    let e = offline_mount_check(&share.open(), "rot", true)
        .expect_err("offline before the first online mount");
    eprintln!("S2 offline, never mounted online: {e:#}");
    mount_session(&rt, &share, "S2: first online mount").unwrap();
    offline_mount_check(&share.open(), "rot", true).expect("S2: offline share mount");
    let e = offline_mount_check(&owner.open(), "rot", false).expect_err("owner offline");
    assert!(format!("{e:#}").contains("journaled"), "{e:#}");
    // A DB the HEAD does not name (an older copy) is refused offline.
    let r = share.open();
    let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
    let other = local_db::DbStamp {
        volume_id: share.id.clone(),
        lineage: Lineage::new(r.config.metadata_version),
    };
    local_db::stamp_db_file(&r.paths.db_path, &schema, Some(&other)).unwrap();
    let e = offline_mount_check(&share.open(), "rot", true).expect_err("mismatched DB offline");
    assert!(format!("{e:#}").contains("must be rebuilt"), "{e:#}");
}
