// Round 10: the lineage stamp (included into key.rs `tests::r8::real_fuse::r10`).
//
// The round-9 review's scenarios (nv1, nv1b, nv1c, nv2, nv3, nv3b, nv5 to
// nv10) as asserting tests.

use crate::commands::volume::{journal_head_path, journal_init_phase, local_db_state};
use teagarden_core::volume::journal_head::Lineage;
use teagarden_store::local_db::LocalDb;

fn head_of(v: &RotVol) -> JournalHead {
    let r = v.open();
    JournalHead::load(&journal_head_path(&r), &r.hierarchy.integrity)
        .unwrap()
        .expect("a journal HEAD")
}

fn local_tree(v: &RotVol) -> local_db::TreeSummary {
    let r = v.open();
    let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
    local_db::tree_summary_of(&r.paths.db_path, &schema).unwrap()
}

fn marker(v: &RotVol) -> bool {
    teagarden_core::volume::rebuild_marker::load(&v.open().paths.base_dir)
        .unwrap()
        .is_some()
}

fn ls_dir(v: &RotVol) -> Vec<String> {
    let mut n: Vec<String> = std::fs::read_dir(v.open().paths.base_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    n.sort();
    n
}

/// A session a mount's preparation started, its connection closed (the
/// tests mount through `with_mount`, which opens its own).
struct Session {
    /// Whether the preparation rebuilt the DB.
    rebuilt: bool,
    /// The DB the preparation opened (what its publishes may read).
    db: crate::commands::volume::SessionDb,
}

fn begin(s: crate::commands::volume::PreparedSession) -> Session {
    drop(s.conn);
    SESSION_CHECKPOINTS.with(|c| *c.borrow_mut() = Some(s.db.checkpoints.clone()));
    Session {
        rebuilt: s.rebuilt,
        db: s.db,
    }
}

/// A mount's preparation that must succeed.
fn prep_ok(
    rt: &tokio::runtime::Runtime,
    v: &RotVol,
    when: &str,
) -> (manager::OpenVolumeResult, Session) {
    let (r, s) = prep(rt, v);
    (
        r,
        begin(s.unwrap_or_else(|e| panic!("{when}: mount: {e:#}"))),
    )
}

/// The unmount publish that ends the session `s`.
fn unmount_publish(
    rt: &tokio::runtime::Runtime,
    v: &RotVol,
    r: &mut manager::OpenVolumeResult,
    s: Session,
) -> Result<()> {
    SESSION_CHECKPOINTS.with(|c| *c.borrow_mut() = None);
    rt.block_on(publish_snapshot_and_compact(
        r,
        v.mock.as_ref(),
        PublishOf::Session(s.db),
    ))
}

/// A first mount's base snapshot publish (phase 2) for the session `s`.
fn base_publish(
    rt: &tokio::runtime::Runtime,
    v: &RotVol,
    r: &mut manager::OpenVolumeResult,
    mut s: Session,
) -> Result<JournalHead> {
    rt.block_on(journal_init_phase(r, v.mock.as_ref(), &mut s.db))
}

/// The local DB's lineage stamp.
fn db_stamp(v: &RotVol) -> Option<local_db::DbStamp> {
    let r = v.open();
    let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
    let c = local_db::open_read_only(&r.paths.db_path).unwrap();
    local_db::read_stamp(&c, &schema).unwrap()
}

/// The lineage stamp inside the snapshot volume.json names.
fn snapshot_stamp(v: &RotVol) -> Option<local_db::DbStamp> {
    let r = v.open();
    let id = r
        .config
        .metadata_snapshot_id
        .expect("a snapshot is recorded");
    let blob = v
        .mock
        .get_raw(id)
        .expect("the recorded snapshot is on the channel");
    let (_, db) = metadata_snapshot::decrypt_snapshot(&r.hierarchy.data, &blob).unwrap();
    let p = v.dir.path().join(format!("stamp-{id}.db"));
    std::fs::write(&p, db).unwrap();
    let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
    let c = local_db::open_read_only(&p).unwrap();
    let st = local_db::read_stamp(&c, &schema).unwrap();
    drop(c);
    metadata_snapshot::remove_db_files(&p).unwrap();
    st
}

/// After a publish (version volume.json records): the local DB, the snapshot
/// and the HEAD carry the same lineage, at that version, for this volume; the
/// DB is usable as it is and the next mount does not rebuild. Returns it.
fn assert_lineage_agrees(rt: &tokio::runtime::Runtime, v: &RotVol, when: &str) -> Lineage {
    let version = v.open().config.metadata_version;
    let head = head_of(v)
        .lineage
        .unwrap_or_else(|| panic!("{when}: the HEAD records no lineage"));
    let db = db_stamp(v).unwrap_or_else(|| panic!("{when}: the DB carries no stamp"));
    let snap = snapshot_stamp(v).unwrap_or_else(|| panic!("{when}: the snapshot carries no stamp"));
    assert_eq!(db.volume_id, v.id, "{when}: DB stamp names another volume");
    assert_eq!(db, snap, "{when}: the snapshot's stamp is not the DB's");
    assert_eq!(
        db.lineage, head,
        "{when}: the HEAD's lineage is not the DB's stamp"
    );
    assert_eq!(
        head.version, version,
        "{when}: lineage version != published version"
    );
    assert_eq!(
        local_db_state(&v.open()).unwrap(),
        LocalDb::Usable,
        "{when}"
    );
    let (_, s) = prep_ok(rt, v, when);
    assert!(
        !s.rebuilt,
        "{when}: the next mount rebuilt the volume's current DB"
    );
    head
}

/// The names in the root directory of the snapshot volume.json names.
fn latest_snapshot_names(v: &RotVol) -> Vec<String> {
    let r = v.open();
    let id = r
        .config
        .metadata_snapshot_id
        .expect("a snapshot is recorded");
    let blob = v
        .mock
        .get_raw(id)
        .expect("the recorded snapshot is on the channel");
    let (_, db) = metadata_snapshot::decrypt_snapshot(&r.hierarchy.data, &blob).unwrap();
    let p = v.dir.path().join(format!("names-{id}.db"));
    std::fs::write(&p, db).unwrap();
    let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
    let c = local_db::open_read_only(&p).unwrap();
    let mut n: Vec<String> = InodeStore::new(&c, &schema, &r.hierarchy.meta)
        .list_children(1)
        .unwrap()
        .into_iter()
        .map(|i| i.name)
        .collect();
    drop(c);
    metadata_snapshot::remove_db_files(&p).unwrap();
    n.sort();
    n
}

/// A volume whose first mount reserved a snapshot version and failed to
/// publish its base snapshot (reserved-only: version 0, no snapshot, no HEAD).
fn reserved_only_volume(rt: &tokio::runtime::Runtime) -> RotVol {
    let v = super::super::r9::new_volume();
    v.mock.set_metadata_budget(Some(0));
    {
        let (mut r, s) = prep_ok(rt, &v, "reserved-only: first mount");
        base_publish(rt, &v, &mut r, s).expect_err("the base publish must fail");
    }
    v.mock.set_metadata_budget(None);
    let c = v.open().config;
    assert!(c.metadata_version_reserved > 0 && c.metadata_version == 0);
    assert!(c.metadata_snapshot_id.is_none());
    assert!(!journal_head_path(&v.open()).exists());
    v
}

/// nv3b: the volume's OWN older metadata.db (a copy from before the last
/// session) is put back while journal.head and volume.json stay current. It
/// holds files, so the emptiness rule took it as the volume's and published
/// it, dropping the newest file. It is not the volume's current database: the
/// mount rebuilds, shows the newest file, and the newest snapshot holds every
/// file.
#[test]
fn nv3b_an_older_copy_of_the_volumes_own_db_is_rebuilt_not_published() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    own_root(&v);
    clean_unmount(&rt, &v);
    let db = v.open().paths.db_path.clone();
    let backup = std::fs::read(&db).unwrap();
    if with_mount(&rt, &v, |mp| {
        std::fs::write(mp.join("thesis"), b"a month of work").unwrap();
    })
    .is_none()
    {
        return;
    }
    let (mut r, s) = prep_ok(&rt, &v, "nv3b: session 2");
    unmount_publish(&rt, &v, &mut r, s).expect("nv3b: session 2 unmount");
    assert_eq!(latest_snapshot_names(&v), ["a", "b", "h", "thesis"]);
    assert_eq!(head_of(&v).seq, 0);
    metadata_snapshot::remove_db_files(&db).unwrap();
    std::fs::write(&db, &backup).unwrap();
    let state = local_db_state(&v.open()).unwrap();
    eprintln!("nv3b: the older copy put back: {state:?}");
    assert!(
        matches!(&state, LocalDb::NeedsRebuild(w) if w.contains("not the volume's current")),
        "nv3b: {state:?}"
    );
    let (mut r, s) = prep_ok(&rt, &v, "nv3b: session 3");
    assert!(s.rebuilt, "nv3b: the mount used the older copy");
    let mut seen = vec![];
    if with_mount(&rt, &v, |mp| seen = names(mp)).is_none() {
        return;
    }
    eprintln!("nv3b: the mount shows {seen:?}");
    assert_eq!(
        seen,
        ["a", "b", "h", "thesis"],
        "nv3b: the mount lost the newest file"
    );
    unmount_publish(&rt, &v, &mut r, s).expect("nv3b: session 3 unmount");
    eprintln!(
        "nv3b: newest snapshot holds {:?}",
        latest_snapshot_names(&v)
    );
    assert_eq!(latest_snapshot_names(&v), ["a", "b", "h", "thesis"]);
    assert_lineage_agrees(&rt, &v, "nv3b");
}

/// nv3: a DB that is not the volume's (created by another build after the
/// real one was lost) with one file in it is never published: the mount
/// rebuilds the volume's database instead, and the snapshot keeps its files.
#[test]
fn nv3_a_foreign_db_with_a_file_is_rebuilt_never_published() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    replace_with_empty_db(&v, true);
    {
        let r = v.open();
        let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
        let c = local_db::open_existing(&r.paths.db_path).unwrap();
        InodeStore::new(&c, &schema, &r.hierarchy.meta)
            .insert(&Inode::new_file(2, 1, "other".into(), 0o644, 1000, 1000))
            .unwrap();
        c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
    }
    let state = local_db_state(&v.open()).unwrap();
    eprintln!("nv3: local_db_state = {state:?}");
    let h = history(&rt, &v);
    eprintln!(
        "nv3: history -> {:?}",
        h.as_ref().map_err(|e| format!("{e:#}"))
    );
    assert!(
        h.is_err(),
        "nv3: history read a database that is not the volume's"
    );
    assert!(
        matches!(&state, LocalDb::NeedsRebuild(w) if w.contains("no lineage stamp")),
        "{state:?}"
    );
    let (mut r, s) = prep_ok(&rt, &v, "nv3");
    assert!(s.rebuilt);
    eprintln!(
        "nv3: after the mount's preparation the local DB holds {:?}",
        local_tree(&v)
    );
    assert_eq!(local_tree(&v).entries, 3, "nv3: the foreign DB was used");
    unmount_publish(&rt, &v, &mut r, s).expect("nv3: unmount");
    assert_eq!(latest_snapshot_names(&v), ["a", "b", "h"]);
    assert_files_exact(&rt, &v, "nv3");
}

/// nv1: a legitimately empty volume whose snapshot message is gone from the
/// group. The mount needs no fetch at HEAD seq 0; the user writes files
/// through a real mount; the unmount publish needs no fetch either and
/// publishes them. The next mount works.
#[test]
fn nv1_an_empty_volume_whose_snapshot_is_gone_publishes_without_a_fetch() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = empty_volume(&rt);
    own_root(&v);
    clean_unmount(&rt, &v);
    let snap = v.open().config.metadata_snapshot_id.unwrap();
    assert!(v.mock.drop_message(snap));
    let (mut r, s) = prep_ok(&rt, &v, "nv1: mount");
    if with_mount(&rt, &v, |mp| {
        std::fs::write(mp.join("x"), b"user data 1").unwrap();
        std::fs::write(mp.join("y"), b"user data 2").unwrap();
    })
    .is_none()
    {
        return;
    }
    let res = unmount_publish(&rt, &v, &mut r, s);
    eprintln!(
        "nv1: unmount publish -> {:?}",
        res.as_ref().map_err(|e| format!("{e:#}"))
    );
    res.expect("nv1: the unmount publish needs no fetch");
    assert_eq!(latest_snapshot_names(&v), ["x", "y"]);
    assert!(!marker(&v));
    assert_lineage_agrees(&rt, &v, "nv1: next mount");
}

/// nv1b: the same lost snapshot, sessions that change nothing: every unmount
/// publishes.
#[test]
fn nv1b_idle_sessions_over_a_lost_snapshot_publish() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = empty_volume(&rt);
    let snap = v.open().config.metadata_snapshot_id.unwrap();
    assert!(v.mock.drop_message(snap));
    for session in 1..=2 {
        let (mut r, s) = prep_ok(&rt, &v, "nv1b");
        let res = unmount_publish(&rt, &v, &mut r, s);
        eprintln!(
            "nv1b: session {session} unmount publish -> {:?}",
            res.as_ref().map_err(|e| format!("{e:#}"))
        );
        res.unwrap_or_else(|e| panic!("nv1b: session {session}: {e:#}"));
    }
}

/// nv1c: control: the lost snapshot of a volume with files; the publish heals.
#[test]
fn nv1c_a_volume_with_files_over_a_lost_snapshot_publishes() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    let snap = v.open().config.metadata_snapshot_id.unwrap();
    assert!(v.mock.drop_message(snap));
    let (mut r, s) = prep_ok(&rt, &v, "nv1c");
    unmount_publish(&rt, &v, &mut r, s).expect("nv1c: unmount");
    assert_eq!(latest_snapshot_names(&v), ["a", "b", "h"]);
}

/// nv1, crashed: the files are written, the session dies before its publish
/// (HEAD seq > 0), and the base snapshot is gone. The next mount cannot
/// rebuild; its error names the explicit recovery command.
#[test]
fn nv1_crashed_over_a_lost_base_snapshot_names_the_recovery_command() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = empty_volume(&rt);
    own_root(&v);
    clean_unmount(&rt, &v);
    if with_mount(&rt, &v, |mp| {
        std::fs::write(mp.join("x"), b"user data 1").unwrap();
        std::fs::write(mp.join("y"), b"user data 2").unwrap();
    })
    .is_none()
    {
        return;
    }
    assert!(head_of(&v).seq >= 2, "nv1: the writes were journaled");
    let base = head_of(&v).base_snapshot_msg_id;
    assert!(v.mock.drop_message(base));
    let msgs = v.mock.message_count();
    let (_, s) = prep(&rt, &v);
    let msg = format!("{:#}", s.err().expect("nv1: the mount cannot rebuild"));
    eprintln!("nv1: next mount: {msg}");
    assert!(
        msg.contains("teagarden volume republish rot --from-local-db"),
        "{msg}"
    );
    assert_eq!(
        v.mock.message_count(),
        msgs,
        "nv1: the failed mount uploaded"
    );
    // The explicit recovery: the local DB (which committed x and y) wins.
    let published = rt
        .block_on(crate::commands::volume::republish_core(
            v.open(),
            v.mock.as_ref(),
            "rot",
            false,
            false,
            &mut |prompt: &str| {
                eprintln!("nv1: republish asks: {prompt}");
                Ok(true)
            },
        ))
        .expect("nv1: republish --from-local-db");
    assert!(published);
    assert_eq!(head_of(&v).seq, 0, "nv1: the HEAD was not reset");
    assert_eq!(
        latest_snapshot_names(&v),
        ["x", "y"],
        "nv1: the local entries"
    );
    assert_lineage_agrees(&rt, &v, "nv1: after republish");
    let (mut r, s) = prep_ok(&rt, &v, "nv1: mount after republish");
    let mut seen = vec![];
    if with_mount(&rt, &v, |mp| {
        seen = names(mp);
        assert_eq!(std::fs::read(mp.join("x")).unwrap(), b"user data 1");
    })
    .is_none()
    {
        return;
    }
    assert_eq!(seen, ["x", "y"]);
    unmount_publish(&rt, &v, &mut r, s).expect("nv1: unmount after republish");
}

/// `volume republish --from-local-db` refuses, changing and uploading
/// nothing (and contacting no transport), while the volume is mounted, while
/// another command holds its lock (exclusive: a mount, a restore; shared:
/// `history`), and when the local DB is missing, unreadable or rootless. A
/// declined confirmation changes nothing either.
#[test]
fn republish_refuses_while_mounted_or_locked_and_an_unusable_db() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    own_root(&v);
    clean_unmount(&rt, &v);
    let pass = pass_file(&v);
    let base = v.open().paths.base_dir.clone();
    let republish_in = |what: &str| {
        let r = rt.block_on(crate::commands::volume::republish_in(
            v.dir.path(),
            &v.id,
            Some(&pass),
            None,
            true,
            false,
            Box::new(|_| Box::pin(async { panic!("Telegram must not be contacted") })),
        ));
        let msg = format!("{:#}", r.expect_err(what));
        eprintln!("republish {what}: {msg}");
        msg
    };
    let before = published_state(&v);
    let db_before = std::fs::read(v.open().paths.db_path).unwrap();
    for shared in [false, true] {
        let lock = if shared {
            manager::VolumeLock::acquire_shared(&base)
        } else {
            manager::VolumeLock::acquire_exclusive(&base)
        }.expect("the previous owner guard must have released its lock immediately");
        let msg = republish_in(&format!("locked (shared: {shared})"));
        assert!(
            msg.contains("in use") && msg.contains("Nothing was changed"),
            "{msg}"
        );
        drop(lock);
    }
    let mounted = with_mount_opts(
        &rt,
        &v,
        &[
            fuser::MountOption::FSName(format!("teagarden:{}", v.id)),
            fuser::MountOption::Subtype("teagarden".into()),
        ],
        |_| {
            let msg = republish_in("while mounted");
            assert!(msg.contains("currently mounted"), "{msg}");
        },
    );
    assert_nothing_published(&v, &before, "republish refusals");
    if mounted.is_some() {
        // The mount opened the DB; it may have checkpointed, not changed it.
        assert_eq!(local_tree(&v).entries, 3);
    } else {
        assert!(std::fs::read(v.open().paths.db_path).unwrap() == db_before);
    }
    // Declined.
    let declined = rt
        .block_on(crate::commands::volume::republish_core(
            v.open(),
            v.mock.as_ref(),
            "rot",
            false,
            false,
            &mut |_: &str| Ok(false),
        ))
        .unwrap();
    assert!(!declined);
    assert_nothing_published(&v, &before, "republish declined");
    // An unusable DB: missing, unreadable, rootless.
    let db = v.open().paths.db_path.clone();
    for how in ["missing", "unreadable", "rootless"] {
        metadata_snapshot::remove_db_files(&db).unwrap();
        match how {
            "missing" => {}
            "unreadable" => std::fs::write(&db, vec![0x5Au8; 8192]).unwrap(),
            _ => replace_with_empty_db(&v, false),
        }
        // Every flag: the refusal is the DB's own, not a guard rail's.
        let r = rt.block_on(crate::commands::volume::republish_core(
            v.open(),
            v.mock.as_ref(),
            "rot",
            true,
            true,
            &mut |_: &str| panic!("must refuse before asking"),
        ));
        let msg = format!("{:#}", r.expect_err(how));
        eprintln!("republish of a {how} DB: {msg}");
        assert!(msg.contains("Nothing was changed"), "{msg}");
        let why = match how {
            "missing" => "is missing",
            "unreadable" => "cannot be read",
            _ => "has no root directory",
        };
        assert!(msg.contains(why), "{how}: {msg}");
        assert_nothing_published(&v, &before, &format!("republish of a {how} DB"));
    }
}

/// nv2: a reserved-only volume (its first mount reserved a version and failed
/// to publish) that "needs a rebuild": a forged marker, a missing DB, a torn
/// DB. Nothing was ever published, so nothing can be rebuilt; it holds no
/// user data (that first mount stopped before FUSE). Each mount succeeds and
/// publishes its base snapshot; so does the control.
#[test]
fn nv2_a_reserved_only_volume_that_needs_a_rebuild_mounts() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    for how in [
        "forged marker",
        "db missing",
        "db torn",
        "nothing (control)",
    ] {
        let v = reserved_only_volume(&rt);
        // The failed first mount stopped before the filesystem was served:
        // its DB holds the root directory and nothing else.
        assert_eq!(
            local_tree(&v),
            local_db::TreeSummary {
                has_root: true,
                entries: 0
            }
        );
        let db = v.open().paths.db_path.clone();
        match how {
            "forged marker" => {
                teagarden_core::volume::rebuild_marker::mark(&v.open().paths.base_dir, "forged")
                    .unwrap()
            }
            "db missing" => metadata_snapshot::remove_db_files(&db).unwrap(),
            "db torn" => {
                metadata_snapshot::remove_db_files(&db).unwrap();
                std::fs::write(&db, vec![0x5Au8; 8192]).unwrap()
            }
            _ => {}
        }
        let (mut r, s) = prep(&rt, &v);
        let s = begin(s.unwrap_or_else(|e| panic!("nv2 [{how}]: mount: {e:#}")));
        let j = base_publish(&rt, &v, &mut r, s);
        eprintln!(
            "nv2 [{how}]: mount OK, base publish {:?}",
            j.as_ref().map(|_| ()).map_err(|e| format!("{e:#}"))
        );
        j.unwrap_or_else(|e| panic!("nv2 [{how}]: base publish: {e:#}"));
        assert!(!marker(&v), "nv2 [{how}]: the marker stayed");
        assert_lineage_agrees(&rt, &v, &format!("nv2 [{how}]"));
        assert!(latest_snapshot_summary(&v).has_root, "nv2 [{how}]");
        assert_eq!(
            local_db_state(&v.open()).unwrap(),
            LocalDb::Usable,
            "nv2 [{how}]"
        );
        history(&rt, &v).unwrap_or_else(|e| panic!("nv2 [{how}]: history: {e:#}"));
        let (mut r, s) = prep_ok(&rt, &v, &format!("nv2 [{how}]: second mount"));
        unmount_publish(&rt, &v, &mut r, s)
            .unwrap_or_else(|e| panic!("nv2 [{how}]: second unmount: {e:#}"));
        if how == "db torn" {
            let aside: Vec<_> = ls_dir(&v)
                .into_iter()
                .filter(|n| n.starts_with("metadata.db.unusable."))
                .collect();
            eprintln!("nv2 [{how}]: kept aside: {aside:?}");
            assert_eq!(
                aside.len(),
                1,
                "nv2 [{how}]: the torn DB was not kept aside"
            );
        }
    }
}

/// nv6 (observation b): a torn DB on a volume that never published (a first
/// mount killed while it wrote the DB) is set aside and the mount creates the
/// DB, never failing with a raw "file is not a database".
#[test]
fn nv6_a_torn_db_on_a_never_published_volume_is_set_aside() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = super::super::r9::new_volume();
    std::fs::write(&v.open().paths.db_path, vec![0x5Au8; 4096]).unwrap();
    for attempt in 1..=2 {
        let (mut r, s) = prep(&rt, &v);
        let s = begin(s.unwrap_or_else(|e| panic!("nv6: mount {attempt}: {e:#}")));
        if attempt == 1 {
            base_publish(&rt, &v, &mut r, s).expect("nv6: base publish");
        } else {
            unmount_publish(&rt, &v, &mut r, s).expect("nv6: unmount");
        }
    }
    assert!(latest_snapshot_summary(&v).has_root);
}

/// nv5: a first mount (of an earlier build) died between creating the schema
/// and inserting the root. The next mount must not publish a rootless base
/// snapshot that then makes every later command refuse.
#[test]
fn nv5_a_first_mount_killed_before_the_root_leaves_a_usable_volume() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = super::super::r9::new_volume();
    {
        let r = v.open();
        let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
        let c = rusqlite::Connection::open(&r.paths.db_path).unwrap();
        initialize_database(&c, &schema).unwrap();
    }
    let (mut r, s) = prep_ok(&rt, &v, "nv5: second mount");
    base_publish(&rt, &v, &mut r, s).expect("nv5: base publish");
    assert!(
        latest_snapshot_summary(&v).has_root,
        "nv5: a rootless base snapshot"
    );
    let state = local_db_state(&v.open()).unwrap();
    eprintln!("nv5: state after the second mount = {state:?}");
    assert_eq!(state, LocalDb::Usable);
    history(&rt, &v).expect("nv5: history");
    for attempt in 3..=4 {
        let (mut r, s) = prep_ok(&rt, &v, "nv5");
        unmount_publish(&rt, &v, &mut r, s)
            .unwrap_or_else(|e| panic!("nv5: mount {attempt}: {e:#}"));
        assert_eq!(local_db_state(&v.open()).unwrap(), LocalDb::Usable);
    }
}

/// nv7: `history` on a volume whose last session did not end cleanly (HEAD
/// seq > 0) reads the local database: it is the volume's.
#[test]
fn nv7_history_after_an_unclean_session_reads_the_local_db() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut v = rot_volume(&rt);
    let lineage = head_of(&v).lineage;
    session_crashes_before_snapshot(&rt, &mut v, 1);
    assert!(head_of(&v).seq > 0);
    assert!(lineage.is_some());
    assert_eq!(
        head_of(&v).lineage,
        lineage,
        "nv7: the journal dropped the lineage"
    );
    assert_eq!(
        db_stamp(&v).map(|s| s.lineage),
        lineage,
        "nv7: the failed publish left its stamp"
    );
    assert_eq!(local_db_state(&v.open()).unwrap(), LocalDb::Usable);
    // history adds only the lock file and (empty) WAL sidecars (N8).
    let files = |v: &RotVol| -> Vec<String> {
        ls_dir(v)
            .into_iter()
            .filter(|n| {
                !["volume.lock", "metadata.db-wal", "metadata.db-shm"].contains(&n.as_str())
            })
            .collect()
    };
    let before = files(&v);
    let db = std::fs::read(v.open().paths.db_path).unwrap();
    history(&rt, &v).expect("nv7: history");
    assert_eq!(files(&v), before);
    assert!(
        std::fs::read(v.open().paths.db_path).unwrap() == db,
        "nv7: history wrote the DB"
    );
}

/// nv8: volume.json's snapshot id (outside the MAC) is stripped and the DB
/// replaced by an empty one. (a) With the HEAD present, the mount rebuilds
/// from the HEAD's base and the unmount republishes every file. (b) With the
/// HEAD deleted too, nothing names a snapshot to rebuild from: the mount
/// fails, uploads nothing, and names the recovery command.
#[test]
fn nv8_a_stripped_snapshot_id() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    for head_too in [false, true] {
        let when = format!("nv8 [HEAD deleted: {head_too}]");
        let v = rot_volume(&rt);
        replace_with_empty_db(&v, true);
        let r = v.open();
        let mut j: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&r.paths.config_path).unwrap()).unwrap();
        j["metadata_snapshot_id"] = serde_json::Value::Null;
        std::fs::write(&r.paths.config_path, serde_json::to_vec_pretty(&j).unwrap()).unwrap();
        if head_too {
            std::fs::remove_file(journal_head_path(&r)).unwrap();
        }
        let msgs = v.mock.message_count();
        let (mut r, s) = prep(&rt, &v);
        if head_too {
            let msg = format!("{:#}", s.err().expect("must fail"));
            eprintln!("{when}: mount: {msg}");
            assert!(
                msg.contains("teagarden volume republish rot --from-local-db"),
                "{msg}"
            );
            assert_eq!(v.mock.message_count(), msgs, "{when}: uploaded");
        } else {
            let s = begin(s.unwrap_or_else(|e| panic!("{when}: mount: {e:#}")));
            assert_eq!(local_tree(&v).entries, 3, "{when}: not rebuilt");
            unmount_publish(&rt, &v, &mut r, s).expect("unmount");
            assert_eq!(latest_snapshot_names(&v), ["a", "b", "h"]);
        }
    }
}

/// Observation c: the stale-snapshot report of a volume that records a
/// published version but names no snapshot message does not claim it has
/// none on Telegram, nor that mounting and unmounting fixes it.
#[test]
fn nv8c_the_stale_report_of_a_volume_whose_snapshot_id_is_gone_is_accurate() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    let r = v.open();
    let mut j: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&r.paths.config_path).unwrap()).unwrap();
    j["metadata_snapshot_id"] = serde_json::Value::Null;
    std::fs::write(&r.paths.config_path, serde_json::to_vec_pretty(&j).unwrap()).unwrap();
    v.mock.set_connected(false);
    let mut r = v.open();
    let s = rt.block_on(crate::commands::volume::publish_as_new_session(
        &mut r,
        v.mock.as_ref(),
    ));
    let e = format!("{:#}", s.expect_err("the transport is down"));
    let status = format!(
        "{:#}",
        crate::commands::volume::snapshot_publish_status(&v.open().paths.base_dir).unwrap_err()
    );
    eprintln!("nv8c: publish: {e}\nnv8c: volume unmount reads: {status}");
    for m in [&e, &status] {
        assert!(
            !m.contains("no metadata snapshot on Telegram at all"),
            "{m}"
        );
        assert!(m.contains("version 1"), "{m}");
    }
}

/// nv9: the base snapshot the HEAD names is served with other bytes (an
/// authentic empty snapshot of this volume at the same version). The DB that
/// is not the volume's is not used, the substituted snapshot is refused, and
/// nothing is uploaded.
#[test]
fn nv9_a_substituted_base_snapshot_is_refused() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    let r = v.open();
    let id = r.config.metadata_snapshot_id.unwrap();
    let empty_db = {
        let p = v.dir.path().join("e.db");
        let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
        let c = rusqlite::Connection::open(&p).unwrap();
        initialize_database(&c, &schema).unwrap();
        InodeStore::new(&c, &schema, &r.hierarchy.meta)
            .insert(&Inode::root())
            .unwrap();
        c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        drop(c);
        std::fs::read(&p).unwrap()
    };
    let forged = metadata_snapshot::encrypt_snapshot(
        &r.hierarchy.data,
        r.config.metadata_version,
        &empty_db,
    )
    .unwrap();
    v.mock.put_raw(id, forged);
    replace_with_empty_db(&v, true);
    let msgs = v.mock.message_count();
    let (_, s) = prep(&rt, &v);
    let msg = format!("{:#}", s.err().expect("nv9: the mount must refuse"));
    eprintln!("nv9: mount: {msg}");
    assert_eq!(v.mock.message_count(), msgs, "nv9: uploaded");
}

/// nv10: `history` between its unlock and its lock: volume.json changed.
#[test]
fn nv10_history_refuses_when_volume_json_changed_after_unlock() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    let pass = pass_file(&v);
    let result =
        crate::commands::utils::open_volume_any(&v.id, Some(&pass), None, v.dir.path()).unwrap();
    clean_unmount(&rt, &v);
    let r = crate::commands::volume::ensure_config_unchanged(&result);
    eprintln!("nv10: {:?}", r.as_ref().map_err(|e| format!("{e:#}")));
    assert!(format!("{:#}", r.unwrap_err()).contains("changed on disk"));
}

/// nv10 (M1), through `volume history` itself: another writer changes
/// volume.json (here it reserves a snapshot version, as a publish does)
/// after `history` unlocked the volume and before it took the lock. `history`
/// must refuse, and read nothing; `volume diff` likewise.
#[test]
fn nv10_history_and_diff_refuse_a_volume_json_changed_between_unlock_and_lock() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    for (what, run) in [
        (
            "history",
            history as fn(&tokio::runtime::Runtime, &RotVol) -> Result<()>,
        ),
        ("diff", diff),
    ] {
        let (dir, id) = (v.dir.path().to_path_buf(), v.id.clone());
        crate::commands::history::AFTER_UNLOCK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                let mut r = manager::open_volume(&id, ROT_PASS, &dir).unwrap();
                r.config.metadata_version_reserved += 1;
                manager::save_config_resealed(&mut r.config, &r.hierarchy, &r.paths.config_path)
                    .unwrap();
            }));
        });
        let res = run(&rt, &v);
        let msg = format!("{:#}", res.expect_err(&format!("{what} must refuse")));
        eprintln!("nv10 {what}: {msg}");
        assert!(msg.contains("changed on disk"), "{msg}");
    }
}

/// The base snapshot publish of a session whose connection is OPEN (as a
/// mount's and `revert`'s are: the filesystem holds the prepared connection
/// while phase 2 publishes): the stamp is written through a second connection
/// and must be checkpointed into the file the snapshot reads. Driven through
/// `revert` on a volume without journal.head whose DB is missing (rebuilt from
/// the snapshot volume.json names, then journal_init_phase with the
/// connection open). (With a readable DB and no journal.head the mount
/// refuses instead: `t1_a_lost_journal_head_never_replaces_a_readable_db`.)
#[test]
fn a_base_publish_stamps_the_db_while_the_sessions_connection_is_open() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut v = rot_volume(&rt);
    std::fs::remove_file(journal_head_path(&v.open())).unwrap();
    metadata_snapshot::remove_db_files(&v.open().paths.db_path).unwrap();
    rt.block_on(crate::commands::volume::revert_core(
        v.open(),
        v.transport(),
        "/h",
        1,
    ))
    .expect("revert on a volume without journal.head");
    v.expect.insert(4, v.h_versions[0].clone());
    assert_lineage_agrees(
        &rt,
        &v,
        "revert after a base publish with the connection open",
    );
    assert_files_exact(
        &rt,
        &v,
        "revert after a base publish with the connection open",
    );
}

/// journal.head cannot be read (it does not authenticate, or is not JSON):
/// for the openers that do not rebuild, that is "must be rebuilt", like any
/// other DB the HEAD does not vouch for, not a raw error: `history` refuses
/// with the rebuild instruction, and `volume delete --local-only` still
/// deletes the local volume. A mount cannot rebuild without a HEAD it can
/// trust: it refuses, uploads nothing, and names `volume restore
/// --discard-journal` (which then works) and `volume republish`.
#[test]
fn an_unreadable_journal_head_reads_as_needs_rebuild() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    for how in ["MAC mismatch", "not JSON"] {
        let v = rot_volume(&rt);
        let hp = journal_head_path(&v.open());
        if how == "not JSON" {
            std::fs::write(&hp, b"\x5a\x5a torn").unwrap();
        } else {
            let mut j: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&hp).unwrap()).unwrap();
            j["seq"] = 7.into();
            std::fs::write(&hp, serde_json::to_vec(&j).unwrap()).unwrap();
        }
        let state = local_db_state(&v.open());
        eprintln!("unreadable HEAD [{how}]: {state:?}");
        assert!(
            matches!(&state, Ok(LocalDb::NeedsRebuild(w)) if w.contains("journal.head")),
            "[{how}] {state:?}"
        );
        assert_refused_as_needing_rebuild(&format!("[{how}] history"), history(&rt, &v));
        // The mount cannot rebuild without a HEAD it can trust: it refuses,
        // changing nothing, and names both ways out.
        let msgs = v.mock.message_count();
        let (_, s) = prep(&rt, &v);
        let msg = format!("{:#}", s.err().expect("the mount must refuse"));
        eprintln!("[{how}] mount: {msg}");
        assert!(
            msg.contains("teagarden volume restore rot --discard-journal"),
            "{msg}"
        );
        assert!(
            msg.contains("teagarden volume republish rot --from-local-db"),
            "{msg}"
        );
        assert_eq!(v.mock.message_count(), msgs, "[{how}] the mount uploaded");
        if how == "MAC mismatch" {
            // The first way out works over the unreadable HEAD.
            restore(&rt, &v).expect("restore --discard-journal over an unreadable HEAD");
            // A restore records a NEW lineage (not the snapshot's own stamp).
            assert_eq!(db_stamp(&v).map(|s| s.lineage), head_of(&v).lineage);
            assert_eq!(local_db_state(&v.open()).unwrap(), LocalDb::Usable);
            let (_, s) = prep_ok(&rt, &v, &format!("[{how}] after restore"));
            assert!(!s.rebuilt, "[{how}] the mount after the restore rebuilt");
            assert_files_exact(&rt, &v, &format!("[{how}] after restore"));
            // Unreadable again, for the delete below.
            std::fs::write(&hp, b"\x5a").unwrap();
        }
        let pass = pass_file(&v);
        let base = v.open().paths.base_dir.clone();
        rt.block_on(crate::commands::volume::delete_in(
            v.dir.path(),
            &v.id,
            true,
            Some(&pass),
            None,
            true,
            Box::new(|_| Box::pin(async { anyhow::bail!("Telegram must not be contacted") })),
        ))
        .unwrap_or_else(|e| panic!("[{how}] delete --local-only: {e:#}"));
        assert!(
            !base.exists(),
            "[{how}] the volume directory is still there"
        );
    }
}

/// Every fetch a rebuild needs that fails names the explicit recovery, and
/// changes and uploads nothing: a volume without journal.head whose snapshot
/// (the one volume.json names) is gone, and whose DB has no root directory (so
/// the mount must fetch: with a readable, rooted DB and no journal.head it
/// refuses before any fetch, see
/// `t1_a_lost_journal_head_never_replaces_a_readable_db`).
#[test]
fn every_failed_recovery_fetch_names_republish() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let hint = "teagarden volume republish rot --from-local-db";
    let refused = |v: &RotVol, when: &str| {
        let msgs = v.mock.message_count();
        let db = std::fs::read(v.open().paths.db_path).unwrap();
        let (_, s) = prep(&rt, v);
        let msg = format!("{:#}", s.err().unwrap_or_else(|| panic!("{when}: mounted")));
        eprintln!("{when}: {msg}");
        assert!(msg.contains(hint), "{when}: {msg}");
        assert!(msg.contains("Nothing was changed"), "{when}: {msg}");
        assert_eq!(v.mock.message_count(), msgs, "{when}: uploaded");
        assert!(
            std::fs::read(v.open().paths.db_path).unwrap() == db,
            "{when}: DB changed"
        );
    };
    let v = rot_volume(&rt);
    let id = v.open().config.metadata_snapshot_id.unwrap();
    std::fs::remove_file(journal_head_path(&v.open())).unwrap();
    replace_with_empty_db(&v, false);
    assert!(v.mock.drop_message(id));
    refused(&v, "(c) no journal.head, volume.json's snapshot gone");
}

// ── the stamp at every publish, and the windows around it ───────────────────

/// Every way a DB becomes or is published as a snapshot version stamps it: a
/// clean unmount, a first mount's base snapshot, `revert`, `key rotate`,
/// `volume restore`. Each time the DB, the snapshot and the HEAD agree, at
/// the new version, under a NEW nonce, and the next mount uses the DB as it is.
#[test]
fn every_publish_stamps_the_db_with_a_new_lineage_that_the_head_records() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut seen: Vec<Lineage> = vec![];
    let mut fresh = |l: Lineage, when: &str| {
        assert!(
            !seen.iter().any(|o| o.nonce == l.nonce),
            "{when}: an old nonce was reused"
        );
        seen.push(l);
    };
    // A first mount's base snapshot.
    let v = super::super::r9::new_volume();
    let (mut r, s) = prep_ok(&rt, &v, "first mount");
    let created = db_stamp(&v).expect("the created DB carries a stamp");
    assert_eq!(
        (created.volume_id.as_str(), created.lineage.version),
        (v.id.as_str(), 0)
    );
    base_publish(&rt, &v, &mut r, s).unwrap();
    fresh(
        assert_lineage_agrees(&rt, &v, "first mount's base snapshot"),
        "base",
    );
    // Clean unmounts.
    let mut v = rot_volume(&rt);
    fresh(assert_lineage_agrees(&rt, &v, "fixture publish"), "fixture");
    for i in 0..2 {
        clean_unmount(&rt, &v);
        fresh(
            assert_lineage_agrees(&rt, &v, "clean unmount"),
            &format!("unmount {i}"),
        );
    }
    // revert (a journaled change, then its publish).
    rt.block_on(crate::commands::volume::revert_core(
        v.open(),
        v.transport(),
        "/h",
        1,
    ))
    .expect("revert");
    v.expect.insert(4, v.h_versions[0].clone());
    fresh(assert_lineage_agrees(&rt, &v, "revert"), "revert");
    // key rotate (unjournaled row changes, then its publish).
    rotate_with(&rt, &v, &|_| {}).expect("rotate");
    fresh(assert_lineage_agrees(&rt, &v, "rotate"), "rotate");
    assert_files_exact(&rt, &v, "after rotate");
    // volume restore of the current snapshot.
    restore(&rt, &v).expect("restore");
    fresh(head_of(&v).lineage.unwrap(), "restore");
    assert_eq!(
        db_stamp(&v).map(|s| s.lineage),
        head_of(&v).lineage,
        "restore"
    );
    assert_eq!(
        local_db_state(&v.open()).unwrap(),
        LocalDb::Usable,
        "restore"
    );
    let (_, s) = prep_ok(&rt, &v, "after restore");
    assert!(!s.rebuilt, "the mount after a restore rebuilt");
    assert_files_exact(&rt, &v, "after restore");
}

/// S3: a copy of the volume's OWN current DB whose stamp names another volume
/// (same version, same nonce) is not this volume's database: rebuilt.
#[test]
fn a_stamp_naming_another_volume_is_rebuilt() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rot_volume(&rt);
    let mut st = db_stamp(&v).unwrap();
    st.volume_id = "00000000-0000-4000-8000-000000000000".into();
    let r = v.open();
    let schema = OpaqueSchema::new(r.hierarchy.schema.clone(), &logical_tables());
    local_db::stamp_db_file(&r.paths.db_path, &schema, Some(&st)).unwrap();
    let state = local_db_state(&v.open()).unwrap();
    eprintln!("S3: {state:?}");
    assert!(matches!(&state, LocalDb::NeedsRebuild(w) if w.contains("another volume")));
    assert!(
        history(&rt, &v).is_err(),
        "S3: history used another volume's DB"
    );
    let (_, s) = prep_ok(&rt, &v, "S3");
    assert!(s.rebuilt, "S3: the mount used another volume's DB");
    assert_eq!(db_stamp(&v).unwrap().volume_id, v.id);
    assert_files_exact(&rt, &v, "S3");
}

/// A publish that fails after it stamped the DB (the upload, here) puts the
/// replaced stamp back: the DB is the volume's current one again, `history`
/// works and the next mount does not rebuild. One killed in that window
/// leaves the new stamp, which the HEAD does not record: the next mount
/// rebuilds from the HEAD's snapshot and journal, losing nothing.
#[test]
fn a_publish_that_fails_after_the_stamp_never_loses_data() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    // Failed: the stamp is put back.
    let v = rot_volume(&rt);
    let before = db_stamp(&v).unwrap();
    v.mock.set_connected(false);
    let mut r = v.open();
    rt.block_on(crate::commands::volume::publish_as_new_session(&mut r, v.mock.as_ref()))
        .expect_err("the transport is down");
    v.mock.set_connected(true);
    assert_eq!(
        db_stamp(&v),
        Some(before),
        "the replaced stamp was not put back"
    );
    assert_eq!(local_db_state(&v.open()).unwrap(), LocalDb::Usable);
    history(&rt, &v).expect("history after a failed publish");
    let (_, s) = prep_ok(&rt, &v, "after a failed publish");
    assert!(!s.rebuilt);
    // Killed: the real publish is dropped while its snapshot upload is in
    // flight (after the stamp, before the HEAD reset): the DB keeps the new
    // stamp, at the version the publish reserved; the HEAD the old lineage.
    let mut v = rot_volume(&rt);
    session_crashes_before_snapshot(&rt, &mut v, 1);
    let old = head_of(&v).lineage;
    v.mock.set_hang_metadata(true);
    let mut r = v.open();
    let killed = rt.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_millis(500),
            crate::commands::volume::publish_as_new_session(&mut r, v.mock.as_ref()),
        )
        .await
    });
    v.mock.set_hang_metadata(false);
    assert!(killed.is_err(), "the publish was not interrupted");
    let reserved = v.open().config.metadata_version_reserved;
    let left = db_stamp(&v).expect("the killed publish left a stamp");
    eprintln!(
        "killed publish: DB stamped {}, HEAD records {:?}",
        left.lineage, old
    );
    assert_eq!(
        left.lineage.version, reserved,
        "stamped at the reserved version"
    );
    assert_eq!(head_of(&v).lineage, old, "the HEAD moved");
    let state = local_db_state(&v.open()).unwrap();
    assert!(matches!(&state, LocalDb::NeedsRebuild(w) if w.contains("not the volume's current")));
    let (mut r, s) = prep_ok(&rt, &v, "after a killed publish");
    assert!(s.rebuilt);
    assert_files_exact(&rt, &v, "after a killed publish (journaled change kept)");
    unmount_publish(&rt, &v, &mut r, s).unwrap();
    assert_lineage_agrees(&rt, &v, "after a killed publish");
}

/// `key rotate` changes block rows WITHOUT journaling them, then publishes. A
/// publish that fails puts the stamp back, so the re-run resumes on the
/// re-pointed rows. A rotation killed after its publish stamped the DB leaves
/// a DB that is not the volume's current one: rotate refuses, the next mount
/// rebuilds the pre-rotation rows (whose old messages still exist: nothing is
/// deleted before the HEAD names the new snapshot), and the re-run rotates
/// them again. Every file reads back byte-exact throughout.
#[test]
fn a_rotation_whose_publish_fails_or_is_killed_after_the_stamp_loses_nothing() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    for killed in [false, true] {
        let when = format!(
            "rotate publish {}",
            if killed { "killed" } else { "failed" }
        );
        let v = rot_volume(&rt);
        let r0 = if killed {
            // The real rotation, dropped while its snapshot upload is in
            // flight: its rows are re-pointed and the DB carries the new
            // stamp; the HEAD still names the pre-rotation snapshot.
            let t = v.transport();
            let connect: ConnectTransport<'_> = Box::new(move || Box::pin(async move { Some(t) }));
            let mock = v.mock.clone();
            let at = move |s: RotateStep| {
                if s == RotateStep::AllBlocksDone {
                    mock.set_hang_metadata(true);
                }
            };
            let out = rt.block_on(async {
                tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    rotate_core("rot", v.open(), connect, &at),
                )
                .await
            });
            v.mock.set_hang_metadata(false);
            assert!(out.is_err(), "{when}: the rotation was not interrupted");
            None
        } else {
            Some(rotate_with(&rt, &v, &|s| {
                if s == RotateStep::AllBlocksDone {
                    v.mock.set_metadata_budget(Some(0));
                }
            }))
        };
        v.mock.set_metadata_budget(None);
        if killed {
            let st = db_stamp(&v).expect("a stamp");
            assert_eq!(
                st.lineage.version,
                v.open().config.metadata_version_reserved
            );
            let msg = format!(
                "{:#}",
                rotate_claims(&rt, &v).map(|_| ()).expect_err("refuse")
            );
            eprintln!("{when}: rotate re-run: {msg}");
            assert!(msg.contains("not the volume's current"), "{msg}");
            let (_, s) = prep_ok(&rt, &v, &when);
            assert!(s.rebuilt, "{when}");
        } else {
            let e = r0.unwrap().expect_err("the publish must fail");
            eprintln!("{when}: {e:#}");
            assert_eq!(
                local_db_state(&v.open()).unwrap(),
                LocalDb::Usable,
                "{when}"
            );
        }
        assert_files_exact(&rt, &v, &format!("{when}: before the re-run"));
        let c = rotate_claims(&rt, &v).unwrap_or_else(|e| panic!("{when}: re-run: {e:#}"));
        assert!(c.complete, "{when}: incomplete");
        assert_rotation_complete(&v, &when);
        assert_files_exact(&rt, &v, &format!("{when}: after the re-run"));
        assert_lineage_agrees(&rt, &v, &when);
    }
}
