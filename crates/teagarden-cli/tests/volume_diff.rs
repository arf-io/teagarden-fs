//! `volume diff` through the shipped binary: two versions of one file, compared
//! by their manifest id prefixes. The volume is offline (no Telegram), every
//! child gets an isolated HOME / config dir, and no Telegram credentials.

use std::process::Command as StdCommand;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

use teagarden_core::block::pointer::{BlockPointer, FileManifest};
use teagarden_core::metadata::inode::Inode;
use teagarden_core::volume::manager;
use teagarden_store::inode_store::InodeStore;
use teagarden_store::manifest_store::ManifestStore;
use teagarden_store::migrations::initialize_database;
use teagarden_store::opaque_schema::OpaqueSchema;
use teagarden_store::schema::logical_tables;

const PASS: &str = "volume-diff-test-pass";

fn block(tag: u8, offset: u64, len: u64) -> BlockPointer {
    BlockPointer {
        block_id: [tag; 32],
        message_id: tag as i64,
        file_offset: offset,
        length: len,
        block_data_offset: 0,
        encrypted_size: len + 40,
        compressed: false,
        epoch: 0,
    }
}

struct Vol {
    volumes: TempDir,
    home: TempDir,
    id: String,
    pass_file: std::path::PathBuf,
    /// Hex manifest ids of /f version 1 and version 2.
    v1: String,
    v2: String,
}

impl Vol {
    fn cli(&self) -> Command {
        #[allow(deprecated)]
        let mut c = StdCommand::new(assert_cmd::cargo::cargo_bin("teagarden"));
        c.env("TEAGARDEN_VOLUMES_DIR", self.volumes.path())
            .env("HOME", self.home.path())
            .env("XDG_CONFIG_HOME", self.home.path().join(".config"))
            .env(
                "TEAGARDEN_CONFIG_DIR",
                self.home.path().join(".config").join("teagarden"),
            )
            .env("XDG_DATA_HOME", self.home.path().join(".local/share"))
            .env(
                "TEAGARDEN_SESSION_PATH",
                self.home.path().join("none.session"),
            )
            .env_remove("TG_API_ID")
            .env_remove("TG_API_HASH");
        Command::from_std(c)
    }

    fn diff(&self, a: &str, b: &str) -> assert_cmd::assert::Assert {
        self.cli()
            .args(["volume", "diff", &self.id, a, b, "--password-file"])
            .arg(&self.pass_file)
            .assert()
    }
}

/// A volume whose /f has v1 = blocks [A(1000), B(2000)] and v2 = [B(2000), C(3000)].
fn volume_with_two_versions() -> Vol {
    let volumes = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let created = manager::create_volume(
        Some("diffvol"),
        PASS.as_bytes(),
        volumes.path(),
        0,
        0,
        0,
        None,
    )
    .unwrap();
    let id = created.config.volume_id.to_string();
    let result = manager::open_volume(&id, PASS.as_bytes(), volumes.path()).unwrap();
    let schema = OpaqueSchema::new(result.hierarchy.schema.clone(), &logical_tables());
    let conn = rusqlite::Connection::open(&result.paths.db_path).unwrap();
    initialize_database(&conn, &schema).unwrap();
    let is = InodeStore::new(&conn, &schema, &result.hierarchy.meta);
    let ms = ManifestStore::new(&conn, &schema, &result.hierarchy.meta);
    is.insert(&Inode::root()).unwrap();

    let v1 = FileManifest {
        inode: 2,
        version: 1,
        total_size: 3000,
        file_hash: [1; 32],
        blocks: vec![block(0xA1, 0, 1000), block(0xB2, 1000, 2000)],
        parent_ids: vec![],
    };
    let v1_id = v1.compute_id(&result.hierarchy.manifest);
    let v2 = FileManifest {
        inode: 2,
        version: 2,
        total_size: 5000,
        file_hash: [2; 32],
        blocks: vec![block(0xB2, 0, 2000), block(0xC3, 2000, 3000)],
        parent_ids: vec![v1_id],
    };
    let v2_id = v2.compute_id(&result.hierarchy.manifest);
    ms.insert(&v1).unwrap();
    ms.insert(&v2).unwrap();
    let mut f = Inode::new_file(2, 1, "f".into(), 0o644, 1000, 1000);
    f.size = v2.total_size;
    f.manifest = Some(v2);
    is.insert(&f).unwrap();
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    drop(conn);

    let pass_file = home.path().join("pass.txt");
    std::fs::write(&pass_file, PASS).unwrap();
    Vol {
        volumes,
        home,
        id,
        pass_file,
        v1: hex::encode(v1_id),
        v2: hex::encode(v2_id),
    }
}

#[test]
fn diff_reports_unchanged_added_and_removed_blocks_and_the_size_change() {
    let v = volume_with_two_versions();
    let out = v.diff(&v.v1[..12], &v.v2[..12]).success();
    let text = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    for want in [
        "Diff: /f (v1) vs /f (v2)",
        "Unchanged blocks: 1",
        "Added blocks:     1",
        &format!("+ {}", hex::encode([0xC3u8; 8])),
        "Removed blocks:   1",
        &format!("- {}", hex::encode([0xA1u8; 8])),
        "Size: 3000 → 5000 (+2000 bytes)",
    ] {
        assert!(text.contains(want), "missing {want:?} in:\n{text}");
    }

    // Reversed, the same blocks swap sides and the size change is negative.
    let out = v.diff(&v.v2[..12], &v.v1[..12]).success();
    let text = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    for want in [
        "Diff: /f (v2) vs /f (v1)",
        &format!("+ {}", hex::encode([0xA1u8; 8])),
        &format!("- {}", hex::encode([0xC3u8; 8])),
        "Size: 5000 → 3000 (-2000 bytes)",
    ] {
        assert!(text.contains(want), "missing {want:?} in:\n{text}");
    }

    // A version against itself: everything unchanged.
    v.diff(&v.v1, &v.v1)
        .success()
        .stdout(predicate::str::contains("Unchanged blocks: 2"))
        .stdout(predicate::str::contains("Added blocks:     0"))
        .stdout(predicate::str::contains("(+0 bytes)"));
}

#[test]
fn diff_refuses_an_unknown_id_prefix() {
    let v = volume_with_two_versions();
    // A prefix that is neither id (both ids are hex; 'zz' never matches).
    v.diff("zz", &v.v2[..12])
        .failure()
        .stderr(predicate::str::contains(
            "No manifest found with ID prefix 'zz'",
        ));
}
