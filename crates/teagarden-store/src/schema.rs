use crate::opaque_schema::TableDef;

/// All logical table definitions for the TeaGarden metadata database.
/// These names are never stored directly - OpaqueSchema maps them to opaque identifiers.
pub fn logical_tables() -> Vec<TableDef> {
    vec![
        TableDef {
            name: "volume".into(),
            columns: vec![
                "volume_id".into(),
                "data".into(),
                "created_at".into(),
                "updated_at".into(),
            ],
            indexes: vec![],
        },
        TableDef {
            name: "inodes".into(),
            columns: vec![
                "ino".into(),
                "parent".into(),
                "name_hash".into(),
                "data".into(),
                "version".into(),
            ],
            indexes: vec!["inodes_parent".into(), "inodes_parent_name".into()],
        },
        TableDef {
            name: "blocks".into(),
            columns: vec![
                "block_id".into(),
                "filename".into(),
                "message_id".into(),
                "plaintext_size".into(),
                "encrypted_size".into(),
                "epoch".into(),
                "ref_count".into(),
                "compressed".into(),
                // SRB2: SHA-256 of the decrypted plaintext (verifies integrity after decrypt).
                "plaintext_sha256".into(),
                // SRB2: SHA-256 of the encrypted payload (verifies transit integrity without decrypting).
                "ciphertext_sha256".into(),
            ],
            indexes: vec!["blocks_message_id".into()],
        },
        TableDef {
            name: "manifests".into(),
            columns: vec![
                "ino".into(),
                "version".into(),
                "data".into(),
                "created_at".into(),
            ],
            indexes: vec![],
        },
        TableDef {
            name: "sdo_versions".into(),
            columns: vec![
                "version_id".into(),
                "path_id".into(),
                "ino".into(),
                "message_id".into(),
                "data".into(),
            ],
            indexes: vec!["sdo_versions_path".into()],
        },
        TableDef {
            name: "sdo_identities".into(),
            columns: vec!["ino".into(), "data".into()],
            indexes: vec![],
        },
        TableDef {
            name: "sdo_clock".into(),
            columns: vec!["clock_id".into(), "physical_ms".into(), "counter".into()],
            indexes: vec![],
        },
        TableDef {
            name: "sdo_poll_cursor".into(),
            columns: vec![
                "cursor_id".into(),
                "message_id".into(),
                "high_water_id".into(),
            ],
            indexes: vec![],
        },
        TableDef {
            name: "sdo_pending_writes".into(),
            columns: vec!["version_id".into(), "data".into()],
            indexes: vec![],
        },
        TableDef {
            name: "sdo_pending_chunks".into(),
            columns: vec!["version_id".into(), "chunk_index".into(), "data".into()],
            indexes: vec![],
        },
        TableDef {
            name: "snapshots".into(),
            columns: vec![
                "sid".into(),
                "timestamp".into(),
                "data".into(),
                "ino".into(),
            ],
            indexes: vec!["snapshots_ts".into(), "snapshots_ino".into()],
        },
        TableDef {
            name: "policies".into(),
            columns: vec!["pid".into(), "data".into()],
            indexes: vec![],
        },
        TableDef {
            name: "path_policies".into(),
            columns: vec!["path_pattern".into(), "pid".into(), "priority".into()],
            indexes: vec!["path_policies_pattern".into()],
        },
        TableDef {
            name: "users".into(),
            columns: vec!["uid".into(), "data".into(), "active".into()],
            indexes: vec![],
        },
        TableDef {
            name: "audit_log".into(),
            columns: vec![
                "id".into(),
                "timestamp".into(),
                "uid".into(),
                "action".into(),
                "details".into(),
            ],
            indexes: vec!["audit_ts".into()],
        },
        TableDef {
            name: "shares".into(),
            columns: vec![
                "sid".into(),
                "volume_id".into(),
                "uid".into(),
                "data".into(),
                "active".into(),
            ],
            indexes: vec!["shares_volume".into()],
        },
        TableDef {
            name: "invites".into(),
            columns: vec![
                "invite_id".into(),
                "volume_id".into(),
                "data".into(),
                "active".into(),
            ],
            indexes: vec!["invites_volume".into()],
        },
        TableDef {
            name: "dag_edges".into(),
            columns: vec!["child_id".into(), "parent_id".into()],
            indexes: vec!["dag_edges_child".into(), "dag_edges_parent".into()],
        },
        // The DB's lineage stamp (`local_db::DbStamp`): one row, no PRIMARY
        // KEY, so the SQLite session extension never records a change to it
        // and it never enters the metadata journal.
        TableDef {
            name: "lineage".into(),
            columns: vec!["volume_id".into(), "version".into(), "nonce".into()],
            indexes: vec![],
        },
        // Which session last opened the DB and the journal position it holds
        // (`local_db::SessionRecord`): one row, no PRIMARY KEY, never
        // journaled (added in round 12 of 1.0.0; a DB without it, or without
        // its row, was last written by an earlier build).
        // The `replaced_*` columns: the stamp and journal position the DB
        // carried before a publish restamped it (`local_db::replaced_stamp`;
        // added in round 13 of 1.0.0).
        TableDef {
            name: "db_session".into(),
            columns: vec![
                "nonce".into(),
                "seq".into(),
                "replaced_volume_id".into(),
                "replaced_version".into(),
                "replaced_nonce".into(),
                "replaced_seq".into(),
            ],
            indexes: vec![],
        },
    ]
}
