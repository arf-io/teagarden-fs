use rusqlite::{params, Connection};
use std::collections::{HashSet, VecDeque};

use crate::opaque_schema::OpaqueSchema;

/// DAG edge storage for the manifest history graph.
///
/// Each edge records that manifest `child_id` directly succeeds `parent_id`.
/// Together the edges form a DAG where each node is a manifest version.
pub struct DagStore<'a> {
    conn: &'a Connection,
    schema: &'a OpaqueSchema,
}

impl<'a> DagStore<'a> {
    /// Create a DAG-edge store over the given connection and opaque schema.
    pub fn new(conn: &'a Connection, schema: &'a OpaqueSchema) -> Self {
        Self { conn, schema }
    }

    /// Record that `child_id` directly succeeds `parent_id`.
    /// Silently ignores duplicate edges (INSERT OR IGNORE).
    pub fn insert_edge(&self, child_id: &[u8; 32], parent_id: &[u8; 32]) -> rusqlite::Result<()> {
        let t = self.schema.require_table("dag_edges")?;
        let c_child = self.schema.require_column("dag_edges", "child_id")?;
        let c_parent = self.schema.require_column("dag_edges", "parent_id")?;

        let sql = format!("INSERT OR IGNORE INTO {t} ({c_child}, {c_parent}) VALUES (?1, ?2)");
        self.conn
            .execute(&sql, params![child_id.as_slice(), parent_id.as_slice()])?;
        Ok(())
    }

    /// Insert edges for all parent_ids of a manifest at once.
    pub fn insert_edges(
        &self,
        child_id: &[u8; 32],
        parent_ids: &[[u8; 32]],
    ) -> rusqlite::Result<()> {
        for pid in parent_ids {
            self.insert_edge(child_id, pid)?;
        }
        Ok(())
    }

    /// Return the direct parent manifest IDs for a given child.
    pub fn get_parents(&self, child_id: &[u8; 32]) -> rusqlite::Result<Vec<[u8; 32]>> {
        let t = self.schema.require_table("dag_edges")?;
        let c_child = self.schema.require_column("dag_edges", "child_id")?;
        let c_parent = self.schema.require_column("dag_edges", "parent_id")?;

        let sql = format!("SELECT {c_parent} FROM {t} WHERE {c_child} = ?1");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![child_id.as_slice()], |row| {
            let bytes: Vec<u8> = row.get(0)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        })?;

        let mut parents = Vec::new();
        for r in rows {
            parents.push(r?);
        }
        Ok(parents)
    }

    /// Return the direct child manifest IDs for a given parent.
    pub fn get_children(&self, parent_id: &[u8; 32]) -> rusqlite::Result<Vec<[u8; 32]>> {
        let t = self.schema.require_table("dag_edges")?;
        let c_child = self.schema.require_column("dag_edges", "child_id")?;
        let c_parent = self.schema.require_column("dag_edges", "parent_id")?;

        let sql = format!("SELECT {c_child} FROM {t} WHERE {c_parent} = ?1");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![parent_id.as_slice()], |row| {
            let bytes: Vec<u8> = row.get(0)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        })?;

        let mut children = Vec::new();
        for r in rows {
            children.push(r?);
        }
        Ok(children)
    }

    /// Return all ancestor manifest IDs reachable from `start_id` via BFS.
    /// The result excludes `start_id` itself.
    pub fn get_ancestors(&self, start_id: &[u8; 32]) -> rusqlite::Result<Vec<[u8; 32]>> {
        let mut seen = HashSet::new();
        let mut queue = VecDeque::new();
        let mut ancestors = Vec::new();

        // Mark start as seen immediately so it is excluded from the output.
        seen.insert(*start_id);
        queue.push_back(*start_id);

        while let Some(current) = queue.pop_front() {
            for parent in self.get_parents(&current)? {
                if seen.insert(parent) {
                    // First time encountering this ancestor.
                    ancestors.push(parent);
                    queue.push_back(parent);
                }
            }
        }

        Ok(ancestors)
    }

    /// Delete all edges where `child_id` or `parent_id` matches the given manifest ID.
    pub fn delete_edges(&self, manifest_id: &[u8; 32]) -> rusqlite::Result<()> {
        let t = self.schema.require_table("dag_edges")?;
        let c_child = self.schema.require_column("dag_edges", "child_id")?;
        let c_parent = self.schema.require_column("dag_edges", "parent_id")?;

        let sql = format!("DELETE FROM {t} WHERE {c_child} = ?1 OR {c_parent} = ?1");
        self.conn.execute(&sql, params![manifest_id.as_slice()])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::initialize_database;
    use crate::opaque_schema::OpaqueSchema;
    use crate::schema::logical_tables;
    use rusqlite::Connection;
    use teagarden_core::crypto::keys::SymmetricKey;

    fn setup() -> (Connection, OpaqueSchema) {
        let conn = Connection::open_in_memory().unwrap();
        let key = SymmetricKey::from_bytes([0x42; 32]);
        let schema = OpaqueSchema::new(key, &logical_tables());
        initialize_database(&conn, &schema).unwrap();
        (conn, schema)
    }

    fn mid(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn insert_and_get_parents() {
        let (conn, schema) = setup();
        let dag = DagStore::new(&conn, &schema);

        // A → B means B is child of A
        dag.insert_edge(&mid(0xBB), &mid(0xAA)).unwrap();

        let parents = dag.get_parents(&mid(0xBB)).unwrap();
        assert_eq!(parents.len(), 1);
        assert_eq!(parents[0], mid(0xAA));

        let parents_of_root = dag.get_parents(&mid(0xAA)).unwrap();
        assert!(parents_of_root.is_empty());
    }

    #[test]
    fn insert_and_get_children() {
        let (conn, schema) = setup();
        let dag = DagStore::new(&conn, &schema);

        dag.insert_edge(&mid(0xBB), &mid(0xAA)).unwrap();
        dag.insert_edge(&mid(0xCC), &mid(0xAA)).unwrap();

        let children = dag.get_children(&mid(0xAA)).unwrap();
        assert_eq!(children.len(), 2);
        assert!(children.contains(&mid(0xBB)));
        assert!(children.contains(&mid(0xCC)));
    }

    #[test]
    fn duplicate_edge_ignored() {
        let (conn, schema) = setup();
        let dag = DagStore::new(&conn, &schema);

        dag.insert_edge(&mid(0xBB), &mid(0xAA)).unwrap();
        dag.insert_edge(&mid(0xBB), &mid(0xAA)).unwrap(); // duplicate — should not fail

        let parents = dag.get_parents(&mid(0xBB)).unwrap();
        assert_eq!(parents.len(), 1);
    }

    #[test]
    fn insert_edges_bulk() {
        let (conn, schema) = setup();
        let dag = DagStore::new(&conn, &schema);

        let parents = [mid(0xAA), mid(0xBB)];
        dag.insert_edges(&mid(0xCC), &parents).unwrap();

        let got = dag.get_parents(&mid(0xCC)).unwrap();
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn get_ancestors_linear_chain() {
        let (conn, schema) = setup();
        let dag = DagStore::new(&conn, &schema);

        // Chain: A ← B ← C (C is newest, A is oldest)
        dag.insert_edge(&mid(0xBB), &mid(0xAA)).unwrap();
        dag.insert_edge(&mid(0xCC), &mid(0xBB)).unwrap();

        let ancestors = dag.get_ancestors(&mid(0xCC)).unwrap();
        assert!(ancestors.contains(&mid(0xAA)));
        assert!(ancestors.contains(&mid(0xBB)));
        assert_eq!(ancestors.len(), 2);
    }

    #[test]
    fn get_ancestors_diamond() {
        let (conn, schema) = setup();
        let dag = DagStore::new(&conn, &schema);

        // Diamond merge: A ← B ← D, A ← C ← D
        dag.insert_edge(&mid(0xBB), &mid(0xAA)).unwrap();
        dag.insert_edge(&mid(0xCC), &mid(0xAA)).unwrap();
        dag.insert_edge(&mid(0xDD), &mid(0xBB)).unwrap();
        dag.insert_edge(&mid(0xDD), &mid(0xCC)).unwrap();

        let ancestors = dag.get_ancestors(&mid(0xDD)).unwrap();
        // Should have A, B, C — each counted once
        assert_eq!(ancestors.len(), 3);
        assert!(ancestors.contains(&mid(0xAA)));
        assert!(ancestors.contains(&mid(0xBB)));
        assert!(ancestors.contains(&mid(0xCC)));
    }

    #[test]
    fn delete_edges() {
        let (conn, schema) = setup();
        let dag = DagStore::new(&conn, &schema);

        dag.insert_edge(&mid(0xBB), &mid(0xAA)).unwrap();
        dag.insert_edge(&mid(0xCC), &mid(0xBB)).unwrap();

        dag.delete_edges(&mid(0xBB)).unwrap();

        assert!(dag.get_parents(&mid(0xBB)).unwrap().is_empty());
        assert!(dag.get_children(&mid(0xBB)).unwrap().is_empty());
        // C still has edge to BB deleted, but BB→AA also deleted
        assert!(dag.get_parents(&mid(0xCC)).unwrap().is_empty());
    }
}
