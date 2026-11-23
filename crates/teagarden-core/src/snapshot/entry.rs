use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::block::pointer::FileManifest;
use crate::metadata::inode::Inode;

/// A single snapshot entry recording a filesystem operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    /// Unique snapshot ID (auto-incrementing)
    pub snapshot_id: u64,
    /// Timestamp (nanoseconds since epoch)
    pub timestamp: i128,
    /// Operation that triggered this snapshot
    pub operation: SnapshotOperation,
    /// Affected inode
    pub inode: u64,
    /// Previous state (for rollback)
    pub before: Option<SnapshotState>,
    /// New state
    pub after: Option<SnapshotState>,
    /// User who performed the operation (for shared volumes)
    pub user_id: Option<Uuid>,
}

/// The type of filesystem operation that was recorded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SnapshotOperation {
    /// A new file was created.
    Create,
    /// File content was written or modified.
    Write,
    /// A file was deleted.
    Delete,
    /// An entry was renamed from `old_name` to `new_name`.
    Rename {
        /// The entry's name before the rename.
        old_name: String,
        /// The entry's name after the rename.
        new_name: String,
    },
    /// A directory was created.
    Mkdir,
    /// A directory was removed.
    Rmdir,
    /// A hard link was created.
    Link,
    /// A symbolic link was created.
    Symlink,
    /// Inode attributes (mode, owner, timestamps, xattrs) were changed.
    SetAttr,
    /// State was restored from the snapshot with the given ID.
    Restore {
        /// The ID of the snapshot whose state was restored.
        from_snapshot: u64,
    },
}

/// State captured at a point in time for rollback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotState {
    /// Inode metadata at this point
    pub inode_snapshot: Inode,
    /// For files: the manifest at this point (block pointers)
    pub manifest: Option<FileManifest>,
}
