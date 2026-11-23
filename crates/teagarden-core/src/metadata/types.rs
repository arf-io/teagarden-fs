use serde::{Deserialize, Serialize};

/// POSIX file type.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileType {
    /// A regular file.
    RegularFile,
    /// A directory.
    Directory,
    /// A symbolic link.
    Symlink,
}

/// Timestamps stored as nanoseconds since UNIX epoch.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Timestamps {
    /// Last access time, in nanoseconds since the UNIX epoch.
    pub atime_ns: i128,
    /// Last modification time, in nanoseconds since the UNIX epoch.
    pub mtime_ns: i128,
    /// Last status-change time, in nanoseconds since the UNIX epoch.
    pub ctime_ns: i128,
    /// Creation (birth) time, in nanoseconds since the UNIX epoch.
    pub crtime_ns: i128,
}

impl Timestamps {
    /// Construct timestamps with every field set to the current wall-clock time.
    pub fn now() -> Self {
        let ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i128;
        Self {
            atime_ns: ns,
            mtime_ns: ns,
            ctime_ns: ns,
            crtime_ns: ns,
        }
    }
}
