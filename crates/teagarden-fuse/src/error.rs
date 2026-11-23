use thiserror::Error;

/// Errors raised by the FUSE filesystem layer, each mapped to a libc errno for kernel replies.
#[derive(Debug, Error)]
pub enum FuseError {
    /// No inode exists for the given inode number (maps to `ENOENT`).
    #[error("inode not found: {0}")]
    InodeNotFound(u64),

    /// The inode was expected to be a directory but is not (maps to `ENOTDIR`).
    #[error("not a directory: {0}")]
    NotDirectory(u64),

    /// The inode was expected to be a regular file but is a directory (maps to `EISDIR`).
    #[error("not a file: {0}")]
    NotFile(u64),

    /// A file or directory with the given name already exists (maps to `EEXIST`).
    #[error("file exists: {0}")]
    Exists(String),

    /// A directory with the given inode number still has entries (maps to `ENOTEMPTY`).
    #[error("directory not empty: {0}")]
    NotEmpty(u64),

    /// The operation is not permitted for the requesting process (maps to `EACCES`).
    #[error("permission denied")]
    PermissionDenied,

    /// An error from the underlying metadata store, carrying its message (maps to `EIO`).
    #[error("store error: {0}")]
    Store(String),

    /// An underlying I/O error, propagated from `std::io::Error` (maps to `EIO`).
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl FuseError {
    /// Convert to libc errno for FUSE responses.
    pub fn to_errno(&self) -> i32 {
        match self {
            FuseError::InodeNotFound(_) => libc::ENOENT,
            FuseError::NotDirectory(_) => libc::ENOTDIR,
            FuseError::NotFile(_) => libc::EISDIR,
            FuseError::Exists(_) => libc::EEXIST,
            FuseError::NotEmpty(_) => libc::ENOTEMPTY,
            FuseError::PermissionDenied => libc::EACCES,
            FuseError::Store(_) => libc::EIO,
            FuseError::Io(_) => libc::EIO,
        }
    }

    /// Returns a user-facing suggestion for how to resolve this error.
    pub fn suggestion(&self) -> &'static str {
        match self {
            FuseError::InodeNotFound(_) => "The file or directory does not exist; check the path",
            FuseError::NotDirectory(_) => "The path component is not a directory",
            FuseError::NotFile(_) => "Cannot perform file operation on a directory",
            FuseError::Exists(_) => "A file or directory with that name already exists",
            FuseError::NotEmpty(_) => "Remove all contents before deleting the directory",
            FuseError::PermissionDenied => {
                "Check volume mount permissions or try mounting with `allow_other`"
            }
            FuseError::Store(_) => "Metadata store may be corrupted; try unmounting and remounting",
            FuseError::Io(_) => "Check available disk space and file permissions",
        }
    }
}

/// Convenience alias for results returned by FUSE filesystem operations.
pub type Result<T> = std::result::Result<T, FuseError>;
