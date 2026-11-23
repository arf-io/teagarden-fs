use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use zeroize::Zeroize;

/// Tracks open file handles and the per-inode write buffers for the FUSE
/// filesystem.
///
/// Write buffers are keyed by **inode**, not by handle: every handle open on an
/// inode reads and writes the same buffer, so two descriptors on one file see one
/// coherent byte image and the persisted file contains every handle's writes (no
/// "last release wins"). A buffer exists only while the inode has unpersisted
/// (dirty) bytes: it is created by the first write, removed once its content has
/// been uploaded and journaled, and discarded (zeroized) when the last handle on
/// the inode is closed.
pub struct HandleTable {
    next_fh: AtomicU64,
    inner: Mutex<Tables>,
}

#[derive(Default)]
struct Tables {
    handles: HashMap<u64, FileHandle>,
    deferred_empty_creates: HashSet<u64>,
    spools: HashMap<(bool, u64), std::sync::Arc<Mutex<crate::spool::WriteSpool>>>,
    /// Dirty write buffer per inode (see the type-level docs).
    buffers: HashMap<u64, Vec<u8>>,
    /// Independent dirty images for portable SDO handles.
    handle_buffers: HashMap<u64, Vec<u8>>,
}

/// A single open file handle.
#[derive(Debug, Clone)]
pub struct FileHandle {
    /// File handle ID.
    pub fh: u64,
    /// Inode number this handle points to.
    pub ino: u64,
    /// Open flags.
    pub flags: i32,
    /// UID of the process that opened this handle (captured from FUSE request).
    pub uid: u32,
    /// Set when the file this handle was opened on has been deleted (unlink,
    /// rmdir, or replaced by a rename). Its inode NUMBER may since have been
    /// reused by a different file, so every data operation through a stale
    /// handle is refused (`ESTALE`) instead of reaching that other file.
    pub stale: bool,
    /// Immutable TGFV version selected when this handle opened, when present.
    pub pinned_sdo_version: Option<uuid::Uuid>,
}

impl FileHandle {
    /// True if the handle was opened with write access (`O_WRONLY` / `O_RDWR`).
    pub fn writable(&self) -> bool {
        (self.flags & libc::O_ACCMODE) != libc::O_RDONLY || self.flags & libc::O_TRUNC != 0
    }
}

impl HandleTable {
    /// Create an empty handle table, with file-handle IDs starting at 1.
    pub fn new() -> Self {
        Self {
            next_fh: AtomicU64::new(1),
            inner: Mutex::new(Tables::default()),
        }
    }

    /// Lock the tables without turning a prior handler panic into a permanent
    /// mount-wide panic loop. A panic may have left a buffer partly mutated, so all
    /// handles and buffers are zeroized and discarded before new operations are
    /// accepted; uncertain buffered data is never reused.
    fn lock(&self) -> MutexGuard<'_, Tables> {
        self.inner.lock().unwrap_or_else(|poisoned| {
            tracing::error!(
                "file-handle table mutex was poisoned; zeroizing and discarding open handles"
            );
            let mut tables = poisoned.into_inner();
            for buf in tables.buffers.values_mut() {
                buf.zeroize();
            }
            tables.buffers.clear();
            for buf in tables.handle_buffers.values_mut() {
                buf.zeroize();
            }
            tables.handle_buffers.clear();
            tables.spools.clear(); // Payloads remain on disk for explicit recovery.
            tables.deferred_empty_creates.clear();
            tables.handles.clear();
            self.inner.clear_poison();
            tables
        })
    }

    pub(crate) fn spool(
        &self,
        portable: bool,
        id: u64,
    ) -> Option<std::sync::Arc<Mutex<crate::spool::WriteSpool>>> {
        self.lock().spools.get(&(portable, id)).cloned()
    }
    pub(crate) fn insert_spool(&self, portable: bool, id: u64, spool: crate::spool::WriteSpool) {
        self.lock()
            .spools
            .insert((portable, id), std::sync::Arc::new(Mutex::new(spool)));
    }
    pub(crate) fn remove_spool(&self, portable: bool, id: u64) {
        self.lock().spools.remove(&(portable, id));
    }
    pub(crate) fn defer_empty_create(&self, fh: u64) {
        self.lock().deferred_empty_creates.insert(fh);
    }
    pub(crate) fn is_deferred_empty_create(&self, fh: u64) -> bool {
        self.lock().deferred_empty_creates.contains(&fh)
    }
    pub(crate) fn mark_written(&self, fh: u64) {
        self.lock().deferred_empty_creates.remove(&fh);
    }
    pub(crate) fn mark_setattr(&self, ino: u64) {
        let mut t = self.lock();
        let handles: Vec<_> = t
            .handles
            .values()
            .filter(|h| h.ino == ino && !h.stale)
            .map(|h| h.fh)
            .collect();
        for fh in handles {
            t.deferred_empty_creates.remove(&fh);
        }
    }

    /// Open a new file handle.
    pub fn open(&self, ino: u64, flags: i32, uid: u32) -> u64 {
        self.open_with_version(ino, flags, uid, None)
    }

    /// Open a handle pinned to one immutable portable object version.
    pub fn open_pinned_sdo(&self, ino: u64, flags: i32, uid: u32, version: uuid::Uuid) -> u64 {
        self.open_with_version(ino, flags, uid, Some(version))
    }

    fn open_with_version(
        &self,
        ino: u64,
        flags: i32,
        uid: u32,
        pinned_sdo_version: Option<uuid::Uuid>,
    ) -> u64 {
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        let handle = FileHandle {
            fh,
            ino,
            flags,
            uid,
            stale: false,
            pinned_sdo_version,
        };
        self.lock().handles.insert(fh, handle);
        fh
    }

    /// Get a file handle by ID.
    pub fn get(&self, fh: u64) -> Option<FileHandle> {
        self.lock().handles.get(&fh).cloned()
    }

    /// A writable descriptor's next image starts from its own last committed save.
    pub(crate) fn advance_sdo_version(&self, fh: u64, version: uuid::Uuid) {
        if let Some(handle) = self.lock().handles.get_mut(&fh) {
            handle.pinned_sdo_version = Some(version);
        }
    }

    /// Close (release) a file handle. Returns the handle if it existed. If it was
    /// the last live handle open on its inode, that inode's write buffer (if any)
    /// is zeroized and discarded — nothing can reach it any more. Callers that must
    /// persist dirty data do so BEFORE closing. Stale handles (deleted file) never
    /// keep a buffer alive and never discard one: the buffer under that inode
    /// number, if any, belongs to the file that reused it.
    pub fn close(&self, fh: u64) -> Option<FileHandle> {
        let mut t = self.lock();
        let handle = t.handles.remove(&fh)?;
        t.deferred_empty_creates.remove(&fh);
        if let Some(mut buf) = t.handle_buffers.remove(&fh) {
            buf.zeroize();
        }
        if !handle.stale && !t.handles.values().any(|h| h.ino == handle.ino && !h.stale) {
            if let Some(mut buf) = t.buffers.remove(&handle.ino) {
                tracing::warn!(
                    ino = handle.ino,
                    bytes = buf.len(),
                    "last handle closed with unpersisted data; discarding buffer"
                );
                buf.zeroize();
            }
        }
        Some(handle)
    }

    /// Get all open handles for an inode.
    pub fn handles_for_ino(&self, ino: u64) -> Vec<u64> {
        self.lock()
            .handles
            .iter()
            .filter(|(_, h)| h.ino == ino)
            .map(|(fh, _)| *fh)
            .collect()
    }

    /// Mark every handle currently open on `ino` stale: its file was deleted.
    pub fn mark_stale(&self, ino: u64) {
        let mut tables = self.lock();
        let affected: Vec<_> = tables
            .handles
            .values_mut()
            .filter(|h| h.ino == ino)
            .map(|h| {
                h.stale = true;
                h.fh
            })
            .collect();
        for fh in affected {
            if let Some(spool) = tables.spools.remove(&(true, fh)) {
                if let Ok(spool) = spool.lock() {
                    let _ = spool.cleanup();
                }
            }
        }
    }

    /// Count open handles.
    pub fn count(&self) -> usize {
        self.lock().handles.len()
    }

    /// True if `ino` has a (dirty) write buffer.
    pub fn has_buffer(&self, ino: u64) -> bool {
        {
            let t = self.lock();
            t.buffers.contains_key(&ino) || t.spools.contains_key(&(false, ino))
        }
    }

    /// Length of `ino`'s write buffer, if it has one.
    pub fn buffer_len(&self, ino: u64) -> Option<u64> {
        {
            let t = self.lock();
            t.buffers.get(&ino).map(|b| b.len() as u64).or_else(|| {
                t.spools
                    .get(&(false, ino))
                    .and_then(|s| s.lock().ok()?.len().ok())
            })
        }
    }

    /// Install `data` as `ino`'s write buffer unless one already exists (in which
    /// case `data` is zeroized and dropped). Returns true if `data` was installed.
    pub fn insert_buffer(&self, ino: u64, mut data: Vec<u8>) -> bool {
        match self.lock().buffers.entry(ino) {
            std::collections::hash_map::Entry::Occupied(_) => {
                data.zeroize();
                false
            }
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(data);
                true
            }
        }
    }

    /// Run `f` on `ino`'s write buffer, if it has one.
    pub fn with_buffer<R>(&self, ino: u64, f: impl FnOnce(&mut Vec<u8>) -> R) -> Option<R> {
        self.lock().buffers.get_mut(&ino).map(f)
    }

    /// Remove and return `ino`'s write buffer (for persisting it). The caller must
    /// either zeroize it once persisted or hand it back with [`Self::insert_buffer`].
    pub fn take_buffer(&self, ino: u64) -> Option<Vec<u8>> {
        self.lock().buffers.remove(&ino)
    }

    /// Zeroize and discard `ino`'s write buffer, if any.
    pub fn discard_buffer(&self, ino: u64) {
        if let Some(spool) = self.lock().spools.remove(&(false, ino)) {
            if let Ok(spool) = spool.lock() {
                let _ = spool.cleanup();
            }
        }
        if let Some(mut buf) = self.lock().buffers.remove(&ino) {
            buf.zeroize();
        }
    }

    /// Whether `fh` owns a portable dirty image.
    pub fn has_handle_buffer(&self, fh: u64) -> bool {
        {
            let t = self.lock();
            t.handle_buffers.contains_key(&fh) || t.spools.contains_key(&(true, fh))
        }
    }

    /// Install an independent buffer for one portable handle.
    pub fn insert_handle_buffer(&self, fh: u64, mut data: Vec<u8>) -> bool {
        match self.lock().handle_buffers.entry(fh) {
            std::collections::hash_map::Entry::Occupied(_) => {
                data.zeroize();
                false
            }
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(data);
                true
            }
        }
    }

    /// Run `f` on one portable handle's dirty image.
    pub fn with_handle_buffer<R>(&self, fh: u64, f: impl FnOnce(&mut Vec<u8>) -> R) -> Option<R> {
        self.lock().handle_buffers.get_mut(&fh).map(f)
    }

    /// Remove one portable handle's dirty image for an upload attempt.
    pub fn take_handle_buffer(&self, fh: u64) -> Option<Vec<u8>> {
        self.lock().handle_buffers.remove(&fh)
    }

    /// Zeroize one portable handle's dirty image.
    pub fn discard_handle_buffer(&self, fh: u64) {
        if let Some(mut buf) = self.lock().handle_buffers.remove(&fh) {
            buf.zeroize();
        }
    }
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_and_get() {
        let table = HandleTable::new();
        let fh = table.open(42, libc::O_RDONLY, 1000);
        let handle = table.get(fh).unwrap();
        assert_eq!(handle.ino, 42);
        assert_eq!(handle.flags, libc::O_RDONLY);
        assert!(!handle.writable());
        assert!(!table.has_buffer(42));
    }

    #[test]
    fn portable_handle_can_pin_its_opened_version() {
        let table = HandleTable::new();
        let version = uuid::Uuid::from_bytes([7; 16]);
        let fh = table.open_pinned_sdo(42, libc::O_RDONLY, 1000, version);
        assert_eq!(table.get(fh).unwrap().pinned_sdo_version, Some(version));
    }

    #[test]
    fn close_handle() {
        let table = HandleTable::new();
        let fh = table.open(42, 0, 1000);
        assert_eq!(table.count(), 1);

        let handle = table.close(fh).unwrap();
        assert_eq!(handle.ino, 42);
        assert_eq!(table.count(), 0);
        assert!(table.get(fh).is_none());
    }

    #[test]
    fn buffer_is_per_inode_and_shared_by_handles() {
        let table = HandleTable::new();
        let fh1 = table.open(42, libc::O_RDWR, 1000);
        let fh2 = table.open(42, libc::O_RDWR, 1000);
        assert!(table.insert_buffer(42, vec![1, 2, 3]));
        assert!(
            !table.insert_buffer(42, vec![9]),
            "an existing buffer is never replaced"
        );
        table.with_buffer(42, |b| b.push(4));
        assert_eq!(table.buffer_len(42), Some(4));

        // Closing one of two handles keeps the shared buffer...
        table.close(fh1);
        assert_eq!(table.with_buffer(42, |b| b.clone()), Some(vec![1, 2, 3, 4]));
        // ...closing the last one discards it.
        table.close(fh2);
        assert!(!table.has_buffer(42));
    }

    #[test]
    fn portable_buffers_are_isolated_by_open_handle() {
        let table = HandleTable::new();
        let first = table.open_pinned_sdo(42, libc::O_RDWR, 1000, uuid::Uuid::from_bytes([1; 16]));
        let second = table.open_pinned_sdo(42, libc::O_RDWR, 1000, uuid::Uuid::from_bytes([2; 16]));
        table.insert_handle_buffer(first, b"first".to_vec());
        table.insert_handle_buffer(second, b"second".to_vec());
        assert_eq!(
            table.with_handle_buffer(first, |bytes| bytes.clone()),
            Some(b"first".to_vec())
        );
        assert_eq!(
            table.with_handle_buffer(second, |bytes| bytes.clone()),
            Some(b"second".to_vec())
        );
        table.close(first);
        assert_eq!(
            table.with_handle_buffer(second, |bytes| bytes.clone()),
            Some(b"second".to_vec())
        );
    }

    #[test]
    fn stale_handle_neither_keeps_nor_discards_the_new_files_buffer() {
        let table = HandleTable::new();
        let old = table.open(9, libc::O_RDWR, 1000);
        table.mark_stale(9);
        assert!(table.get(old).unwrap().stale);
        let new = table.open(9, libc::O_RDWR, 1000);
        assert!(!table.get(new).unwrap().stale, "new opens are live");
        table.insert_buffer(9, b"new file".to_vec());
        table.close(old);
        assert!(table.has_buffer(9), "closing the stale handle keeps it");
        table.close(new);
        assert!(!table.has_buffer(9), "the last LIVE close discards it");
    }

    #[test]
    fn take_and_discard_buffer() {
        let table = HandleTable::new();
        let _fh = table.open(7, libc::O_RDWR, 1000);
        table.insert_buffer(7, b"abc".to_vec());
        assert_eq!(table.take_buffer(7), Some(b"abc".to_vec()));
        assert!(!table.has_buffer(7));
        table.insert_buffer(7, b"def".to_vec());
        table.discard_buffer(7);
        assert!(!table.has_buffer(7));
    }

    #[test]
    fn unique_fh_ids() {
        let table = HandleTable::new();
        let fh1 = table.open(1, 0, 1000);
        let fh2 = table.open(2, 0, 1000);
        let fh3 = table.open(3, 0, 1000);
        assert_ne!(fh1, fh2);
        assert_ne!(fh2, fh3);
    }

    #[test]
    fn handles_for_ino() {
        let table = HandleTable::new();
        let fh1 = table.open(42, libc::O_RDONLY, 1000);
        let fh2 = table.open(42, libc::O_WRONLY, 1000);
        let _fh3 = table.open(99, libc::O_RDONLY, 1000);

        let handles = table.handles_for_ino(42);
        assert_eq!(handles.len(), 2);
        assert!(handles.contains(&fh1));
        assert!(handles.contains(&fh2));
        assert!(table.get(fh2).unwrap().writable());
    }

    #[test]
    fn close_nonexistent() {
        let table = HandleTable::new();
        assert!(table.close(999).is_none());
    }

    #[test]
    fn handle_records_owner_uid() {
        let table = HandleTable::new();
        let fh = table.open(42, libc::O_RDWR, 1001);
        let handle = table.get(fh).unwrap();
        assert_eq!(handle.uid, 1001);
    }

    #[test]
    fn poisoned_handle_table_does_not_panic_future_mount_operations() {
        use std::sync::Arc;

        let table = Arc::new(HandleTable::new());
        let abandoned = table.open(5, libc::O_WRONLY, 1000);
        table.insert_buffer(5, b"uncertain plaintext".to_vec());
        let poisoner = Arc::clone(&table);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.inner.lock().unwrap();
            panic!("deliberately poison the handle table");
        })
        .join();

        let fh = table.open(7, libc::O_RDONLY, 1000);
        assert!(table.get(abandoned).is_none());
        assert!(!table.has_buffer(5), "uncertain buffer must be discarded");
        assert_eq!(table.get(fh).unwrap().ino, 7);
        assert_eq!(table.count(), 1);
    }
}
