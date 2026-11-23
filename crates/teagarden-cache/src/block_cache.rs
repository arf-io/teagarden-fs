use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use teagarden_core::crypto::{aead, keys::SymmetricKey};

use crate::error::{CacheError, Result};

/// Configuration for the block cache.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Directory for cached blocks on disk.
    pub cache_dir: PathBuf,
    /// Maximum cache size in bytes.
    pub max_size: u64,
    /// Whether to encrypt cached blocks on disk.
    pub encrypt_at_rest: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        // Use ~/.cache/teagarden rather than /tmp so the directory is user-private
        // and survives reboots. Fall back to a relative path only if $HOME is unset.
        let cache_dir = dirs::cache_dir()
            .unwrap_or_else(|| {
                std::env::var("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join(".cache")
            })
            .join("teagarden");
        Self {
            cache_dir,
            max_size: 512 * 1024 * 1024, // 512MB
            encrypt_at_rest: true,
        }
    }
}

/// Create the cache directory with mode 0o700 (owner-only).
fn ensure_cache_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

/// Distinguishes the temporary files of concurrent `put`s within this process.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A block file name: the 64 lowercase hex digits of a block RID.
fn is_block_name(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(is_lower_hex)
}

/// A shard directory name: the first 2 hex digits of the RIDs it holds.
fn is_shard_name(name: &str) -> bool {
    name.len() == 2 && name.bytes().all(is_lower_hex)
}

fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

fn block_path_in(cache_dir: &Path, rid_hex: &str) -> PathBuf {
    // Use first 2 chars as subdirectory for filesystem efficiency.
    // This function is purely computational — callers are responsible for
    // creating the parent directory before writing to the returned path.
    cache_dir.join(&rid_hex[..2]).join(rid_hex)
}

/// LRU entry tracking metadata.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Block random ID (hex).
    rid_hex: String,
    /// Size of the cached data.
    size: u64,
    /// Access counter for LRU ordering.
    access_order: u64,
}

/// Encrypted local block cache with LRU eviction.
pub struct BlockCache {
    config: CacheConfig,
    cache_key: SymmetricKey,
    inner: Mutex<CacheInner>,
}

struct CacheInner {
    /// Map from block RID (hex) to entry metadata.
    entries: HashMap<String, CacheEntry>,
    /// Secondary index: access_order → rid_hex. Kept in sync with `entries`.
    /// Enables O(log n) LRU eviction instead of O(n) linear scan.
    lru_order: BTreeMap<u64, String>,
    /// Current total size.
    current_size: u64,
    /// Monotonic access counter.
    access_counter: u64,
    /// Cache statistics.
    hits: u64,
    misses: u64,
}

/// Cache statistics.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Number of blocks currently held in the cache.
    pub entries: usize,
    /// Total size in bytes of all cached blocks on disk.
    pub current_size: u64,
    /// Configured maximum cache size in bytes.
    pub max_size: u64,
    /// Number of lookups served from the cache.
    pub hits: u64,
    /// Number of lookups that missed and required a fetch.
    pub misses: u64,
}

impl BlockCache {
    /// Create a block cache over `config.cache_dir`.
    ///
    /// Blocks left in the directory by an earlier instance (a previous mount)
    /// are adopted: each well-formed block file is registered with its on-disk
    /// size, least recently written first, and the cache is then evicted down to
    /// `max_size`. Nothing is decrypted here; a file that does not authenticate
    /// is dropped when it is first read ([`BlockCache::get`]).
    ///
    /// Leftovers inside a shard (`xx/`) subdirectory that are not block files
    /// (temporary files of an interrupted `put`, misnamed or misfiled files) are
    /// deleted. Anything else in `cache_dir` is left alone.
    pub fn new(config: CacheConfig, cache_key: SymmetricKey) -> Result<Self> {
        ensure_cache_dir(&config.cache_dir)?;

        let mut inner = Self::scan(&config.cache_dir)?;
        Self::evict_locked(&config, &mut inner, 0);

        Ok(Self {
            config,
            cache_key,
            inner: Mutex::new(inner),
        })
    }

    /// Build the index from the block files already in `cache_dir`.
    fn scan(cache_dir: &Path) -> Result<CacheInner> {
        let mut found: Vec<(std::time::SystemTime, String, u64)> = Vec::new();

        for shard in std::fs::read_dir(cache_dir)? {
            let Ok(shard) = shard else { continue };
            let shard_name = shard.file_name();
            let Some(shard_name) = shard_name.to_str().filter(|n| is_shard_name(n)) else {
                continue;
            };
            let shard_path = shard.path();
            // `symlink_metadata`: a symlink is never followed, whatever it names.
            match std::fs::symlink_metadata(&shard_path) {
                Ok(m) if m.is_dir() => {}
                _ => continue,
            }
            let Ok(files) = std::fs::read_dir(&shard_path) else {
                continue;
            };
            for file in files {
                let Ok(file) = file else { continue };
                let path = file.path();
                let Ok(meta) = std::fs::symlink_metadata(&path) else {
                    continue;
                };
                if meta.is_dir() {
                    continue;
                }
                let name = file.file_name();
                match name.to_str() {
                    Some(n) if meta.is_file() && is_block_name(n) && n.starts_with(shard_name) => {
                        let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
                        found.push((mtime, n.to_owned(), meta.len()));
                    }
                    _ => {
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
        }

        // Oldest first; the name breaks ties so the order is deterministic.
        found.sort();

        let mut inner = CacheInner {
            entries: HashMap::new(),
            lru_order: BTreeMap::new(),
            current_size: 0,
            access_counter: 0,
            hits: 0,
            misses: 0,
        };
        for (_, rid_hex, size) in found {
            inner.access_counter += 1;
            let order = inner.access_counter;
            inner.lru_order.insert(order, rid_hex.clone());
            inner.entries.insert(
                rid_hex.clone(),
                CacheEntry {
                    rid_hex,
                    size,
                    access_order: order,
                },
            );
            inner.current_size += size;
        }
        Ok(inner)
    }

    /// Store a block in the cache, evicting if necessary.
    pub fn put(&self, rid: &[u8; 32], data: &[u8]) -> Result<()> {
        let rid_hex = hex::encode(rid);
        let data_to_write = if self.config.encrypt_at_rest {
            let aad = format!("cache:{rid_hex}");
            aead::encrypt(&self.cache_key, data, aad.as_bytes())
                .map_err(|e| CacheError::Encryption(e.to_string()))?
        } else {
            data.to_vec()
        };
        let data_size = data_to_write.len() as u64;

        // A block larger than the whole cache is not cached: evicting everything
        // to make room would still leave the directory over `max_size`.
        if data_size > self.config.max_size {
            return Ok(());
        }

        // Evict entries if needed to make room
        self.evict_if_needed(data_size)?;

        // Write to disk.
        // Create the subdirectory immediately before the write so that any
        // concurrent eviction that removed an empty subdirectory between
        // evict_if_needed() and this point does not cause the write to fail.
        let path = self.block_path(&rid_hex);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(CacheError::Io)?;
        }
        // Write under a temporary name and rename into place, so a block file
        // either does not exist or is complete: an interrupted write leaves only
        // a temporary file, which `new` removes and never registers.
        let tmp = path.with_file_name(format!(
            ".{rid_hex}.tmp.{}.{}",
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        if let Err(e) =
            std::fs::write(&tmp, &data_to_write).and_then(|()| std::fs::rename(&tmp, &path))
        {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }

        // Update index
        let mut inner = self.inner.lock().unwrap();
        inner.access_counter += 1;

        // If replacing an existing entry, remove old LRU index entry and subtract old size.
        // Copy the fields first to avoid a simultaneous immutable + mutable borrow of `inner`.
        if let Some((old_order, old_size)) = inner
            .entries
            .get(&rid_hex)
            .map(|e| (e.access_order, e.size))
        {
            inner.lru_order.remove(&old_order);
            inner.current_size -= old_size;
        }

        let order = inner.access_counter;
        inner.lru_order.insert(order, rid_hex.clone());
        inner.entries.insert(
            rid_hex.clone(),
            CacheEntry {
                rid_hex,
                size: data_size,
                access_order: order,
            },
        );
        inner.current_size += data_size;

        Ok(())
    }

    /// Retrieve a block from the cache.
    ///
    /// Returns [`CacheError::Miss`] when the block is not cached, and also when
    /// its file is gone or does not authenticate under this cache's key and the
    /// block's RID (truncated, corrupted, or written under another key): such a
    /// file is removed so the block is fetched again. Wrong data is never
    /// returned for an encrypted cache.
    pub fn get(&self, rid: &[u8; 32]) -> Result<Vec<u8>> {
        let rid_hex = hex::encode(rid);

        {
            let mut inner = self.inner.lock().unwrap();
            if !inner.entries.contains_key(&rid_hex) {
                inner.misses += 1;
                return Err(CacheError::Miss(rid_hex));
            }
        }

        let path = self.block_path(&rid_hex);
        let raw = match std::fs::read(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.drop_block(&rid_hex);
                return Err(CacheError::Miss(rid_hex));
            }
            Err(e) => {
                self.inner.lock().unwrap().misses += 1;
                return Err(e.into());
            }
        };

        let data = if self.config.encrypt_at_rest {
            let aad = format!("cache:{rid_hex}");
            match aead::decrypt(&self.cache_key, &raw, aad.as_bytes()) {
                Ok(data) => data,
                Err(_) => {
                    self.drop_block(&rid_hex);
                    return Err(CacheError::Miss(rid_hex));
                }
            }
        } else {
            raw
        };

        let mut inner = self.inner.lock().unwrap();
        inner.access_counter += 1;
        let order = inner.access_counter;
        // The entry may have been evicted while the file was being read; the data
        // is good either way.
        if let Some(old_order) = inner.entries.get_mut(&rid_hex).map(|e| {
            let old = e.access_order;
            e.access_order = order;
            old
        }) {
            inner.lru_order.remove(&old_order);
            inner.lru_order.insert(order, rid_hex);
        }
        inner.hits += 1;
        Ok(data)
    }

    /// Forget a block whose file is missing or unusable and delete the file,
    /// counting the lookup that found it as a miss.
    fn drop_block(&self, rid_hex: &str) {
        let mut inner = self.inner.lock().unwrap();
        inner.misses += 1;
        if let Some(entry) = inner.entries.remove(rid_hex) {
            inner.lru_order.remove(&entry.access_order);
            inner.current_size -= entry.size;
        }
        let _ = std::fs::remove_file(self.block_path(rid_hex));
    }

    /// Check if a block is in the cache.
    pub fn contains(&self, rid: &[u8; 32]) -> bool {
        let rid_hex = hex::encode(rid);
        self.inner.lock().unwrap().entries.contains_key(&rid_hex)
    }

    /// Remove a block from the cache.
    pub fn remove(&self, rid: &[u8; 32]) -> Result<()> {
        let rid_hex = hex::encode(rid);
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.entries.remove(&rid_hex) {
            inner.lru_order.remove(&entry.access_order);
            inner.current_size -= entry.size;
            let path = self.block_path(&rid_hex);
            let _ = std::fs::remove_file(path);
        }
        Ok(())
    }

    /// Clear the entire cache.
    pub fn clear(&self) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        for (rid_hex, _) in inner.entries.drain() {
            let path = self.block_path(&rid_hex);
            let _ = std::fs::remove_file(path);
        }
        inner.lru_order.clear();
        inner.current_size = 0;
        inner.hits = 0;
        inner.misses = 0;
        Ok(())
    }

    /// Get cache statistics.
    pub fn stats(&self) -> CacheStats {
        let inner = self.inner.lock().unwrap();
        CacheStats {
            entries: inner.entries.len(),
            current_size: inner.current_size,
            max_size: self.config.max_size,
            hits: inner.hits,
            misses: inner.misses,
        }
    }

    fn block_path(&self, rid_hex: &str) -> PathBuf {
        block_path_in(&self.config.cache_dir, rid_hex)
    }

    fn evict_if_needed(&self, needed_size: u64) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        Self::evict_locked(&self.config, &mut inner, needed_size);
        Ok(())
    }

    /// Evict least recently used blocks until `needed_size` more bytes fit.
    fn evict_locked(config: &CacheConfig, inner: &mut CacheInner, needed_size: u64) {
        while inner.current_size + needed_size > config.max_size {
            // O(log n): the BTreeMap's first entry has the lowest access_order
            // (the least-recently-used block).
            let Some((_, lru_rid)) = inner.lru_order.pop_first() else {
                break;
            };
            if let Some(entry) = inner.entries.remove(&lru_rid) {
                inner.current_size -= entry.size;
                let _ = std::fs::remove_file(block_path_in(&config.cache_dir, &entry.rid_hex));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, BlockCache) {
        let dir = tempfile::TempDir::new().unwrap();
        let config = CacheConfig {
            cache_dir: dir.path().to_path_buf(),
            max_size: 10 * 1024, // 10KB for testing
            encrypt_at_rest: true,
        };
        let key = SymmetricKey::from_bytes([0x42; 32]);
        let cache = BlockCache::new(config, key).unwrap();
        (dir, cache)
    }

    #[test]
    fn put_and_get() {
        let (_dir, cache) = setup();
        let rid = [0x01; 32];
        let data = vec![0xAA; 256];

        cache.put(&rid, &data).unwrap();
        let retrieved = cache.get(&rid).unwrap();
        assert_eq!(retrieved, data);
    }

    #[test]
    fn get_miss() {
        let (_dir, cache) = setup();
        let rid = [0x01; 32];
        let err = cache.get(&rid).unwrap_err();
        assert!(matches!(err, CacheError::Miss(_)));
    }

    #[test]
    fn contains() {
        let (_dir, cache) = setup();
        let rid = [0x01; 32];
        assert!(!cache.contains(&rid));

        cache.put(&rid, &[1, 2, 3]).unwrap();
        assert!(cache.contains(&rid));
    }

    #[test]
    fn remove() {
        let (_dir, cache) = setup();
        let rid = [0x01; 32];
        cache.put(&rid, &[1, 2, 3]).unwrap();
        cache.remove(&rid).unwrap();
        assert!(!cache.contains(&rid));
    }

    #[test]
    fn stats_tracking() {
        let (_dir, cache) = setup();
        let rid = [0x01; 32];
        cache.put(&rid, &[1, 2, 3]).unwrap();

        let _ = cache.get(&rid).unwrap();
        let _ = cache.get(&[0xFF; 32]).unwrap_err();

        let stats = cache.stats();
        assert_eq!(stats.entries, 1);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn lru_eviction() {
        let (_dir, cache) = setup();

        // Fill cache with blocks close to limit
        // Cache max is 10KB; each encrypted block is ~256 + overhead
        let block_data = vec![0xAA; 2048]; // ~2KB each after encryption overhead

        let r1 = [0x01; 32];
        let r2 = [0x02; 32];
        let r3 = [0x03; 32];
        let r4 = [0x04; 32];
        let r5 = [0x05; 32];

        cache.put(&r1, &block_data).unwrap();
        cache.put(&r2, &block_data).unwrap();
        cache.put(&r3, &block_data).unwrap();

        // Access r1 to make it recently used
        let _ = cache.get(&r1);

        // Add more to trigger eviction
        cache.put(&r4, &block_data).unwrap();
        cache.put(&r5, &block_data).unwrap();

        // r2 should have been evicted (oldest access, r1 was refreshed)
        let stats = cache.stats();
        assert!(stats.current_size <= stats.max_size);
    }

    #[test]
    fn clear() {
        let (_dir, cache) = setup();
        cache.put(&[0x01; 32], &[1, 2, 3]).unwrap();
        cache.put(&[0x02; 32], &[4, 5, 6]).unwrap();
        cache.clear().unwrap();

        let stats = cache.stats();
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.current_size, 0);
    }

    #[test]
    fn encrypted_at_rest() {
        let (dir, cache) = setup();
        let rid = [0x01; 32];
        let data = vec![0xAA; 64];

        cache.put(&rid, &data).unwrap();

        // Read raw file - should be different from plaintext (encrypted)
        let rid_hex = hex::encode(rid);
        let subdir = &rid_hex[..2];
        let path = dir.path().join(subdir).join(&rid_hex);
        let raw = std::fs::read(path).unwrap();
        assert_ne!(raw, data);

        // But cache.get should return plaintext
        let retrieved = cache.get(&rid).unwrap();
        assert_eq!(retrieved, data);
    }

    #[test]
    fn put_recreates_subdir_after_eviction() {
        let (dir, cache) = setup();
        let rid = [0xABu8; 32];

        cache.put(&rid, &[1, 2, 3]).unwrap();
        cache.remove(&rid).unwrap();

        // The subdirectory may now be empty; manually remove it to simulate the
        // race where eviction deletes the empty directory.
        let rid_hex = hex::encode(rid);
        let subdir = &rid_hex[..2];
        let _ = std::fs::remove_dir(dir.path().join(subdir));

        // put() must recreate the subdirectory without error.
        let rid2 = [0xABu8; 32]; // same 2-char prefix
        cache.put(&rid2, &[4, 5, 6]).unwrap();
        let got = cache.get(&rid2).unwrap();
        assert_eq!(got, vec![4, 5, 6]);
    }

    #[test]
    fn unencrypted_mode() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = CacheConfig {
            cache_dir: dir.path().to_path_buf(),
            max_size: 10 * 1024,
            encrypt_at_rest: false,
        };
        let key = SymmetricKey::from_bytes([0x42; 32]);
        let cache = BlockCache::new(config, key).unwrap();

        let rid = [0x01; 32];
        let data = vec![0xAA; 64];
        cache.put(&rid, &data).unwrap();

        // Raw file should match plaintext
        let rid_hex = hex::encode(rid);
        let subdir = &rid_hex[..2];
        let path = dir.path().join(subdir).join(&rid_hex);
        let raw = std::fs::read(path).unwrap();
        assert_eq!(raw, data);
    }

    // --- persistence across instances (remounts) ---

    fn config_for(dir: &Path, max_size: u64) -> CacheConfig {
        CacheConfig {
            cache_dir: dir.to_path_buf(),
            max_size,
            encrypt_at_rest: true,
        }
    }

    fn open(dir: &Path, max_size: u64, key_byte: u8) -> BlockCache {
        BlockCache::new(
            config_for(dir, max_size),
            SymmetricKey::from_bytes([key_byte; 32]),
        )
        .unwrap()
    }

    fn block_file(dir: &Path, rid: &[u8; 32]) -> PathBuf {
        let rid_hex = hex::encode(rid);
        dir.join(&rid_hex[..2]).join(rid_hex)
    }

    /// Total bytes of every regular file below the cache directory, counted from
    /// the filesystem (not from any cache's own bookkeeping).
    fn bytes_on_disk(dir: &Path) -> u64 {
        let mut total = 0;
        for sub in std::fs::read_dir(dir).unwrap() {
            let sub = sub.unwrap().path();
            if sub.is_dir() {
                for f in std::fs::read_dir(&sub).unwrap() {
                    total += f.unwrap().metadata().unwrap().len();
                }
            } else {
                total += sub.metadata().unwrap().len();
            }
        }
        total
    }

    #[test]
    fn block_survives_a_new_instance() {
        let dir = tempfile::TempDir::new().unwrap();
        let rid = [0x11; 32];
        let data = vec![0x5A; 3000];

        open(dir.path(), 64 * 1024, 0x42).put(&rid, &data).unwrap();

        let second = open(dir.path(), 64 * 1024, 0x42);
        assert!(second.contains(&rid));
        assert_eq!(second.get(&rid).unwrap(), data);
        let stats = second.stats();
        assert_eq!(stats.entries, 1);
        assert_eq!(stats.current_size, bytes_on_disk(dir.path()));
        assert_eq!((stats.hits, stats.misses), (1, 0));
    }

    #[test]
    fn directory_never_exceeds_max_size_across_remounts() {
        let dir = tempfile::TempDir::new().unwrap();
        let max = 10 * 1024;
        let data = vec![0xAA; 2048];

        for mount in 0u8..6 {
            let cache = open(dir.path(), max, 0x42);
            for i in 0u8..3 {
                cache.put(&[mount * 16 + i; 32], &data).unwrap();
                assert!(
                    bytes_on_disk(dir.path()) <= max,
                    "mount {mount} put {i}: {} bytes on disk exceed {max}",
                    bytes_on_disk(dir.path())
                );
            }
            // The cache's own count must agree with the directory.
            assert_eq!(cache.stats().current_size, bytes_on_disk(dir.path()));
        }
    }

    #[test]
    fn new_evicts_an_oversized_directory_oldest_first() {
        let dir = tempfile::TempDir::new().unwrap();
        let data = vec![0xAA; 2048];
        let rids: Vec<[u8; 32]> = (1u8..=4).map(|i| [i; 32]).collect();
        {
            let big = open(dir.path(), 1024 * 1024, 0x42);
            for rid in &rids {
                big.put(rid, &data).unwrap();
            }
        }
        // Make the age order explicit: rids[0] oldest .. rids[3] newest.
        let base = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        for (i, rid) in rids.iter().enumerate() {
            let f = std::fs::File::options()
                .write(true)
                .open(block_file(dir.path(), rid))
                .unwrap();
            f.set_modified(base + std::time::Duration::from_secs(i as u64 * 10))
                .unwrap();
        }

        // Room for two encrypted blocks (2048 + 24 nonce + 16 tag = 2088 each).
        let small = open(dir.path(), 2 * 2088 + 10, 0x42);
        assert!(bytes_on_disk(dir.path()) <= 2 * 2088 + 10);
        assert!(!small.contains(&rids[0]) && !small.contains(&rids[1]));
        assert!(small.contains(&rids[2]) && small.contains(&rids[3]));
        assert!(!block_file(dir.path(), &rids[0]).exists());
        assert_eq!(small.get(&rids[3]).unwrap(), data);
        assert_eq!(small.stats().entries, 2);
    }

    #[test]
    fn new_removes_stray_files_and_keeps_unrelated_entries() {
        let dir = tempfile::TempDir::new().unwrap();
        let rid = [0xab; 32];
        open(dir.path(), 64 * 1024, 0x42)
            .put(&rid, &[1, 2, 3])
            .unwrap();
        let good_size = bytes_on_disk(dir.path());

        let rid_hex = hex::encode(rid);
        let sub = dir.path().join(&rid_hex[..2]);
        // The upper-case stray is another block's name, in that block's own
        // subdirectory: on a case-insensitive filesystem (macOS) an upper-case
        // copy of the valid block's name would alias the valid block itself.
        let other_sub = dir.path().join("cd");
        std::fs::create_dir(&other_sub).unwrap();
        // Leftovers of a crashed put, a misnamed file, an upper-case name, and a
        // file filed under the wrong subdirectory.
        let strays = [
            sub.join(format!(".{rid_hex}.tmp.1234.7")),
            sub.join("not-a-block"),
            other_sub.join(hex::encode([0xcdu8; 32]).to_uppercase()),
            sub.join(hex::encode([0x23u8; 32])),
        ];
        for s in &strays {
            std::fs::write(s, b"partial").unwrap();
        }
        // The cache directory may be shared with other things: top-level entries
        // that are not 2-hex-digit subdirectories are none of our business.
        let unrelated = dir.path().join("notes.txt");
        std::fs::write(&unrelated, b"keep me").unwrap();
        let other_dir = dir.path().join("lost+found");
        std::fs::create_dir(&other_dir).unwrap();
        std::fs::write(other_dir.join("x"), b"keep me too").unwrap();

        let cache = open(dir.path(), 64 * 1024, 0x42);
        for s in &strays {
            assert!(!s.exists(), "stray {} survived", s.display());
        }
        assert!(unrelated.exists() && other_dir.join("x").exists());
        assert_eq!(cache.stats().entries, 1);
        assert_eq!(cache.stats().current_size, good_size);
        assert_eq!(cache.get(&rid).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn put_leaves_no_temp_file_behind() {
        let dir = tempfile::TempDir::new().unwrap();
        let cache = open(dir.path(), 64 * 1024, 0x42);
        let rid = [0x33; 32];
        cache.put(&rid, &[9; 100]).unwrap();
        cache.put(&rid, &[8; 100]).unwrap(); // replace in place
        let sub = block_file(dir.path(), &rid).parent().unwrap().to_path_buf();
        let names: Vec<_> = std::fs::read_dir(&sub)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, vec![hex::encode(rid)]);
        assert_eq!(cache.get(&rid).unwrap(), vec![8; 100]);
    }

    /// Damage applied to a cached file by the corruption tests.
    fn flip_a_byte(path: &Path) {
        let mut raw = std::fs::read(path).unwrap();
        let mid = raw.len() / 2;
        raw[mid] ^= 0x01;
        std::fs::write(path, raw).unwrap();
    }
    fn truncate_half(path: &Path) {
        let raw = std::fs::read(path).unwrap();
        std::fs::write(path, &raw[..raw.len() / 2]).unwrap();
    }
    fn truncate_to_zero(path: &Path) {
        std::fs::write(path, b"").unwrap();
    }

    fn assert_damaged_block_is_a_removed_miss(damage: fn(&Path)) {
        let dir = tempfile::TempDir::new().unwrap();
        let data = vec![0xC3; 4096];

        // Damaged while the same instance holds it in its index.
        let rid = [0x44; 32];
        let cache = open(dir.path(), 64 * 1024, 0x42);
        cache.put(&rid, &data).unwrap();
        damage(&block_file(dir.path(), &rid));
        assert!(matches!(cache.get(&rid), Err(CacheError::Miss(_))));
        assert!(!block_file(dir.path(), &rid).exists());
        assert!(!cache.contains(&rid));
        assert_eq!(cache.stats().entries, 0);
        assert_eq!(cache.stats().current_size, 0);
        assert_eq!((cache.stats().hits, cache.stats().misses), (0, 1));

        // Damaged between mounts, found by the next instance.
        let rid2 = [0x45; 32];
        cache.put(&rid2, &data).unwrap();
        damage(&block_file(dir.path(), &rid2));
        let remounted = open(dir.path(), 64 * 1024, 0x42);
        assert!(matches!(remounted.get(&rid2), Err(CacheError::Miss(_))));
        assert!(!block_file(dir.path(), &rid2).exists());
        assert_eq!(remounted.stats().current_size, 0);

        // The slot is usable again afterwards.
        remounted.put(&rid2, &data).unwrap();
        assert_eq!(remounted.get(&rid2).unwrap(), data);
    }

    #[test]
    fn flipped_byte_is_a_removed_miss() {
        assert_damaged_block_is_a_removed_miss(flip_a_byte);
    }

    #[test]
    fn truncated_file_is_a_removed_miss() {
        assert_damaged_block_is_a_removed_miss(truncate_half);
    }

    #[test]
    fn empty_file_is_a_removed_miss() {
        assert_damaged_block_is_a_removed_miss(truncate_to_zero);
    }

    #[test]
    fn file_deleted_behind_the_cache_is_a_miss() {
        let dir = tempfile::TempDir::new().unwrap();
        let cache = open(dir.path(), 64 * 1024, 0x42);
        let rid = [0x46; 32];
        cache.put(&rid, &[1; 500]).unwrap();
        std::fs::remove_file(block_file(dir.path(), &rid)).unwrap();
        assert!(matches!(cache.get(&rid), Err(CacheError::Miss(_))));
        assert!(!cache.contains(&rid));
        assert_eq!(cache.stats().current_size, 0);
    }

    #[test]
    fn block_cached_under_another_key_is_a_removed_miss() {
        let dir = tempfile::TempDir::new().unwrap();
        let rid = [0x55; 32];
        open(dir.path(), 64 * 1024, 0x01)
            .put(&rid, b"volume one's block")
            .unwrap();

        // Same directory and block id, but another volume's key.
        let other = open(dir.path(), 64 * 1024, 0x02);
        assert!(matches!(other.get(&rid), Err(CacheError::Miss(_))));
        assert!(!block_file(dir.path(), &rid).exists());
        assert_eq!(other.stats().current_size, 0);
    }

    #[test]
    fn block_moved_to_another_block_id_is_a_miss() {
        // The AAD binds a cached file to its block id: a file renamed to a
        // different (well-formed) id must not authenticate.
        let dir = tempfile::TempDir::new().unwrap();
        let (a, b) = ([0x66; 32], [0x67; 32]);
        open(dir.path(), 64 * 1024, 0x42)
            .put(&a, b"block a")
            .unwrap();
        std::fs::create_dir_all(block_file(dir.path(), &b).parent().unwrap()).unwrap();
        std::fs::rename(block_file(dir.path(), &a), block_file(dir.path(), &b)).unwrap();

        let cache = open(dir.path(), 64 * 1024, 0x42);
        assert!(matches!(cache.get(&b), Err(CacheError::Miss(_))));
        assert!(!block_file(dir.path(), &b).exists());
    }

    #[test]
    fn block_larger_than_the_cache_is_not_stored() {
        let dir = tempfile::TempDir::new().unwrap();
        let cache = open(dir.path(), 1024, 0x42);
        cache.put(&[0x01; 32], &[1; 100]).unwrap();
        cache.put(&[0x02; 32], &[2; 4096]).unwrap();
        assert!(!cache.contains(&[0x02; 32]));
        // The small block that was already cached is not sacrificed for it.
        assert!(cache.contains(&[0x01; 32]));
        assert!(bytes_on_disk(dir.path()) <= 1024);
    }
}
