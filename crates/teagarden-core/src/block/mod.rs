/// Selection of the AEAD additional-authenticated-data for block formats v1/v2.
pub mod aad;
/// Content-defined chunking (CDC) that splits files into variable-size blocks.
pub mod cdc;
/// Pre-encryption block compression (LZ4 / Zstd).
pub mod compress;
/// In-memory, session-scoped block deduplication index.
pub mod dedup;
/// Block pointer: the addressable location and metadata of a stored block.
pub mod pointer;
/// SRB1 on-disk block format (single content-hash header).
pub mod srb1;
/// SRB2 on-disk block format (inner plaintext + outer ciphertext hashes).
pub mod srb2;

/// Test-only: a read-only, zero-filled mapping larger than `u32::MAX` bytes.
///
/// Backed by `MAP_NORESERVE` anonymous memory, so it costs no RAM or commit
/// charge until a page is touched. The over-length refusal in `srb1::encode` /
/// `srb2::encode` must happen before any byte is read; a regression that reads
/// the buffer still only maps the shared zero page.
#[cfg(all(test, unix, target_pointer_width = "64"))]
pub(crate) mod oversize {
    /// One byte past the largest length a `u32` header field can carry.
    pub(crate) const LEN: usize = u32::MAX as usize + 2;

    pub(crate) struct Mapping(*mut libc::c_void);

    impl Mapping {
        pub(crate) fn new() -> Self {
            // SAFETY: anonymous private mapping, no fd; checked for MAP_FAILED.
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    LEN,
                    libc::PROT_READ,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                    -1,
                    0,
                )
            };
            assert_ne!(
                p,
                libc::MAP_FAILED,
                "mmap of the oversize test buffer failed"
            );
            Self(p)
        }

        pub(crate) fn as_slice(&self) -> &[u8] {
            // SAFETY: the mapping is LEN bytes, readable, and lives as long as self.
            unsafe { std::slice::from_raw_parts(self.0 as *const u8, LEN) }
        }
    }

    impl Drop for Mapping {
        fn drop(&mut self) {
            // SAFETY: unmapping exactly the region mapped in `new`.
            unsafe {
                libc::munmap(self.0, LEN);
            }
        }
    }
}
