//! In-memory [`BlockDevice`] test double.

use std::io;
use std::sync::Mutex;

use crate::{BlockDevice, LOGICAL_BLOCK_SIZE};

/// A volatile, memory-backed [`BlockDevice`] for tests and development. Not
/// persistent across restarts. A `discard`ed range reads back as zeros, matching
/// the log-structured device's "discarded ⇒ unmapped ⇒ zeros" contract.
pub struct MemBlockDevice(Mutex<Vec<u8>>);

impl MemBlockDevice {
    /// Create a device with `size_bytes` of zero-initialised storage.
    /// `size_bytes` must be a multiple of [`LOGICAL_BLOCK_SIZE`].
    pub fn new(size_bytes: usize) -> Self {
        assert_eq!(
            size_bytes % LOGICAL_BLOCK_SIZE as usize,
            0,
            "MemBlockDevice size must be a multiple of LOGICAL_BLOCK_SIZE"
        );
        Self(Mutex::new(vec![0u8; size_bytes]))
    }

    fn byte_range(&self, lba: u64, count: u32) -> io::Result<(usize, usize)> {
        let offset = (lba as usize)
            .checked_mul(LOGICAL_BLOCK_SIZE as usize)
            .ok_or_else(overflow)?;
        let len = (count as usize)
            .checked_mul(LOGICAL_BLOCK_SIZE as usize)
            .ok_or_else(overflow)?;
        Ok((offset, len))
    }
}

fn overflow() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "lba/count overflow")
}
fn oob() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "request beyond device end")
}
fn badlen(actual: usize, expected: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("buffer length {actual} != expected {expected} bytes for the request"),
    )
}

impl BlockDevice for MemBlockDevice {
    fn capacity(&self) -> u64 {
        self.0.lock().unwrap().len() as u64
    }

    fn read_blocks(&self, lba: u64, count: u32, buf: &mut [u8]) -> io::Result<()> {
        let (offset, len) = self.byte_range(lba, count)?;
        // Enforce the trait's exact-buffer-size contract: a short buffer would
        // panic in `copy_from_slice`, an oversized one would silently mislead.
        if buf.len() != len {
            return Err(badlen(buf.len(), len));
        }
        let storage = self.0.lock().unwrap();
        if offset.checked_add(len).ok_or_else(overflow)? > storage.len() {
            return Err(oob());
        }
        buf.copy_from_slice(&storage[offset..offset + len]);
        Ok(())
    }

    fn write_blocks(&self, lba: u64, count: u32, data: &[u8]) -> io::Result<()> {
        let (offset, len) = self.byte_range(lba, count)?;
        if data.len() != len {
            return Err(badlen(data.len(), len));
        }
        let mut storage = self.0.lock().unwrap();
        if offset.checked_add(len).ok_or_else(overflow)? > storage.len() {
            return Err(oob());
        }
        storage[offset..offset + len].copy_from_slice(data);
        Ok(())
    }

    fn discard(&self, lba: u64, count: u32) -> io::Result<()> {
        let (offset, len) = self.byte_range(lba, count)?;
        let mut storage = self.0.lock().unwrap();
        if offset.checked_add(len).ok_or_else(overflow)? > storage.len() {
            return Err(oob());
        }
        storage[offset..offset + len].fill(0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_discard_and_bounds() {
        let bs = LOGICAL_BLOCK_SIZE as usize;
        let dev = MemBlockDevice::new(16 * bs);
        assert_eq!(dev.capacity(), 16 * LOGICAL_BLOCK_SIZE);

        // write two blocks at lba 3, read them back
        let data = vec![0xabu8; 2 * bs];
        dev.write_blocks(3, 2, &data).unwrap();
        let mut buf = vec![0u8; 2 * bs];
        dev.read_blocks(3, 2, &mut buf).unwrap();
        assert_eq!(buf, data);

        // discard the first of the two → zeros; the second stays intact
        dev.discard(3, 1).unwrap();
        dev.read_blocks(3, 2, &mut buf).unwrap();
        assert!(buf[..bs].iter().all(|&b| b == 0));
        assert!(buf[bs..].iter().all(|&b| b == 0xab));

        // out-of-bounds is an error, not a panic
        assert!(dev.read_blocks(15, 2, &mut buf).is_err());
        assert!(dev.write_blocks(16, 1, &data[..bs]).is_err());
    }

    #[test]
    fn buffer_length_mismatch_is_error_not_panic() {
        let bs = LOGICAL_BLOCK_SIZE as usize;
        let dev = MemBlockDevice::new(8 * bs);

        // a short read buffer errors instead of panicking in copy_from_slice
        let mut short = vec![0u8; bs - 1];
        assert!(dev.read_blocks(0, 1, &mut short).is_err());
        // an oversized read buffer also errors (would otherwise mislead)
        let mut big = vec![0u8; 2 * bs];
        assert!(dev.read_blocks(0, 1, &mut big).is_err());
        // short + oversized write buffers error (no silent truncation)
        assert!(dev.write_blocks(0, 1, &vec![0u8; bs - 1]).is_err());
        assert!(dev.write_blocks(0, 1, &vec![0u8; bs + 1]).is_err());
        // the exact size still succeeds
        let mut exact = vec![0u8; bs];
        assert!(dev.read_blocks(0, 1, &mut exact).is_ok());
        assert!(dev.write_blocks(0, 1, &vec![0u8; bs]).is_ok());
    }
}
