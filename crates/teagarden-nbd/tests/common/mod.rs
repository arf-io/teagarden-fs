//! Shared by the `serve_*` integration tests: a minimal NBD client (the same
//! one `nbd_e2e.rs` uses) and a TeaGarden block device over the test transport.
#![allow(dead_code)]

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use teagarden_blockdev::LOGICAL_BLOCK_SIZE;
use teagarden_core::crypto::keys::SymmetricKey;
use teagarden_dev::adapter::BlockDeviceAdapter;
use teagarden_dev::cache::CacheConfig;
use teagarden_dev::device::{DeviceConfig, DeviceKeys, TeaGardenDevice};
use teagarden_telegram::mock::MockTransport;

pub const BS: usize = LOGICAL_BLOCK_SIZE as usize;
pub const UUID: [u8; 16] = [7u8; 16];
pub const CAPACITY: u64 = 4096;

// NBD protocol constants (fixed by the spec; redeclared so the test doesn't lean
// on the server crate's internals).
pub const NBDMAGIC: u64 = 0x4e42_444d_4147_4943;
pub const IHAVEOPT: u64 = 0x4948_4156_454f_5054;
pub const NBD_REP_MAGIC: u64 = 0x0003_e889_0455_65a9;
pub const NBD_FLAG_C_FIXED_NEWSTYLE: u32 = 1;
pub const NBD_OPT_GO: u32 = 7;
pub const NBD_REP_ACK: u32 = 1;
pub const NBD_REP_INFO: u32 = 3;
pub const NBD_INFO_EXPORT: u16 = 0;
pub const NBD_REQUEST_MAGIC: u32 = 0x2560_9513;
pub const NBD_SIMPLE_REPLY_MAGIC: u32 = 0x6744_6698;
pub const NBD_CMD_READ: u16 = 0;
pub const NBD_CMD_WRITE: u16 = 1;
pub const NBD_CMD_DISC: u16 = 2;
pub const NBD_CMD_FLUSH: u16 = 3;
pub const NBD_CMD_TRIM: u16 = 4;

pub struct NbdClient {
    s: TcpStream,
    handle: u64,
}

impl NbdClient {
    /// Connect + newstyle handshake via NBD_OPT_GO (empty export name). Returns the
    /// client and the advertised export size.
    pub async fn connect(addr: std::net::SocketAddr) -> (Self, u64) {
        let mut s = TcpStream::connect(addr).await.unwrap();
        assert_eq!(s.read_u64().await.unwrap(), NBDMAGIC);
        assert_eq!(s.read_u64().await.unwrap(), IHAVEOPT);
        let _hs_flags = s.read_u16().await.unwrap();
        s.write_u32(NBD_FLAG_C_FIXED_NEWSTYLE).await.unwrap();

        // NBD_OPT_GO, data = [u32 name_len=0][u16 n_info=0]
        s.write_u64(IHAVEOPT).await.unwrap();
        s.write_u32(NBD_OPT_GO).await.unwrap();
        s.write_u32(6).await.unwrap();
        s.write_u32(0).await.unwrap(); // name_len = 0 → default export
        s.write_u16(0).await.unwrap(); // n_info = 0
        s.flush().await.unwrap();

        let mut size = 0u64;
        loop {
            assert_eq!(s.read_u64().await.unwrap(), NBD_REP_MAGIC);
            let _opt = s.read_u32().await.unwrap();
            let rtype = s.read_u32().await.unwrap();
            let len = s.read_u32().await.unwrap() as usize;
            let mut d = vec![0u8; len];
            s.read_exact(&mut d).await.unwrap();
            if rtype == NBD_REP_INFO && len >= 2 {
                let info_type = u16::from_be_bytes([d[0], d[1]]);
                if info_type == NBD_INFO_EXPORT {
                    size = u64::from_be_bytes(d[2..10].try_into().unwrap());
                }
            } else if rtype == NBD_REP_ACK {
                break;
            } else if rtype & (1 << 31) != 0 {
                panic!("NBD_OPT_GO error reply {rtype:#x}");
            }
        }
        (Self { s, handle: 0 }, size)
    }

    pub async fn request(
        &mut self,
        cmd: u16,
        offset: u64,
        length: u32,
        data: &[u8],
    ) -> (u32, Vec<u8>) {
        self.handle += 1;
        let h = self.handle;
        self.s.write_u32(NBD_REQUEST_MAGIC).await.unwrap();
        self.s.write_u16(0).await.unwrap(); // command flags
        self.s.write_u16(cmd).await.unwrap();
        self.s.write_u64(h).await.unwrap();
        self.s.write_u64(offset).await.unwrap();
        self.s.write_u32(length).await.unwrap();
        if !data.is_empty() {
            self.s.write_all(data).await.unwrap();
        }
        self.s.flush().await.unwrap();

        assert_eq!(self.s.read_u32().await.unwrap(), NBD_SIMPLE_REPLY_MAGIC);
        let err = self.s.read_u32().await.unwrap();
        assert_eq!(self.s.read_u64().await.unwrap(), h);
        let mut payload = Vec::new();
        if cmd == NBD_CMD_READ && err == 0 {
            payload = vec![0u8; length as usize];
            self.s.read_exact(&mut payload).await.unwrap();
        }
        (err, payload)
    }

    pub async fn write(&mut self, offset: u64, data: &[u8]) -> u32 {
        self.request(NBD_CMD_WRITE, offset, data.len() as u32, data)
            .await
            .0
    }
    pub async fn read(&mut self, offset: u64, length: u32) -> (u32, Vec<u8>) {
        self.request(NBD_CMD_READ, offset, length, &[]).await
    }
    pub async fn flush(&mut self) -> u32 {
        self.request(NBD_CMD_FLUSH, 0, 0, &[]).await.0
    }
    pub async fn trim(&mut self, offset: u64, length: u32) -> u32 {
        self.request(NBD_CMD_TRIM, offset, length, &[]).await.0
    }
    /// Send a request WITHOUT waiting for its reply (pipelining, as the kernel
    /// does).
    pub async fn send_only(&mut self, cmd: u16, offset: u64, length: u32) {
        self.handle += 1;
        self.s.write_u32(NBD_REQUEST_MAGIC).await.unwrap();
        self.s.write_u16(0).await.unwrap();
        self.s.write_u16(cmd).await.unwrap();
        self.s.write_u64(self.handle).await.unwrap();
        self.s.write_u64(offset).await.unwrap();
        self.s.write_u32(length).await.unwrap();
        self.s.flush().await.unwrap();
    }

    pub async fn disconnect(mut self) {
        self.handle += 1;
        self.s.write_u32(NBD_REQUEST_MAGIC).await.unwrap();
        self.s.write_u16(0).await.unwrap();
        self.s.write_u16(NBD_CMD_DISC).await.unwrap();
        self.s.write_u64(self.handle).await.unwrap();
        self.s.write_u64(0).await.unwrap();
        self.s.write_u32(0).await.unwrap();
        self.s.flush().await.unwrap();
    }
}

pub fn keys() -> DeviceKeys {
    DeviceKeys {
        data_key: SymmetricKey::from_bytes([1u8; 32]),
        meta_key: SymmetricKey::from_bytes([2u8; 32]),
        integrity_key: SymmetricKey::from_bytes([3u8; 32]),
    }
}

/// 32 KiB segments: an 8-block (32 KiB) write fills and seals one.
pub fn config() -> DeviceConfig {
    DeviceConfig {
        segment_target: 32 * 1024,
        record_max: 8 * 1024,
        cache: CacheConfig {
            budget_bytes: 1 << 30,
            ..Default::default()
        },
        ..Default::default()
    }
}

pub fn new_device(
    dir: &std::path::Path,
    transport: Arc<MockTransport>,
) -> Arc<BlockDeviceAdapter<MockTransport>> {
    let dev = TeaGardenDevice::create(transport, keys(), UUID, CAPACITY, dir, config()).unwrap();
    Arc::new(BlockDeviceAdapter::new(
        dev,
        tokio::runtime::Handle::current(),
    ))
}

/// Deterministic, block-distinct bytes.
pub fn pattern(blocks: usize, seed: u8) -> Vec<u8> {
    (0..blocks * BS)
        .map(|i| {
            (i as u8)
                .wrapping_mul(31)
                .wrapping_add(seed)
                .wrapping_add((i / BS) as u8)
        })
        .collect()
}

/// Rebuild the device from Telegram alone (an EMPTY directory) at `head` and
/// read `count` blocks at `lba`.
pub async fn recover_and_read(
    transport: Arc<MockTransport>,
    head: i64,
    lba: u64,
    count: u64,
) -> Vec<u8> {
    let fresh = tempfile::tempdir().unwrap();
    let mut dev =
        TeaGardenDevice::recover_from_head(transport, keys(), UUID, fresh.path(), head, config())
            .await
            .expect("recover_from_head into an empty directory");
    dev.read_at(lba, count).await.unwrap()
}
