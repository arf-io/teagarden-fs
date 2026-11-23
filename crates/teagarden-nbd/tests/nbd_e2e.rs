//! In-process NBD end-to-end tests: a minimal NBD client drives the real server
//! over loopback TCP (no kernel module needed), first over the in-memory device
//! (protocol correctness), then over the FULL encrypted stack
//! `teagarden-dev` engine → `BlockDeviceAdapter` → NBD → client (real e2e).

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use teagarden_blockdev::{BlockDevice, LOGICAL_BLOCK_SIZE};
use teagarden_nbd::NbdServer;

const BS: usize = LOGICAL_BLOCK_SIZE as usize;

// NBD protocol constants (fixed by the spec; redeclared so the test doesn't lean
// on the server crate's internals).
const NBDMAGIC: u64 = 0x4e42_444d_4147_4943;
const IHAVEOPT: u64 = 0x4948_4156_454f_5054;
const NBD_REP_MAGIC: u64 = 0x0003_e889_0455_65a9;
const NBD_FLAG_C_FIXED_NEWSTYLE: u32 = 1;
const NBD_OPT_GO: u32 = 7;
const NBD_REP_ACK: u32 = 1;
const NBD_REP_INFO: u32 = 3;
const NBD_INFO_EXPORT: u16 = 0;
const NBD_REQUEST_MAGIC: u32 = 0x2560_9513;
const NBD_SIMPLE_REPLY_MAGIC: u32 = 0x6744_6698;
const NBD_CMD_READ: u16 = 0;
const NBD_CMD_WRITE: u16 = 1;
const NBD_CMD_DISC: u16 = 2;
const NBD_CMD_FLUSH: u16 = 3;
const NBD_CMD_TRIM: u16 = 4;

struct NbdClient {
    s: TcpStream,
    handle: u64,
}

impl NbdClient {
    /// Connect + newstyle handshake via NBD_OPT_GO (empty export name). Returns the
    /// client and the advertised export size.
    async fn connect(addr: std::net::SocketAddr) -> (Self, u64) {
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

    async fn request(&mut self, cmd: u16, offset: u64, length: u32, data: &[u8]) -> (u32, Vec<u8>) {
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

    async fn write(&mut self, offset: u64, data: &[u8]) -> u32 {
        self.request(NBD_CMD_WRITE, offset, data.len() as u32, data)
            .await
            .0
    }
    async fn read(&mut self, offset: u64, length: u32) -> (u32, Vec<u8>) {
        self.request(NBD_CMD_READ, offset, length, &[]).await
    }
    async fn flush(&mut self) -> u32 {
        self.request(NBD_CMD_FLUSH, 0, 0, &[]).await.0
    }
    async fn trim(&mut self, offset: u64, length: u32) -> u32 {
        self.request(NBD_CMD_TRIM, offset, length, &[]).await.0
    }
    async fn disconnect(mut self) {
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

async fn serve<D: BlockDevice>(device: Arc<D>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let server = NbdServer::new(device, "");
        let _ = server.serve_with_listener(listener).await;
    });
    addr
}

// Protocol correctness over the in-memory device: handshake advertises size,
// WRITE/READ round-trips, FLUSH/TRIM succeed, and alignment/range are enforced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nbd_protocol_round_trip_over_mem_device() {
    let dev = Arc::new(teagarden_blockdev::MemBlockDevice::new(64 * BS));
    let addr = serve(dev).await;
    let (mut c, size) = NbdClient::connect(addr).await;
    assert_eq!(size, (64 * BS) as u64);

    let a = vec![0xA1u8; 4 * BS];
    assert_eq!(c.write(0, &a).await, 0);
    assert_eq!(c.flush().await, 0);
    let (err, got) = c.read(0, 4 * BS as u32).await;
    assert_eq!(err, 0);
    assert_eq!(got, a);

    // TRIM then read → zeros
    assert_eq!(c.trim(0, BS as u32).await, 0);
    let (err, z) = c.read(0, BS as u32).await;
    assert_eq!(err, 0);
    assert_eq!(z, vec![0u8; BS]);

    // unaligned + out-of-range are rejected (EINVAL=22), not mishandled
    let (err, _) = c.read(1, BS as u32).await;
    assert_eq!(err, 22);
    let (err, _) = c.read(0, BS as u32 + 1).await;
    assert_eq!(err, 22);
    let (err, _) = c.read(1000 * BS as u64, BS as u32).await;
    assert_eq!(err, 22);
    // an oversized request length is rejected before any allocation (DoS guard)
    let (err, _) = c.read(0, 200 * 1024 * 1024).await;
    assert_eq!(err, 22);

    // nonzero (unnegotiated) command flags are rejected with EINVAL, not ignored
    c.handle += 1;
    let h = c.handle;
    c.s.write_u32(NBD_REQUEST_MAGIC).await.unwrap();
    c.s.write_u16(1).await.unwrap(); // e.g. FUA — never advertised (no SEND_FUA)
    c.s.write_u16(NBD_CMD_READ).await.unwrap();
    c.s.write_u64(h).await.unwrap();
    c.s.write_u64(0).await.unwrap();
    c.s.write_u32(BS as u32).await.unwrap();
    c.s.flush().await.unwrap();
    assert_eq!(c.s.read_u32().await.unwrap(), NBD_SIMPLE_REPLY_MAGIC);
    assert_eq!(c.s.read_u32().await.unwrap(), 22); // EINVAL
    assert_eq!(c.s.read_u64().await.unwrap(), h);

    c.disconnect().await;
}

// Regression: a TRIM/DISCARD whose length exceeds MAX_REQUEST_LEN (the READ/WRITE
// buffer cap) must SUCCEED, not be rejected as EINVAL. `mkfs` issues a single
// full-device DISCARD before laying down structures; when that was rejected the
// kernel logged a block-layer I/O error that escalated ext4 to errors=remount-ro,
// silently breaking every filesystem mounted on the device. A discard carries no
// payload, so the buffer cap does not apply.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nbd_whole_device_trim_larger_than_max_request_succeeds() {
    // 9000 blocks × 4 KiB ≈ 35 MiB > MAX_REQUEST_LEN (32 MiB).
    let blocks = 9000u64;
    let dev = Arc::new(teagarden_blockdev::MemBlockDevice::new(
        (blocks * BS as u64) as usize,
    ));
    let addr = serve(dev).await;
    let (mut c, size) = NbdClient::connect(addr).await;
    assert_eq!(size, blocks * BS as u64);

    let whole = u32::try_from(blocks * BS as u64).unwrap(); // ~35 MiB, fits u32
    assert!(
        whole as u64 > 32 * 1024 * 1024,
        "must exceed MAX_REQUEST_LEN"
    );
    assert_eq!(c.trim(0, whole).await, 0, "full-device TRIM must succeed");

    // A WRITE that large is still rejected (the cap protects buffer allocation).
    // Send a WRITE header for an oversized length with no payload; server replies
    // EINVAL and disconnects, so we only check the reply status.
    c.handle += 1;
    let h = c.handle;
    c.s.write_u32(NBD_REQUEST_MAGIC).await.unwrap();
    c.s.write_u16(0).await.unwrap();
    c.s.write_u16(NBD_CMD_WRITE).await.unwrap();
    c.s.write_u64(h).await.unwrap();
    c.s.write_u64(0).await.unwrap();
    c.s.write_u32(whole).await.unwrap(); // > MAX_REQUEST_LEN
    c.s.flush().await.unwrap();
    assert_eq!(c.s.read_u32().await.unwrap(), NBD_SIMPLE_REPLY_MAGIC);
    assert_eq!(c.s.read_u32().await.unwrap(), 22); // EINVAL — oversized WRITE still capped
}

// FULL encrypted stack e2e: TeaGarden block-device engine → BlockDeviceAdapter → NBD → client.
// Bytes written by the NBD client are position-addressed, AEAD-sealed into
// segments, and read back byte-exact through the whole stack.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn nbd_full_stack_over_teagarden_dev() {
    use teagarden_core::crypto::keys::SymmetricKey;
    use teagarden_dev::adapter::BlockDeviceAdapter;
    use teagarden_dev::cache::CacheConfig;
    use teagarden_dev::device::{DeviceConfig, DeviceKeys, TeaGardenDevice};
    use teagarden_telegram::mock::MockTransport;

    let dir = tempfile::tempdir().unwrap();
    let keys = DeviceKeys {
        data_key: SymmetricKey::from_bytes([1u8; 32]),
        meta_key: SymmetricKey::from_bytes([2u8; 32]),
        integrity_key: SymmetricKey::from_bytes([3u8; 32]),
    };
    let cfg = DeviceConfig {
        segment_target: 32 * 1024,
        record_max: 8 * 1024,
        cache: CacheConfig {
            budget_bytes: 1 << 30,
            ..Default::default()
        },
        ..Default::default()
    };
    let transport = Arc::new(MockTransport::new());
    let device = TeaGardenDevice::create(transport, keys, [7u8; 16], 256, dir.path(), cfg).unwrap();
    let adapter = BlockDeviceAdapter::new(device, tokio::runtime::Handle::current());
    let addr = serve(Arc::new(adapter)).await;

    let (mut c, size) = NbdClient::connect(addr).await;
    assert_eq!(size, 256 * BS as u64);

    // a filesystem-like access pattern: scattered aligned writes, then verify
    let p1 = vec![0x11u8; 8 * BS]; // 8 blocks at block 0
    let p2 = vec![0x22u8; 4 * BS]; // 4 blocks at block 100
    assert_eq!(c.write(0, &p1).await, 0);
    assert_eq!(c.write(100 * BS as u64, &p2).await, 0);
    assert_eq!(c.flush().await, 0);

    let (err, g1) = c.read(0, 8 * BS as u32).await;
    assert_eq!(err, 0);
    assert_eq!(g1, p1);
    let (err, g2) = c.read(100 * BS as u64, 4 * BS as u32).await;
    assert_eq!(err, 0);
    assert_eq!(g2, p2);
    // an untouched region reads zeros through the whole stack
    let (err, hole) = c.read(50 * BS as u64, BS as u32).await;
    assert_eq!(err, 0);
    assert_eq!(hole, vec![0u8; BS]);

    // overwrite mid-extent (position-addressed supersede) and re-verify
    let ov = vec![0x33u8; BS];
    assert_eq!(c.write(2 * BS as u64, &ov).await, 0);
    let (_e, g) = c.read(0, 8 * BS as u32).await;
    assert_eq!(&g[0..2 * BS], &p1[0..2 * BS]);
    assert_eq!(&g[2 * BS..3 * BS], &ov[..]);
    assert_eq!(&g[3 * BS..], &p1[3 * BS..]);

    c.disconnect().await;
}

// A failed staging fsync on the device side reaches the NBD client as EIO —
// and STAYS failed: the next FLUSH and WRITE must not report success, or the
// guest filesystem would believe lost writes durable (fsync "gate").
// Uses the TeaGarden block device's test-only `fault-injection` hook to fail one fsync.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nbd_fsync_failure_is_sticky_eio() {
    use teagarden_core::crypto::keys::SymmetricKey;
    use teagarden_dev::adapter::BlockDeviceAdapter;
    use teagarden_dev::cache::CacheConfig;
    use teagarden_dev::device::{DeviceConfig, DeviceKeys, TeaGardenDevice};
    use teagarden_telegram::mock::MockTransport;

    const EIO: u32 = 5;
    let dir = tempfile::tempdir().unwrap();
    let keys = DeviceKeys {
        data_key: SymmetricKey::from_bytes([1u8; 32]),
        meta_key: SymmetricKey::from_bytes([2u8; 32]),
        integrity_key: SymmetricKey::from_bytes([3u8; 32]),
    };
    let cfg = DeviceConfig {
        segment_target: 32 * 1024,
        record_max: 8 * 1024,
        cache: CacheConfig {
            budget_bytes: 1 << 30,
            ..Default::default()
        },
        ..Default::default()
    };
    let transport = Arc::new(MockTransport::new());
    let mut device =
        TeaGardenDevice::create(transport, keys, [7u8; 16], 256, dir.path(), cfg).unwrap();
    device.inject_fsync_failures(1, 0);
    let adapter = BlockDeviceAdapter::new(device, tokio::runtime::Handle::current());
    let addr = serve(Arc::new(adapter)).await;
    let (mut c, _size) = NbdClient::connect(addr).await;

    assert_eq!(c.write(0, &vec![0x11u8; BS]).await, 0);
    assert_eq!(c.flush().await, EIO, "failed fsync not reported as EIO");
    assert_eq!(c.flush().await, EIO, "flush after a failed fsync succeeded");
    assert_eq!(c.write(BS as u64, &vec![0x22u8; BS]).await, EIO);
    assert_eq!(c.flush().await, EIO);
    c.disconnect().await;
}

// TWO concurrent NBD connections to the same teagarden-dev-backed device (advisor):
// exercises the adapter's async Mutex serialization + per-connection server tasks.
// The clients write disjoint regions concurrently and each reads its own back —
// no interference through the shared single-writer engine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nbd_two_concurrent_connections_over_teagarden_dev() {
    use teagarden_core::crypto::keys::SymmetricKey;
    use teagarden_dev::adapter::BlockDeviceAdapter;
    use teagarden_dev::cache::CacheConfig;
    use teagarden_dev::device::{DeviceConfig, DeviceKeys, TeaGardenDevice};
    use teagarden_telegram::mock::MockTransport;

    let dir = tempfile::tempdir().unwrap();
    let keys = DeviceKeys {
        data_key: SymmetricKey::from_bytes([1u8; 32]),
        meta_key: SymmetricKey::from_bytes([2u8; 32]),
        integrity_key: SymmetricKey::from_bytes([3u8; 32]),
    };
    let cfg = DeviceConfig {
        segment_target: 32 * 1024,
        record_max: 8 * 1024,
        cache: CacheConfig {
            budget_bytes: 1 << 30,
            ..Default::default()
        },
        ..Default::default()
    };
    let device = TeaGardenDevice::create(
        Arc::new(MockTransport::new()),
        keys,
        [7u8; 16],
        256,
        dir.path(),
        cfg,
    )
    .unwrap();
    let adapter = BlockDeviceAdapter::new(device, tokio::runtime::Handle::current());
    let addr = serve(Arc::new(adapter)).await;

    let region = |off: u64, byte: u8| async move {
        let (mut c, _) = NbdClient::connect(addr).await;
        let data = vec![byte; 8 * BS];
        for _ in 0..5 {
            assert_eq!(c.write(off, &data).await, 0);
            let (e, g) = c.read(off, 8 * BS as u32).await;
            assert_eq!(e, 0);
            assert_eq!(g, data); // this client never sees the other's bytes
        }
        c.disconnect().await;
    };
    let h1 = tokio::spawn(region(0, 0xAA));
    let h2 = tokio::spawn(region(100 * BS as u64, 0xBB));
    h1.await.unwrap();
    h2.await.unwrap();
}
