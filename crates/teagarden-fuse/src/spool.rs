//! Sole durable payload for open writes. Intents contain metadata and part offsets only.
use ring::digest::{Context as Sha256, SHA256};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::{FileExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use teagarden_core::{
    crypto::{aead, keys::SymmetricKey},
    sdo::{
        streaming::{SdoFileStream, SdoStreamPlan},
        SdoObjectMetadataV3,
    },
};
use teagarden_telegram::transfer::UploadSource;
const MAX_INTENT_BYTES: u64 = 16 * 1024 * 1024;
const AAD: &[u8] = b"teagarden.write-spool.intent.v1";
// Each block has a fresh random XChaCha20-Poly1305 nonce on every rewrite.
// Physical addressing is fixed-stride; only the final record can be short.
const BLOCK: u64 = 64 * 1024;
const OVERHEAD: u64 = (aead::NONCE_SIZE + aead::TAG_SIZE) as u64;
const STRIDE: u64 = BLOCK + OVERHEAD;
pub(crate) struct SpoolFile {
    file: File,
    key: SymmetricKey,
    id: uuid::Uuid,
    position: u64,
    io: std::sync::Arc<teagarden_telegram::transfer::LocalWriteStats>,
}
impl SpoolFile {
    fn new(
        file: File,
        hierarchy_key: &SymmetricKey,
        id: uuid::Uuid,
        io: std::sync::Arc<teagarden_telegram::transfer::LocalWriteStats>,
    ) -> Self {
        let mut material = zeroize::Zeroizing::new([0u8; 48]);
        material[..32].copy_from_slice(hierarchy_key.as_bytes());
        material[32..].copy_from_slice(id.as_bytes());
        let key = SymmetricKey::from_bytes(blake3::derive_key(
            "teagarden encrypted write spool payload v1",
            material.as_ref(),
        ));
        Self {
            file,
            key,
            id,
            position: 0,
            io,
        }
    }
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            file: self.file.try_clone()?,
            key: self.key.clone(),
            id: self.id,
            position: self.position,
            io: self.io.clone(),
        })
    }
    fn aad(&self, block: u64) -> Vec<u8> {
        let mut aad = b"teagarden.spool.block.v1".to_vec();
        aad.extend_from_slice(self.id.as_bytes());
        aad.extend_from_slice(&block.to_le_bytes());
        aad
    }
    fn len(&self) -> io::Result<u64> {
        let size = self.file.metadata()?.len();
        let tail = size % STRIDE;
        if tail != 0 && tail <= OVERHEAD {
            return Err(io::Error::other("truncated encrypted spool block"));
        }
        Ok(size / STRIDE * BLOCK + tail.saturating_sub(OVERHEAD))
    }
    fn block(&self, index: u64, len: u64) -> io::Result<zeroize::Zeroizing<Vec<u8>>> {
        let n = len.saturating_sub(index * BLOCK).min(BLOCK);
        if n == 0 {
            return Ok(zeroize::Zeroizing::new(Vec::new()));
        }
        let mut wire = vec![0; (n + OVERHEAD) as usize];
        self.file.read_exact_at(&mut wire, index * STRIDE)?;
        aead::decrypt(&self.key, &wire, &self.aad(index))
            .map(zeroize::Zeroizing::new)
            .map_err(|_| io::Error::other("encrypted spool authentication failed"))
    }
    fn put_block(&self, index: u64, plain: &[u8]) -> io::Result<()> {
        let wire = aead::encrypt(&self.key, plain, &self.aad(index))
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.file.write_all_at(&wire, index * STRIDE)?;
        self.io.record_payload(wire.len() as u64);
        Ok(())
    }
    fn read_exact_at(&self, mut out: &mut [u8], mut offset: u64) -> io::Result<()> {
        if out.is_empty() {
            return Ok(());
        }
        let len = self.len()?;
        if offset
            .checked_add(out.len() as u64)
            .is_none_or(|end| end > len)
        {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "encrypted spool EOF",
            ));
        }
        while !out.is_empty() {
            let block = self.block(offset / BLOCK, len)?;
            let start = (offset % BLOCK) as usize;
            let n = out.len().min(block.len() - start);
            out[..n].copy_from_slice(&block[start..start + n]);
            offset += n as u64;
            out = &mut out[n..];
        }
        Ok(())
    }
    fn write_all_at(&self, mut bytes: &[u8], mut offset: u64) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let mut len = self.len()?;
        if offset > len {
            self.set_len(offset)?;
            len = offset;
        }
        while !bytes.is_empty() {
            let index = offset / BLOCK;
            let start = (offset % BLOCK) as usize;
            let n = bytes.len().min(BLOCK as usize - start);
            let mut block = self.block(index, len)?;
            let new_len = block.len().max(start + n);
            block.resize(new_len, 0);
            block[start..start + n].copy_from_slice(&bytes[..n]);
            self.put_block(index, &block)?;
            offset += n as u64;
            len = len.max(offset);
            bytes = &bytes[n..];
        }
        Ok(())
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        let old = self.len()?;
        if len < old {
            let tail = len % BLOCK;
            if tail != 0 {
                let block = self.block(len / BLOCK, old)?;
                self.put_block(len / BLOCK, &block[..tail as usize])?;
            }
            self.file
                .set_len(len / BLOCK * STRIDE + if tail == 0 { 0 } else { tail + OVERHEAD })?;
        } else {
            let zeroes = [0; BLOCK as usize];
            let mut offset = old;
            while offset < len {
                let n = (len - offset).min(BLOCK) as usize;
                self.write_all_at(&zeroes[..n], offset)?;
                offset += n as u64;
            }
        }
        Ok(())
    }
    pub fn sync_data(&self) -> io::Result<()> {
        self.file.sync_data()
    }
    pub fn sync_all(&self) -> io::Result<()> {
        self.file.sync_all()
    }
}
impl Read for SpoolFile {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self
            .len()?
            .saturating_sub(self.position)
            .min(out.len() as u64) as usize;
        self.read_exact_at(&mut out[..n], self.position)?;
        self.position += n as u64;
        Ok(n)
    }
}
impl Seek for SpoolFile {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let next = match from {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::Current(n) => self.position as i128 + n as i128,
            SeekFrom::End(n) => self.len()? as i128 + n as i128,
        };
        self.position = u64::try_from(next).map_err(|_| io::Error::other("invalid spool seek"))?;
        Ok(self.position)
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Intent {
    #[serde(default)]
    payload_format: u8,
    #[serde(default)]
    pub initialized: bool,
    #[serde(default)]
    empty_create: bool,
    pub inode: u64,
    pub handle: u64,
    pub spool: PathBuf,
    pub metadata: SdoObjectMetadataV3,
    pub plan: Option<SdoStreamPlan>,
    pub upload_id: i64,
    pub publication_id: i64,
    pub acknowledged: BTreeSet<usize>,
    pub confirmed: Option<i64>,
    pub file_hash: [u8; 32],
}
struct HashWorker {
    sender: std::sync::mpsc::SyncSender<Vec<u8>>,
    join: std::thread::JoinHandle<io::Result<Sha256>>,
}

pub(crate) struct WriteSpool {
    hash_worker: Option<HashWorker>,
    pub file: SpoolFile,
    pub intent: Intent,
    pub intent_path: PathBuf,
    key: SymmetricKey,
    segment_hash: blake3::Hasher,
    segment_pos: usize,
    segment_checks: Vec<[u8; 32]>,
    hash: Sha256,
    manifest_hash: blake3::Hasher,
    hashed_len: Option<u64>,
    pub written: u64,
    io: std::sync::Arc<teagarden_telegram::transfer::LocalWriteStats>,
}
impl WriteSpool {
    pub fn create(
        root: &Path,
        key: SymmetricKey,
        manifest_key: &SymmetricKey,
        metadata: SdoObjectMetadataV3,
        inode: u64,
        handle: u64,
    ) -> io::Result<Self> {
        use rand::Rng;
        std::fs::create_dir_all(root)?;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        let stem = metadata.version_id.to_string();
        let path = root.join(format!("{stem}.spool"));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let io = std::sync::Arc::default();
        let s = Self {
            hash_worker: None,
            file: SpoolFile::new(file, &key, metadata.version_id, std::sync::Arc::clone(&io)),
            intent: Intent {
                payload_format: 1,
                initialized: false,
                empty_create: false,
                inode,
                handle,
                spool: path,
                metadata,
                plan: None,
                upload_id: rand::thread_rng().gen(),
                publication_id: rand::thread_rng().gen(),
                acknowledged: BTreeSet::new(),
                confirmed: None,
                file_hash: [0; 32],
            },
            intent_path: root.join(format!("{stem}.intent")),
            key,
            segment_hash: blake3::Hasher::new(),
            segment_pos: 0,
            segment_checks: Vec::new(),
            hash: Sha256::new(&SHA256),
            manifest_hash: blake3::Hasher::new_keyed(manifest_key.as_bytes()),
            hashed_len: Some(0),
            written: 0,
            io,
        };
        s.save()?;
        File::open(root)?.sync_all()?;
        Ok(s)
    }
    pub fn load(path: &Path, key: SymmetricKey, manifest_key: &SymmetricKey) -> io::Result<Self> {
        if std::fs::metadata(path)?.len() > MAX_INTENT_BYTES {
            return Err(io::Error::other("oversized spool intent"));
        }
        let bytes = std::fs::read(path)?;
        if bytes.len() as u64 > MAX_INTENT_BYTES {
            return Err(io::Error::other("oversized spool intent"));
        }
        let plain =
            aead::decrypt(&key, &bytes, AAD).map_err(|e| io::Error::other(e.to_string()))?;
        let mut intent: Intent = serde_json::from_slice(&plain)?;
        if intent.payload_format != 1 {
            return Err(io::Error::other(
                "legacy plaintext spool: recovery requires explicit migration",
            ));
        }
        let progress = path.with_extension("parts");
        if progress.exists() && intent.confirmed.is_none() {
            if std::fs::metadata(&progress)?.len() > 4 * 1024 * 1024 {
                return Err(io::Error::other("oversized part acknowledgement log"));
            }
            let records = std::fs::read(&progress)?;
            if records.len() > 4 * 1024 * 1024 {
                return Err(io::Error::other("oversized part acknowledgement log"));
            }
            let aad = progress_aad(&intent);
            let (complete_records, _) = records.as_chunks::<48>();
            for record in complete_records {
                let plain = aead::decrypt(&key, record, &aad)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let n = u64::from_le_bytes(
                    plain
                        .try_into()
                        .map_err(|_| io::Error::other("invalid part offset"))?,
                );
                if intent
                    .plan
                    .as_ref()
                    .is_none_or(|p| n >= p.wire_len().div_ceil(512 * 1024))
                {
                    return Err(io::Error::other("part acknowledgement beyond upload"));
                }
                intent.acknowledged.insert(n as usize);
            }
            OpenOptions::new()
                .write(true)
                .open(&progress)?
                .set_len((complete_records.len() * 48) as u64)?;
        }
        if intent.spool.parent() != path.parent() {
            return Err(io::Error::other(
                "spool intent escapes its private directory",
            ));
        }
        // A confirmed publication no longer needs its payload; index repair uses the header.
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .open(&intent.spool)
        {
            Ok(f) => f,
            Err(e) if intent.confirmed.is_some() && e.kind() == io::ErrorKind::NotFound => {
                File::open("/dev/null")?
            }
            Err(e) => return Err(e),
        };
        let io = std::sync::Arc::default();
        Ok(Self {
            hash_worker: None,
            file: SpoolFile::new(
                file,
                &key,
                intent.metadata.version_id,
                std::sync::Arc::clone(&io),
            ),
            intent,
            intent_path: path.to_owned(),
            key,
            segment_hash: blake3::Hasher::new(),
            segment_pos: 0,
            segment_checks: Vec::new(),
            hash: Sha256::new(&SHA256),
            manifest_hash: blake3::Hasher::new_keyed(manifest_key.as_bytes()),
            hashed_len: None,
            written: 0,
            io,
        })
    }
    /// Recovery may publish only a complete image synced with its immutable plan.
    pub fn verify_recoverable(&mut self, manifest_key: &SymmetricKey) -> io::Result<()> {
        if !self.intent.initialized {
            return Err(io::Error::other("initialization incomplete"));
        }
        if self.intent.plan.is_none() && self.intent.empty_create && self.len()? == 0 {
            // CREATE saved this initialized empty image before replying. Deferred
            // close owes its publication even if RELEASE never prepared a plan.
            return Ok(());
        }
        let plan = self.intent.plan.as_ref().ok_or_else(|| {
            io::Error::other("no synced stream plan: no durability point reached")
        })?;
        if self.intent.confirmed.is_some() {
            return Ok(());
        }
        let size = plan.metadata.size;
        let expected = plan.metadata.content_sha256.clone();
        if self.len()? != size {
            return Err(io::Error::other("prepared spool length mismatch"));
        }
        let (digest, manifest) = self.digests(manifest_key)?;
        if hex::encode(digest) != expected || manifest != self.intent.file_hash {
            return Err(io::Error::other("prepared spool digest mismatch"));
        }
        Ok(())
    }

    /// Move the complete pending-image family aside without copying payload bytes.
    pub fn quarantine(path: &Path, reason: &str) -> io::Result<PathBuf> {
        let root = path
            .parent()
            .ok_or_else(|| io::Error::other("intent has no directory"))?;
        let quarantine = root.join("quarantine");
        std::fs::create_dir_all(&quarantine)?;
        std::fs::set_permissions(&quarantine, std::fs::Permissions::from_mode(0o700))?;
        let bucket = quarantine.join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir(&bucket)?;
        std::fs::set_permissions(&bucket, std::fs::Permissions::from_mode(0o700))?;
        for extension in ["intent", "spool", "parts", "intent-tmp"] {
            let source = path.with_extension(extension);
            match std::fs::rename(&source, bucket.join(source.file_name().unwrap())) {
                Ok(()) => (),
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => return Err(e),
            }
        }
        let mut warning = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(bucket.join("reason.txt"))?;
        warning.write_all(reason.as_bytes())?;
        warning.sync_all()?;
        File::open(&bucket)?.sync_all()?;
        File::open(&quarantine)?.sync_all()?;
        File::open(root)?.sync_all()?;
        Ok(bucket)
    }

    pub fn save(&self) -> io::Result<()> {
        let plain = serde_json::to_vec(&self.intent)?;
        if plain.len() as u64 + 40 > MAX_INTENT_BYTES {
            return Err(io::Error::other("oversized spool intent"));
        }
        let wire =
            aead::encrypt(&self.key, &plain, AAD).map_err(|e| io::Error::other(e.to_string()))?;
        let temp = self.intent_path.with_extension("intent-tmp");
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp)?;
        f.write_all(&wire)?;
        self.io.record_intent(wire.len() as u64);
        f.sync_all()?;
        std::fs::rename(temp, &self.intent_path)?;
        File::open(
            self.intent_path
                .parent()
                .ok_or_else(|| io::Error::other("spool intent has no parent"))?,
        )?
        .sync_all()
    }
    /// Only a complete, durable seed may become a recoverable dirty image.
    pub fn finish_initialization(&mut self) -> io::Result<()> {
        self.file.sync_all()?;
        self.intent.initialized = true;
        self.save()
    }
    pub fn mark_empty_create(&mut self) -> io::Result<()> {
        self.intent.empty_create = true;
        self.save()
    }
    fn clear_empty_create(&mut self) -> io::Result<()> {
        if self.intent.empty_create {
            self.intent.empty_create = false;
            self.save()?;
        }
        Ok(())
    }
    pub fn len(&self) -> io::Result<u64> {
        self.file.len()
    }
    pub fn write(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        if self.intent.plan.is_some() {
            return Err(io::Error::other(
                "immutable upload is awaiting acknowledgement",
            ));
        }
        if !bytes.is_empty() {
            self.clear_empty_create()?;
        }
        self.file.write_all_at(bytes, offset)?;
        self.written += bytes.len() as u64;
        if self.hashed_len == Some(offset) {
            self.queue_hash(bytes)?;
            self.manifest_hash.update(bytes);
            self.update_segment_checks(bytes);
            self.hashed_len = Some(offset + bytes.len() as u64);
        } else {
            self.hashed_len = None;
        }
        Ok(())
    }
    pub fn resize(&mut self, len: u64) -> io::Result<()> {
        if self.intent.plan.is_some() {
            return Err(io::Error::other("immutable upload pending"));
        }
        self.clear_empty_create()?;
        self.file.set_len(len)?;
        self.hashed_len = None;
        Ok(())
    }
    pub fn read_range(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let n = self.len()?.saturating_sub(offset).min(len as u64) as usize;
        let mut bytes = vec![0; n];
        self.file.read_exact_at(&mut bytes, offset)?;
        Ok(bytes)
    }
    pub fn digests(&mut self, manifest_key: &SymmetricKey) -> io::Result<([u8; 32], [u8; 32])> {
        let len = self.len()?;
        if let Some(worker) = self.hash_worker.take() {
            drop(worker.sender);
            let result = worker
                .join
                .join()
                .map_err(|_| io::Error::other("spool hash worker panicked"))?;
            if self.hashed_len.is_some() {
                self.hash = result?;
            }
            // A truncate or random write invalidated this job's image. Its
            // old-length EOF (or old-data read error) is not an error in the
            // current image: recompute all digests from that image below.
        }
        if self.hashed_len != Some(len) {
            self.segment_hash = blake3::Hasher::new();
            self.segment_pos = 0;
            self.segment_checks.clear();
            self.hash = Sha256::new(&SHA256);
            self.manifest_hash = blake3::Hasher::new_keyed(manifest_key.as_bytes());
            let mut offset = 0;
            let mut buf = vec![0; 1024 * 1024];
            while offset < len {
                let n = (len - offset).min(buf.len() as u64) as usize;
                self.file.read_exact_at(&mut buf[..n], offset)?;
                self.hash.update(&buf[..n]);
                self.manifest_hash.update(&buf[..n]);
                self.update_segment_checks(&buf[..n]);
                offset += n as u64;
            }
            self.hashed_len = Some(len);
        }
        Ok((
            self.hash
                .clone()
                .finish()
                .as_ref()
                .try_into()
                .expect("SHA-256 is 32 bytes"),
            *self.manifest_hash.finalize().as_bytes(),
        ))
    }
    fn queue_hash(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.hash_worker.is_none() {
            let mut hash = self.hash.clone();
            let (sender, receiver) = std::sync::mpsc::sync_channel::<Vec<u8>>(8);
            let join = std::thread::spawn(move || {
                for bytes in &receiver {
                    let bytes = zeroize::Zeroizing::new(bytes);
                    hash.update(&bytes);
                }
                Ok(hash)
            });
            self.hash_worker = Some(HashWorker { sender, join });
        }
        // Hash bounded plaintext chunks, never concurrently reread a block while
        // another write replaces its nonce/ciphertext/tag.
        for chunk in bytes.chunks(1024 * 1024) {
            self.hash_worker
                .as_ref()
                .unwrap()
                .sender
                .send(chunk.to_vec())
                .map_err(|_| io::Error::other("spool hash worker stopped"))?;
        }
        Ok(())
    }
    fn update_segment_checks(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let n = bytes.len().min(1024 * 1024 - self.segment_pos);
            self.segment_hash.update(&bytes[..n]);
            self.segment_pos += n;
            bytes = &bytes[n..];
            if self.segment_pos == 1024 * 1024 {
                self.segment_checks
                    .push(*self.segment_hash.finalize().as_bytes());
                self.segment_hash = blake3::Hasher::new();
                self.segment_pos = 0;
            }
        }
    }
    pub fn segment_checks(&self) -> Vec<[u8; 32]> {
        let mut checks = self.segment_checks.clone();
        if self.segment_pos > 0 {
            checks.push(*self.segment_hash.finalize().as_bytes());
        }
        checks
    }
    pub fn restart_upload(&mut self) -> io::Result<()> {
        use rand::Rng;
        let progress = self.intent_path.with_extension("parts");
        match std::fs::remove_file(progress) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
        self.intent.acknowledged.clear();
        self.intent.upload_id = rand::thread_rng().gen();
        // The immutable version framing and SendMedia random_id remain unchanged.
        self.save()
    }
    pub fn confirm(&mut self, id: i64) -> io::Result<()> {
        self.sync_progress()?;
        self.intent.confirmed = Some(id);
        self.save()?;
        File::open(self.intent_path.parent().unwrap())?.sync_all()?;
        self.remove_payload()
    }
    fn remove_payload(&self) -> io::Result<()> {
        match std::fs::remove_file(&self.intent.spool) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
    pub fn sync_progress(&self) -> io::Result<()> {
        let path = self.intent_path.with_extension("parts");
        if path.exists() {
            File::open(path)?.sync_all()?;
        }
        Ok(())
    }
    pub fn ack(&mut self, n: usize) -> io::Result<()> {
        if !self.intent.acknowledged.insert(n) {
            return Ok(());
        }
        let aad = progress_aad(&self.intent);
        let record = aead::encrypt(&self.key, &(n as u64).to_le_bytes(), &aad)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(self.intent_path.with_extension("parts"))?;
        f.write_all(&record)?;
        self.io.record_intent(record.len() as u64);
        if self.intent.acknowledged.len().is_multiple_of(32) {
            f.sync_data()?;
        }
        Ok(())
    }
    pub fn cleanup(&self) -> io::Result<()> {
        self.remove_payload()?;
        let progress = self.intent_path.with_extension("parts");
        if progress.exists() {
            std::fs::remove_file(progress)?;
        }
        std::fs::remove_file(&self.intent_path)?;
        File::open(self.intent_path.parent().unwrap())?.sync_all()
    }
}
pub(crate) struct SpoolUpload<'a> {
    pub stream: SdoFileStream<SpoolFile>,
    pub spool: &'a mut WriteSpool,
}
impl Read for SpoolUpload<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.stream.read(out)
    }
}
impl UploadSource for SpoolUpload<'_> {
    fn size(&self) -> u64 {
        self.spool.intent.plan.as_ref().unwrap().wire_len()
    }
    fn upload_id(&self) -> i64 {
        self.spool.intent.upload_id
    }
    fn publication_id(&self) -> i64 {
        self.spool.intent.publication_id
    }
    fn acknowledged(&self, n: usize) -> bool {
        self.spool.intent.acknowledged.contains(&n)
    }
    fn acknowledge(&mut self, n: usize) -> io::Result<()> {
        self.spool.ack(n)
    }
    fn local_write_meter(
        &self,
    ) -> Option<std::sync::Arc<teagarden_telegram::transfer::LocalWriteStats>> {
        Some(self.spool.io.clone())
    }
}

fn progress_aad(intent: &Intent) -> Vec<u8> {
    let mut aad = b"teagarden.spool.part.v1".to_vec();
    aad.extend_from_slice(intent.metadata.version_id.as_bytes());
    aad.extend_from_slice(&intent.upload_id.to_le_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_spool_random_io_sparse_resize_and_authentication() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let id = uuid::Uuid::new_v4();
        let file = SpoolFile::new(
            temp.reopen().unwrap(),
            &SymmetricKey::from_bytes([1; 32]),
            id,
            Default::default(),
        );
        let marker = b"KNOWN_SPOOL_PLAINTEXT_MARKER";
        file.write_all_at(marker, 0).unwrap();
        let before = std::fs::read(temp.path()).unwrap();
        assert!(!before.windows(marker.len()).any(|w| w == marker));
        file.write_all_at(marker, 0).unwrap();
        assert_ne!(
            before,
            std::fs::read(temp.path()).unwrap(),
            "fresh nonce per rewrite"
        );
        file.write_all_at(b"cross-block", BLOCK - 5).unwrap();
        let mut read = vec![0; (BLOCK + 6) as usize];
        file.read_exact_at(&mut read, 0).unwrap();
        assert_eq!(&read[..marker.len()], marker);
        assert!(read[marker.len()..BLOCK as usize - 5]
            .iter()
            .all(|b| *b == 0));
        assert_eq!(&read[BLOCK as usize - 5..], b"cross-block");
        file.set_len(2).unwrap();
        file.set_len(BLOCK + 3).unwrap();
        let mut read = vec![0; (BLOCK + 3) as usize];
        file.read_exact_at(&mut read, 0).unwrap();
        assert_eq!(&read[..2], &marker[..2]);
        assert!(read[2..].iter().all(|b| *b == 0));
        let wrong = SpoolFile::new(
            temp.reopen().unwrap(),
            &SymmetricKey::from_bytes([2; 32]),
            id,
            Default::default(),
        );
        assert!(wrong.read_exact_at(&mut [0; 1], 0).is_err());
        temp.as_file().write_all_at(&[0xff; 24], 0).unwrap();
        assert!(file.read_exact_at(&mut [0; 1], 0).is_err());
    }

    #[test]
    fn sole_payload_spool_has_bounded_random_io_and_linear_disk_cost() {
        let root = tempfile::tempdir().unwrap();
        let key = SymmetricKey::from_bytes([1; 32]);
        let mk = SymmetricKey::from_bytes([2; 32]);
        let meta:SdoObjectMetadataV3=serde_json::from_value(serde_json::json!({"file_id":uuid::Uuid::new_v4(),"path":"bench","size":0,"mtime_ns":0,"mode":384,"version_id":uuid::Uuid::new_v4(),"author_device_id":uuid::Uuid::new_v4(),"kind":"file","key_generation":0,"clock_ms":1,"clock_counter":0,"saved_at_ns":1,"local_version":1,"deleted":false,"segment_size":1048576,"segment_count":0,"content_sha256":""})).unwrap();
        let mut spool = WriteSpool::create(root.path(), key.clone(), &mk, meta, 2, 1).unwrap();
        let bytes = vec![3; 128 * 1024];
        let start = std::time::Instant::now();
        for n in 0..800 {
            spool.write(n * bytes.len() as u64, &bytes).unwrap();
        }
        spool.file.sync_data().unwrap();
        let write_s = start.elapsed().as_secs_f64();
        let start = std::time::Instant::now();
        let (sha, blake) = spool.digests(&mk).unwrap();
        let digest_s = start.elapsed().as_secs_f64();
        assert_eq!(spool.len().unwrap(), 100 * 1024 * 1024);
        assert_eq!(spool.written, 100 * 1024 * 1024);
        let mut metadata = spool.intent.metadata.clone();
        metadata.size = spool.len().unwrap();
        let mut plan = SdoStreamPlan::prepare(
            uuid::Uuid::from_bytes([4; 16]),
            0,
            &key,
            metadata,
            sha,
            None,
        )
        .unwrap();
        plan.spool_segment_hashes = spool.segment_checks();
        let mut stream = plan
            .reader(spool.file.try_clone().unwrap(), key.clone(), None)
            .unwrap();
        let start = std::time::Instant::now();
        let n = io::copy(&mut stream, &mut io::sink()).unwrap();
        let encode_s = start.elapsed().as_secs_f64();
        assert!(n > spool.len().unwrap());
        eprintln!("SPOOL_STAGE_BENCH write_s={write_s:.6} digest_s={digest_s:.6} encode_s={encode_s:.6} written={} write_mib_s={:.3} encode_mib_s={:.3}",spool.written,100.0/write_s,100.0/encode_s);
        spool.write(10, b"alter").unwrap();
        let (changed, _) = spool.digests(&mk).unwrap();
        assert_ne!(changed, sha);
        assert_ne!(spool.digests(&mk).unwrap().1, blake);
        spool.resize(11).unwrap();
        assert_eq!(spool.read_range(9, 100).unwrap(), vec![3, b'a']);
        spool.cleanup().unwrap();
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}
