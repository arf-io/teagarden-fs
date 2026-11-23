//! Streaming TGFV3 framing with a bounded 16 MiB content window.

use super::*;
use chacha20poly1305::aead::AeadInPlace;
use rand::RngCore;
use ring::digest::{Context as Sha256, SHA256};
use std::io::{self, Read};

/// Small, serializable recipe for an immutable upload; contains no file payload.
#[derive(Clone, Serialize, Deserialize)]
pub struct SdoStreamPlan {
    /// Exact authenticated prefix and metadata, reused across retries.
    pub header_wire: Vec<u8>,
    /// Signed logical record captured before the first part is sent.
    pub metadata: SdoObjectMetadataV3,
    /// Credential bootstrap, when this object is independently decryptable.
    pub bootstrap: Option<Vec<u8>>,
    /// Persisted wrap nonces keep the streamed trailer identical after a crash.
    pub wrap_nonces: [[u8; 24]; 2],
    /// Fixed JSON allocation; trailing whitespace is authenticated by the footer MAC.
    pub footer_json_bytes: usize,
    /// Local spool checks, never serialized into the Telegram document.
    #[serde(default)]
    pub spool_segment_hashes: Vec<[u8; 32]>,
}

impl SdoStreamPlan {
    /// Prepare the metadata using a digest calculated from the local write spool.
    pub fn prepare(
        volume: Uuid,
        generation: u64,
        key: &SymmetricKey,
        mut metadata: SdoObjectMetadataV3,
        digest: [u8; 32],
        signer: Option<&SigningKey>,
    ) -> Result<Self> {
        if metadata.size > MAX_SDO_FILE_BYTES_PREMIUM || metadata.key_generation != generation {
            return Err(CoreError::Manifest(
                "invalid streaming object size/generation".into(),
            ));
        }
        metadata.segment_size = SDO_SEGMENT_SIZE;
        metadata.segment_count = if metadata.kind == SdoKind::File && !metadata.deleted {
            metadata.size.div_ceil(u64::from(SDO_SEGMENT_SIZE)) as u32
        } else {
            0
        };
        metadata.content_sha256 = hex::encode(digest);
        if let Some(signer) = signer {
            metadata.sign_authority_digest(volume, signer, digest)?;
        }
        metadata.validate()?;
        metadata.verify_authority(volume)?;
        let plain =
            serde_json::to_vec(&metadata).map_err(|e| CoreError::Serialization(e.to_string()))?;
        let length = plain
            .len()
            .checked_add(40)
            .ok_or_else(|| CoreError::Manifest("header overflow".into()))?;
        if length as u64 + 34 > MAX_TGFV3_HEADER_BYTES {
            return Err(CoreError::Manifest("streaming header too large".into()));
        }
        let mut header_wire = Vec::with_capacity(34 + length);
        header_wire.extend_from_slice(b"TGFV");
        header_wire.extend_from_slice(&3u16.to_le_bytes());
        header_wire.extend_from_slice(volume.as_bytes());
        header_wire.extend_from_slice(&generation.to_le_bytes());
        header_wire.extend_from_slice(&(length as u32).to_le_bytes());
        let mut aad = b"teagarden.sdo.file.v3".to_vec();
        aad.extend_from_slice(&header_wire);
        header_wire.extend_from_slice(&aead::encrypt(key, &plain, &aad)?);
        Ok(Self {
            header_wire,
            metadata,
            bootstrap: None,
            wrap_nonces: [[0; 24]; 2],
            footer_json_bytes: 0,
            spool_segment_hashes: Vec::new(),
        })
    }

    /// Add a bounded credential trailer without reading, decoding or copying the body.
    pub fn with_envelope(
        mut self,
        bootstrap: &[u8],
        hierarchy: &crate::crypto::keys::KeyHierarchy,
    ) -> Result<Self> {
        let header = HeaderDocument::decode(bootstrap, &hierarchy.integrity)?;
        SdoFileObjectV3::decode_header(
            &self.header_wire,
            header.volume_id,
            self.metadata.key_generation,
            &hierarchy.meta,
        )?;
        if header.key_generation.unwrap_or(0) != self.metadata.key_generation {
            return Err(CoreError::Manifest(
                "streaming envelope generation mismatch".into(),
            ));
        }
        let largest = ObjectEnvelope {
            header_wire: bootstrap.to_vec(),
            object_sha256: "f".repeat(64),
            password_wrapped_key: vec![255; 72],
            recovery_wrapped_key: vec![255; 72],
        };
        self.footer_json_bytes = serde_json::to_vec(&largest)
            .map_err(|e| CoreError::Serialization(e.to_string()))?
            .len();
        if self.footer_json_bytes > MAX_HEADER_SIZE {
            return Err(CoreError::Manifest("streaming envelope too large".into()));
        }
        self.bootstrap = Some(bootstrap.to_vec());
        for nonce in &mut self.wrap_nonces {
            rand::rngs::OsRng.fill_bytes(nonce);
        }
        Ok(self)
    }

    /// Exact upload size, known before the first SaveFilePart request.
    pub fn wire_len(&self) -> u64 {
        self.body_len()
            + if self.bootstrap.is_some() {
                self.footer_json_bytes as u64 + 40
            } else {
                0
            }
    }

    fn body_len(&self) -> u64 {
        self.header_wire.len() as u64
            + self.metadata.size
            + u64::from(self.metadata.segment_count) * 16
    }

    /// Create a bounded reader. Reopening the same spool and plan yields identical bytes.
    pub fn reader<R: Read>(
        self,
        reader: R,
        key: SymmetricKey,
        hierarchy: Option<crate::crypto::keys::KeyHierarchy>,
    ) -> Result<SdoFileStream<R>> {
        let volume = Uuid::from_slice(
            self.header_wire
                .get(6..22)
                .ok_or_else(|| CoreError::Manifest("truncated stream header".into()))?,
        )
        .map_err(|e| CoreError::Manifest(e.to_string()))?;
        let decoded = SdoFileObjectV3::decode_header(
            &self.header_wire,
            volume,
            self.metadata.key_generation,
            &key,
        )?;
        if decoded.metadata != self.metadata {
            return Err(CoreError::Manifest(
                "stream intent metadata mismatch".into(),
            ));
        }
        if self.bootstrap.is_some() && hierarchy.is_none() {
            return Err(CoreError::Manifest(
                "stream envelope keys unavailable".into(),
            ));
        }
        if !self.spool_segment_hashes.is_empty()
            && self.spool_segment_hashes.len() != self.metadata.segment_count as usize
        {
            return Err(CoreError::Manifest(
                "invalid local spool segment checks".into(),
            ));
        }
        let content_key = sdo_v3_content_key(&key, self.metadata.version_id)?;
        let buffer = self.header_wire.clone();
        Ok(SdoFileStream {
            plan: self,
            reader,
            meta_key: key,
            content_key,
            hierarchy,
            buffer,
            position: 0,
            segment: 0,
            phase: 0,
            ready: std::collections::VecDeque::new(),
            plain_hash: Sha256::new(&SHA256),
            wire_hash: Sha256::new(&SHA256),
        })
    }
}

/// Byte reader for one immutable TGFV object; never owns the complete plaintext or wire.
pub struct SdoFileStream<R> {
    plan: SdoStreamPlan,
    reader: R,
    meta_key: SymmetricKey,
    content_key: SymmetricKey,
    hierarchy: Option<crate::crypto::keys::KeyHierarchy>,
    buffer: Vec<u8>,
    position: usize,
    segment: u32,
    phase: u8,
    ready: std::collections::VecDeque<Vec<u8>>,
    plain_hash: Sha256,
    wire_hash: Sha256,
}

impl<R: Read> SdoFileStream<R> {
    fn refill(&mut self) -> io::Result<bool> {
        if self.segment < self.plan.metadata.segment_count {
            if self.ready.is_empty() {
                // Parallel local segment cryptography, never parallel network
                // connections. A 16 MiB window bounds all plaintext/ciphertext.
                let count = (self.plan.metadata.segment_count - self.segment).min(16);
                let mut buffers = Vec::with_capacity(count as usize);
                for part in self.segment..self.segment + count {
                    let n = (self.plan.metadata.size
                        - u64::from(part) * u64::from(SDO_SEGMENT_SIZE))
                    .min(u64::from(SDO_SEGMENT_SIZE)) as usize;
                    let mut bytes = Vec::with_capacity(n + 16);
                    bytes.resize(n, 0);
                    self.reader.read_exact(&mut bytes)?;
                    if self.plan.spool_segment_hashes.is_empty() {
                        self.plain_hash.update(&bytes);
                    }
                    buffers.push(bytes);
                }
                let content_key = &self.content_key;
                let metadata = &self.plan.metadata;
                let first = self.segment;
                let checks = &self.plan.spool_segment_hashes;
                std::thread::scope(|scope| -> io::Result<()> {
                    let workers = std::thread::available_parallelism()
                        .map_or(1, usize::from)
                        .min(buffers.len());
                    let chunk = buffers.len().div_ceil(workers);
                    let tasks: Vec<_> = buffers
                        .chunks_mut(chunk)
                        .enumerate()
                        .map(|(group, items)| {
                            scope.spawn(move || -> io::Result<()> {
                                for (i, bytes) in items.iter_mut().enumerate() {
                                    let part = first + (group * chunk + i) as u32;
                                    if !checks.is_empty()
                                        && checks.get(part as usize)
                                            != Some(&crate::crypto::blake3::hash(bytes))
                                    {
                                        return Err(io::Error::other(
                                            "local spool segment changed before upload",
                                        ));
                                    }
                                    let nonce = sdo_v3_segment_nonce(
                                        content_key,
                                        metadata.version_id,
                                        part,
                                    );
                                    let mut aad = b"teagarden.sdo.segment.v3".to_vec();
                                    aad.extend_from_slice(metadata.version_id.as_bytes());
                                    aad.extend_from_slice(&part.to_le_bytes());
                                    aad.extend_from_slice(&metadata.segment_count.to_le_bytes());
                                    aad.push(u8::from(part + 1 == metadata.segment_count));
                                    let tag = XChaCha20Poly1305::new(content_key.as_bytes().into())
                                        .encrypt_in_place_detached(
                                            XNonce::from_slice(&nonce),
                                            &aad,
                                            bytes,
                                        )
                                        .map_err(|e| io::Error::other(e.to_string()))?;
                                    bytes.extend_from_slice(&tag);
                                }
                                Ok(())
                            })
                        })
                        .collect();
                    for task in tasks {
                        task.join().map_err(|_| {
                            io::Error::other("segment encryption worker panicked")
                        })??;
                    }
                    Ok(())
                })?;
                self.ready = buffers.into();
            }
            self.buffer = self
                .ready
                .pop_front()
                .ok_or_else(|| io::Error::other("empty segment window"))?;
            self.segment += 1;
            self.position = 0;
            self.phase = 1;
            return Ok(true);
        }
        if self.phase < 2 {
            let digest = hex::encode(self.plain_hash.clone().finish().as_ref());
            if self.plan.spool_segment_hashes.is_empty()
                && digest != self.plan.metadata.content_sha256
            {
                return Err(io::Error::other(
                    "local spool hash changed before publication",
                ));
            }
            let mut extra = [0; 1];
            if self.reader.read(&mut extra)? != 0 {
                return Err(io::Error::other("local spool grew before publication"));
            }
            self.buffer = self.footer().map_err(|e| io::Error::other(e.to_string()))?;
            self.position = 0;
            self.phase = 2;
            return Ok(!self.buffer.is_empty());
        }
        Ok(false)
    }

    fn footer(&self) -> Result<Vec<u8>> {
        let Some(bootstrap) = &self.plan.bootstrap else {
            return Ok(Vec::new());
        };
        let hierarchy = self
            .hierarchy
            .as_ref()
            .ok_or_else(|| CoreError::Manifest("envelope keys missing".into()))?;
        let mut envelope = ObjectEnvelope {
            header_wire: bootstrap.clone(),
            object_sha256: hex::encode(self.wire_hash.clone().finish().as_ref()),
            password_wrapped_key: Vec::new(),
            recovery_wrapped_key: Vec::new(),
        };
        let aad = envelope.aad()?;
        let password_key = crate::crypto::kdf::hkdf_derive(
            &hierarchy.root,
            b"teagarden.sdo.envelope.password.v1",
        )?;
        let recovery_key = crate::crypto::kdf::hkdf_derive(
            &hierarchy.root,
            b"teagarden.sdo.envelope.recovery.v1",
        )?;
        let wrap = |key: &SymmetricKey, nonce: &[u8; 24]| -> Result<Vec<u8>> {
            let mut result = nonce.to_vec();
            let cipher = XChaCha20Poly1305::new(key.as_bytes().into())
                .encrypt(
                    XNonce::from_slice(nonce),
                    chacha20poly1305::aead::Payload {
                        msg: hierarchy.meta.as_bytes(),
                        aad: &aad,
                    },
                )
                .map_err(|e| CoreError::Encryption(e.to_string()))?;
            result.extend_from_slice(&cipher);
            Ok(result)
        };
        envelope.password_wrapped_key = wrap(&password_key, &self.plan.wrap_nonces[0])?;
        envelope.recovery_wrapped_key = wrap(&recovery_key, &self.plan.wrap_nonces[1])?;
        let mut json =
            serde_json::to_vec(&envelope).map_err(|e| CoreError::Serialization(e.to_string()))?;
        if json.len() > self.plan.footer_json_bytes {
            return Err(CoreError::Manifest("stream footer size overflow".into()));
        }
        json.resize(self.plan.footer_json_bytes, b' ');
        let mut input = b"teagarden.sdo.envelope.framing.v1".to_vec();
        input.extend_from_slice(&json);
        input.extend_from_slice(&self.plan.body_len().to_le_bytes());
        let mac = blake3::keyed_hash(&self.meta_key, &input);
        let length = json.len() as u32;
        json.extend_from_slice(&mac);
        json.extend_from_slice(&length.to_le_bytes());
        json.extend_from_slice(b"TGFE");
        Ok(json)
    }
}

impl<R: Read> Read for SdoFileStream<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < out.len() {
            if self.position == self.buffer.len() && !self.refill()? {
                break;
            }
            let n = (out.len() - written).min(self.buffer.len() - self.position);
            out[written..written + n]
                .copy_from_slice(&self.buffer[self.position..self.position + n]);
            if self.phase < 2 && self.plan.bootstrap.is_some() {
                self.wire_hash.update(&out[written..written + n]);
            }
            self.position += n;
            written += n;
        }
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    fn metadata(n: usize) -> SdoObjectMetadataV3 {
        serde_json::from_value(
            serde_json::json!({"file_id":Uuid::from_bytes([1;16]),"path":"file",
            "size":n,"mtime_ns":0,"mode":384,"version_id":Uuid::from_bytes([2;16]),
            "author_device_id":Uuid::from_bytes([3;16]),"kind":SdoKind::File,"key_generation":0,
            "clock_ms":1,"clock_counter":0,"saved_at_ns":1,"local_version":1,"deleted":false,
            "segment_size":SDO_SEGMENT_SIZE,"segment_count":0,"content_sha256":""}),
        )
        .unwrap()
    }
    #[test]
    fn streamed_wire_is_bounded_replayable_and_accepted_by_existing_decoder() {
        let data = vec![0x43; 2 * SDO_SEGMENT_SIZE as usize + 19];
        let key = SymmetricKey::from_bytes([9; 32]);
        let volume = Uuid::from_bytes([4; 16]);
        let signer = SigningKey::from_bytes(&[5; 32]);
        let plan = SdoStreamPlan::prepare(
            volume,
            0,
            &key,
            metadata(data.len()),
            crate::block::srb2::sha256(&data),
            Some(&signer),
        )
        .unwrap();
        let mut wire = Vec::new();
        plan.clone()
            .reader(Cursor::new(&data), key.clone(), None)
            .unwrap()
            .read_to_end(&mut wire)
            .unwrap();
        assert_eq!(wire.len() as u64, plan.wire_len());
        let decoded = SdoFileObjectV3::decode(&wire, volume, 0, &key).unwrap();
        assert_eq!(decoded.content, data);
        let mut replay = Vec::new();
        let mut reader = plan.reader(Cursor::new(&data), key, None).unwrap();
        reader.read_to_end(&mut replay).unwrap();
        assert_eq!(wire, replay);
        assert!(reader.buffer.capacity() <= 2 * SDO_SEGMENT_SIZE as usize);
    }
    #[test]
    fn streamed_credential_envelope_is_replayable_and_opens_with_both_root_credentials() {
        let root = SymmetricKey::from_bytes([8; 32]);
        let salt = [7; 32];
        let hierarchy = crate::crypto::kdf::derive_hierarchy_v1(root, &salt, -100, 42).unwrap();
        let mut header = HeaderDocument::test_fixture();
        header.group_id = -100;
        header.topic_id = 42;
        header.salt = hex::encode(salt);
        let bootstrap = header.encode(&hierarchy.integrity).unwrap();
        let data = vec![6; 2 * SDO_SEGMENT_SIZE as usize + 3];
        let plan = SdoStreamPlan::prepare(
            header.volume_id,
            0,
            &hierarchy.meta,
            metadata(data.len()),
            crate::block::srb2::sha256(&data),
            None,
        )
        .unwrap()
        .with_envelope(&bootstrap, &hierarchy)
        .unwrap();
        let mut bytes = Vec::new();
        plan.clone()
            .reader(
                Cursor::new(&data),
                hierarchy.meta.clone(),
                Some(hierarchy.clone()),
            )
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes.len() as u64, plan.wire_len());
        let envelope = ObjectEnvelope::parse(&bytes).unwrap().unwrap();
        for recovery in [false, true] {
            let key = envelope.open(&bytes, &hierarchy.root, recovery).unwrap();
            assert_eq!(key.as_bytes(), hierarchy.meta.as_bytes());
        }
        assert_eq!(
            SdoFileObjectV3::decode(&bytes, header.volume_id, 0, &hierarchy.meta)
                .unwrap()
                .content,
            data
        );
        let mut replay = Vec::new();
        plan.reader(Cursor::new(&data), hierarchy.meta.clone(), Some(hierarchy))
            .unwrap()
            .read_to_end(&mut replay)
            .unwrap();
        assert_eq!(replay, bytes);
    }

    #[test]
    fn streamed_wire_refuses_changed_or_truncated_local_bytes() {
        let key = SymmetricKey::from_bytes([9; 32]);
        let data = vec![7; 2 * SDO_SEGMENT_SIZE as usize];
        let mut plan = SdoStreamPlan::prepare(
            Uuid::from_bytes([4; 16]),
            0,
            &key,
            metadata(data.len()),
            crate::block::srb2::sha256(&data),
            None,
        )
        .unwrap();
        plan.spool_segment_hashes = data
            .chunks(SDO_SEGMENT_SIZE as usize)
            .map(crate::crypto::blake3::hash)
            .collect();
        assert!(plan
            .clone()
            .reader(Cursor::new(&data[..10]), key.clone(), None)
            .unwrap()
            .read_to_end(&mut Vec::new())
            .is_err());
        let mut changed = data.clone();
        changed[1] ^= 1;
        assert!(plan
            .reader(Cursor::new(changed), key, None)
            .unwrap()
            .read_to_end(&mut Vec::new())
            .is_err());
    }
}
