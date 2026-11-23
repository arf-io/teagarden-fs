use sha2::{Digest, Sha256};

use crate::crypto::{aead, keys::SymmetricKey};
use crate::error::{CoreError, Result};

const SRB2_MAGIC: &[u8; 4] = b"SRB2";
const SRB2_VERSION: u8 = 2;

/// Header: magic(4) + version(1) + epoch(4) + flags(1) + plaintext_len(4) + ciphertext_sha256(32) = 46 bytes
const HEADER_SIZE: usize = 46;

const FLAG_COMPRESSED: u8 = 0x01;

/// Compute SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Encode data into SRB2 block format.
///
/// Block layout:
/// ```text
/// SRB2 | version(1) | epoch(4) | flags(1) | plaintext_len(4) | ciphertext_sha256(32)
/// | encrypted( SHA-256(plaintext)(32) | plaintext )
/// ```
///
/// The inner hash (SHA-256 of plaintext) is encrypted together with the plaintext.
/// The outer hash (SHA-256 of the encrypted payload) lives in the unencrypted header —
/// it lets the receiver verify transit integrity before spending the decryption cost,
/// and can be used as a content-addressed deduplication key.
pub fn encode(
    key: &SymmetricKey,
    epoch: u32,
    plaintext: &[u8],
    compressed: bool,
    aad: &[u8],
) -> Result<Vec<u8>> {
    // core-L10: the header's plaintext_len is a u32. `as u32` silently truncated
    // a >4 GiB plaintext into a block that can never decode; refuse it before
    // touching the data.
    let plaintext_len = u32::try_from(plaintext.len()).map_err(|_| {
        CoreError::BlockFormat(format!(
            "plaintext too large for one block: {} bytes (max {})",
            plaintext.len(),
            u32::MAX
        ))
    })?;
    let flags = if compressed { FLAG_COMPRESSED } else { 0 };

    // Compute inner hash, prepend to plaintext.
    let inner_hash = sha256(plaintext);
    let mut extended = Vec::with_capacity(32 + plaintext.len());
    extended.extend_from_slice(&inner_hash);
    extended.extend_from_slice(plaintext);

    // Build a partial header (without ciphertext_sha256 — filled in below).
    let mut partial_header = Vec::with_capacity(HEADER_SIZE - 32);
    partial_header.extend_from_slice(SRB2_MAGIC);
    partial_header.push(SRB2_VERSION);
    partial_header.extend_from_slice(&epoch.to_le_bytes());
    partial_header.push(flags);
    partial_header.extend_from_slice(&plaintext_len.to_le_bytes());

    // AAD binds the metadata fields to the ciphertext.
    let mut full_aad = Vec::with_capacity(aad.len() + partial_header.len() - 4);
    full_aad.extend_from_slice(aad);
    full_aad.extend_from_slice(&partial_header[4..]); // exclude magic

    let encrypted = aead::encrypt(key, &extended, &full_aad)?;

    // Outer hash: SHA-256 of the encrypted payload.
    let outer_hash = sha256(&encrypted);

    let mut block = Vec::with_capacity(HEADER_SIZE + encrypted.len());
    block.extend_from_slice(&partial_header);
    block.extend_from_slice(&outer_hash);
    block.extend_from_slice(&encrypted);
    Ok(block)
}

/// Decoded SRB2 block with both hash fields verified.
#[derive(Debug)]
pub struct DecodedBlock {
    /// Key epoch the block was sealed under.
    pub epoch: u32,
    /// Whether the plaintext was compressed before encryption.
    pub compressed: bool,
    /// Original plaintext length (does not include the inner SHA-256 prefix).
    pub plaintext_len: u32,
    /// SHA-256 of the plaintext — verified during decode.
    pub plaintext_sha256: [u8; 32],
    /// SHA-256 of the encrypted payload — verified during decode.
    pub ciphertext_sha256: [u8; 32],
    /// Decrypted plaintext bytes.
    pub plaintext: Vec<u8>,
}

impl DecodedBlock {
    /// Encryption overhead in bytes (block size − plaintext size).
    pub fn overhead_bytes(&self) -> usize {
        HEADER_SIZE + aead::NONCE_SIZE + 32 + aead::TAG_SIZE
    }
}

/// Decode an SRB2 block, verifying both the outer ciphertext hash and the inner
/// plaintext hash.
pub fn decode(key: &SymmetricKey, block: &[u8], aad: &[u8]) -> Result<DecodedBlock> {
    let min_len = HEADER_SIZE + aead::NONCE_SIZE + 32 + aead::TAG_SIZE;
    if block.len() < min_len {
        return Err(CoreError::BlockFormat("block too short".into()));
    }

    if &block[..4] != SRB2_MAGIC {
        return Err(CoreError::BlockFormat("invalid magic".into()));
    }

    let version = block[4];
    if version != SRB2_VERSION {
        return Err(CoreError::BlockFormat(format!(
            "unsupported SRB2 version: {version}"
        )));
    }

    let epoch = u32::from_le_bytes(block[5..9].try_into().unwrap());
    let flags = block[9];
    let compressed = flags & FLAG_COMPRESSED != 0;
    let plaintext_len = u32::from_le_bytes(block[10..14].try_into().unwrap());

    let mut ciphertext_sha256 = [0u8; 32];
    ciphertext_sha256.copy_from_slice(&block[14..46]);

    let encrypted = &block[HEADER_SIZE..];

    // Verify outer hash before attempting decryption.
    let actual_outer = sha256(encrypted);
    if actual_outer != ciphertext_sha256 {
        return Err(CoreError::BlockFormat(
            "ciphertext SHA-256 mismatch — block corrupted in transit".into(),
        ));
    }

    // Reconstruct AAD.
    let mut full_aad = Vec::with_capacity(aad.len() + HEADER_SIZE - 4 - 32);
    full_aad.extend_from_slice(aad);
    full_aad.extend_from_slice(&block[4..14]); // version + epoch + flags + plaintext_len

    let extended = aead::decrypt(key, encrypted, &full_aad)?;

    if extended.len() < 32 {
        return Err(CoreError::BlockFormat("decrypted payload too short".into()));
    }

    let mut plaintext_sha256 = [0u8; 32];
    plaintext_sha256.copy_from_slice(&extended[..32]);
    let plaintext = extended[32..].to_vec();

    if plaintext.len() != plaintext_len as usize {
        return Err(CoreError::BlockFormat(format!(
            "plaintext length mismatch: header says {plaintext_len}, got {}",
            plaintext.len()
        )));
    }

    // Verify inner hash after decryption.
    let actual_inner = sha256(&plaintext);
    if actual_inner != plaintext_sha256 {
        return Err(CoreError::BlockFormat(
            "plaintext SHA-256 mismatch — decryption integrity failure".into(),
        ));
    }

    Ok(DecodedBlock {
        epoch,
        compressed,
        plaintext_len,
        plaintext_sha256,
        ciphertext_sha256,
        plaintext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SymmetricKey {
        SymmetricKey::from_bytes([0x42; 32])
    }

    #[test]
    fn encode_decode_roundtrip() {
        let key = test_key();
        let data = b"hello srb2 world";
        let aad = b"inode:1:offset:0";

        let block = encode(&key, 0, data, false, aad).unwrap();
        let decoded = decode(&key, &block, aad).unwrap();

        assert_eq!(decoded.plaintext, data);
        assert_eq!(decoded.epoch, 0);
        assert!(!decoded.compressed);
        assert_eq!(decoded.plaintext_len, data.len() as u32);
        assert_eq!(decoded.plaintext_sha256, sha256(data));
    }

    #[test]
    fn compressed_flag() {
        let key = test_key();
        let block = encode(&key, 7, b"data", true, b"").unwrap();
        let decoded = decode(&key, &block, b"").unwrap();
        assert!(decoded.compressed);
        assert_eq!(decoded.epoch, 7);
    }

    #[test]
    fn wrong_key_fails() {
        let k1 = test_key();
        let k2 = SymmetricKey::from_bytes([0x99; 32]);
        let block = encode(&k1, 0, b"secret", false, b"").unwrap();
        assert!(decode(&k2, &block, b"").is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = test_key();
        let block = encode(&key, 0, b"data", false, b"correct").unwrap();
        assert!(decode(&key, &block, b"wrong").is_err());
    }

    #[test]
    fn tampered_ciphertext_detected_by_outer_hash() {
        let key = test_key();
        let mut block = encode(&key, 0, b"data", false, b"").unwrap();
        // Flip a byte in the encrypted payload (after the header).
        block[HEADER_SIZE + 5] ^= 0xFF;
        let err = decode(&key, &block, b"").unwrap_err();
        assert!(err.to_string().contains("ciphertext SHA-256 mismatch"));
    }

    #[test]
    fn tampered_header_fails_aad_check() {
        let key = test_key();
        let mut block = encode(&key, 0, b"data", false, b"").unwrap();
        // Corrupt the epoch field in the header.
        block[5] ^= 0xFF;
        assert!(decode(&key, &block, b"").is_err());
    }

    #[test]
    fn block_size_overhead() {
        let key = test_key();
        let data = b"hello";
        let block = encode(&key, 0, data, false, b"").unwrap();
        // header(46) + nonce(24) + sha256(32) + plaintext(5) + tag(16)
        assert_eq!(
            block.len(),
            HEADER_SIZE + aead::NONCE_SIZE + 32 + data.len() + aead::TAG_SIZE
        );
    }

    #[test]
    fn overhead_bytes_matches_block_layout() {
        let key = test_key();
        let data = vec![0u8; 1024];
        let block = encode(&key, 0, &data, false, b"").unwrap();
        let decoded = decode(&key, &block, b"").unwrap();
        assert_eq!(block.len() - data.len(), decoded.overhead_bytes());
    }

    #[test]
    fn ciphertext_sha256_stored_in_decoded() {
        let key = test_key();
        let data = b"test data";
        let block = encode(&key, 0, data, false, b"").unwrap();
        let decoded = decode(&key, &block, b"").unwrap();
        // Verify the stored outer hash matches what we compute from the block bytes.
        let expected_outer = sha256(&block[HEADER_SIZE..]);
        assert_eq!(decoded.ciphertext_sha256, expected_outer);
    }

    #[test]
    fn plaintext_sha256_verifies_integrity() {
        let key = test_key();
        let data = b"integrity check";
        let block = encode(&key, 0, data, false, b"").unwrap();
        let decoded = decode(&key, &block, b"").unwrap();
        assert_eq!(decoded.plaintext_sha256, sha256(data));
    }

    #[test]
    fn truncated_block_fails() {
        let key = test_key();
        assert!(decode(&key, &[0u8; 20], b"").is_err());
    }

    #[test]
    fn invalid_magic_fails() {
        let key = test_key();
        let mut block = vec![0u8; 200];
        block[..4].copy_from_slice(b"XXXX");
        assert!(decode(&key, &block, b"").is_err());
    }

    #[test]
    fn empty_plaintext() {
        let key = test_key();
        let block = encode(&key, 0, b"", false, b"").unwrap();
        let decoded = decode(&key, &block, b"").unwrap();
        assert!(decoded.plaintext.is_empty());
        assert_eq!(decoded.plaintext_sha256, sha256(b""));
    }

    #[test]
    fn large_payload() {
        let key = test_key();
        let data = vec![0xAB; 512 * 1024]; // 512 KiB — typical TeaGarden block
        let block = encode(&key, 3, &data, false, b"volume-id").unwrap();
        let decoded = decode(&key, &block, b"volume-id").unwrap();
        assert_eq!(decoded.plaintext, data);
        assert_eq!(decoded.plaintext_sha256, sha256(&data));
    }

    #[test]
    fn sha256_deterministic() {
        let h1 = sha256(b"same input");
        let h2 = sha256(b"same input");
        assert_eq!(h1, h2);
    }
}

#[cfg(all(test, unix, target_pointer_width = "64"))]
mod oversize_tests {
    use super::*;
    use crate::block::oversize;

    /// core-L10: see `srb1::oversize_tests` — same u32 header field.
    #[test]
    fn encode_refuses_plaintext_longer_than_u32() {
        let buf = oversize::Mapping::new();
        let key = SymmetricKey::from_bytes([0x42; 32]);
        let err = encode(&key, 0, buf.as_slice(), false, b"")
            .expect_err("a >4 GiB plaintext must be refused at encode");
        assert!(
            format!("{err}").contains("too large"),
            "unexpected error: {err}"
        );
    }
}
