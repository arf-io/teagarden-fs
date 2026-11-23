/// Authenticated encryption (XChaCha20-Poly1305) over blocks and metadata.
pub mod aead;
/// BLAKE3 hashing: unkeyed content addressing and keyed integrity MACs.
pub mod blake3;
/// Key derivation: Argon2id root derivation and HKDF key hierarchy.
pub mod kdf;
/// Symmetric key types and the derived key hierarchy.
pub mod keys;
/// ML-KEM-768 post-quantum key encapsulation for key sharing.
pub mod mlkem;
