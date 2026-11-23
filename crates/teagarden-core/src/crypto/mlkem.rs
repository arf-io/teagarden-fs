use crate::crypto::keys::SymmetricKey;
use crate::error::{CoreError, Result};

use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem, KeyExport},
    ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey},
    MlKem768, Seed,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-KEM-768 encapsulation key (public key), serialized.
#[derive(Debug, Clone)]
pub struct MlKemEncapsulationKey(pub Vec<u8>);

/// ML-KEM-768 decapsulation key (secret key), serialized.
/// Zeroized on drop to prevent key material from lingering in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlKemDecapsulationKey(pub Vec<u8>);

impl std::fmt::Debug for MlKemDecapsulationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MlKemDecapsulationKey")
            .field(&"[REDACTED]")
            .finish()
    }
}

/// ML-KEM-768 ciphertext (encapsulated shared secret), serialized.
#[derive(Debug, Clone)]
pub struct MlKemCiphertext(pub Vec<u8>);

/// Generate an ML-KEM-768 keypair.
pub fn generate_keypair() -> Result<(MlKemDecapsulationKey, MlKemEncapsulationKey)> {
    let (dk, ek) = MlKem768::generate_keypair();

    let mut dk_seed = dk.to_bytes();
    let dk_bytes = dk_seed.to_vec();
    let ek_bytes = ek.to_bytes().to_vec();
    dk_seed.zeroize();

    Ok((
        MlKemDecapsulationKey(dk_bytes),
        MlKemEncapsulationKey(ek_bytes),
    ))
}

/// Encapsulate: produce a shared secret and ciphertext from a public key.
pub fn encapsulate(ek: &MlKemEncapsulationKey) -> Result<(SymmetricKey, MlKemCiphertext)> {
    let ek_encoded =
        ek.0.as_slice()
            .try_into()
            .map_err(|_| CoreError::InvalidKey("invalid encapsulation key length".into()))?;

    let ek_parsed = EncapsulationKey::new(ek_encoded)
        .map_err(|_| CoreError::InvalidKey("invalid encapsulation key encoding".into()))?;

    let (ct, mut ss) = ek_parsed.encapsulate();

    let ct_bytes = ct.to_vec();
    let mut ss_bytes = [0u8; 32];
    ss_bytes.copy_from_slice(ss.as_slice());
    let key = SymmetricKey::from_bytes(ss_bytes);
    ss.zeroize();
    ss_bytes.zeroize();

    Ok((key, MlKemCiphertext(ct_bytes)))
}

/// Decapsulate: recover the shared secret from a ciphertext and secret key.
///
/// # Important: ML-KEM Implicit Rejection
///
/// Per FIPS 203, if the ciphertext was produced for a *different* encapsulation
/// key, decapsulation **does not return an error**. Instead it returns a
/// deterministic pseudorandom shared secret (implicit rejection). An `Ok` return
/// only means the ciphertext is structurally valid — not that the key matches.
///
/// Callers MUST authenticate the shared secret via AEAD before trusting it.
/// The AEAD decryption step (in `key_exchange::unwrap_key`) is the definitive
/// "correct key" check.
pub fn decapsulate(dk: &MlKemDecapsulationKey, ct: &MlKemCiphertext) -> Result<SymmetricKey> {
    let dk_parsed = parse_decapsulation_key(&dk.0)?;

    let ct_parsed: &Ciphertext =
        ct.0.as_slice()
            .try_into()
            .map_err(|_| CoreError::InvalidKey("invalid ciphertext length".into()))?;

    // FIPS 203 implicit rejection makes ML-KEM decapsulation infallible for a
    // structurally valid ciphertext. The caller's AEAD authentication is the
    // definitive wrong-key/corruption check.
    let mut ss = dk_parsed.decapsulate(ct_parsed);

    let mut ss_bytes = [0u8; 32];
    ss_bytes.copy_from_slice(ss.as_slice());
    let key = SymmetricKey::from_bytes(ss_bytes);
    ss.zeroize();
    ss_bytes.zeroize();

    Ok(key)
}

/// Parse the current 64-byte seed encoding, with read compatibility for
/// pre-1.0 identities that stored RustCrypto's legacy 2,400-byte expanded
/// ML-KEM-768 private-key encoding. New identities never emit the expanded form.
fn parse_decapsulation_key(bytes: &[u8]) -> Result<DecapsulationKey> {
    if let Ok(seed) = <&Seed>::try_from(bytes) {
        return Ok(DecapsulationKey::from_seed(*seed));
    }
    parse_legacy_expanded_key(bytes)
}

#[allow(deprecated)]
fn parse_legacy_expanded_key(bytes: &[u8]) -> Result<DecapsulationKey> {
    use ml_kem::ExpandedKeyEncoding;

    let expanded = bytes
        .try_into()
        .map_err(|_| CoreError::InvalidKey("invalid decapsulation key length".into()))?;
    DecapsulationKey::from_expanded_bytes(expanded)
        .map_err(|_| CoreError::InvalidKey("invalid legacy decapsulation key encoding".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_generation() {
        let (dk, ek) = generate_keypair().unwrap();
        assert_eq!(
            dk.0.len(),
            64,
            "new private keys use the FIPS 203 seed form"
        );
        assert!(!ek.0.is_empty());
    }

    #[test]
    #[allow(deprecated)]
    fn legacy_expanded_private_key_remains_readable() {
        use ml_kem::ExpandedKeyEncoding;

        let (dk, ek) = MlKem768::generate_keypair();
        let expanded = dk.to_expanded_bytes().to_vec();
        assert_eq!(expanded.len(), 2400);

        let (sender, ct) = encapsulate(&MlKemEncapsulationKey(ek.to_bytes().to_vec())).unwrap();
        let receiver = decapsulate(&MlKemDecapsulationKey(expanded), &ct).unwrap();
        assert_eq!(sender.as_bytes(), receiver.as_bytes());
    }

    #[test]
    fn encapsulate_decapsulate_roundtrip() {
        let (dk, ek) = generate_keypair().unwrap();
        let (ss_sender, ct) = encapsulate(&ek).unwrap();
        let ss_receiver = decapsulate(&dk, &ct).unwrap();
        assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
    }

    #[test]
    fn different_encapsulations_produce_different_secrets() {
        let (_dk, ek) = generate_keypair().unwrap();
        let (ss1, _ct1) = encapsulate(&ek).unwrap();
        let (ss2, _ct2) = encapsulate(&ek).unwrap();
        assert_ne!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn wrong_decapsulation_key_produces_different_secret() {
        let (_dk1, ek1) = generate_keypair().unwrap();
        let (dk2, _ek2) = generate_keypair().unwrap();
        let (ss1, ct1) = encapsulate(&ek1).unwrap();
        let ss_wrong = decapsulate(&dk2, &ct1).unwrap();
        assert_ne!(ss1.as_bytes(), ss_wrong.as_bytes());
    }

    #[test]
    fn wrong_key_returns_ok_but_different_secret_implicit_rejection() {
        // ML-KEM spec: decapsulation with the wrong key returns Ok with a
        // pseudorandom shared secret, not an error. The AEAD step is the real check.
        let (_dk1, ek1) = generate_keypair().unwrap();
        let (dk2, _ek2) = generate_keypair().unwrap();

        let (_ss, ct) = encapsulate(&ek1).unwrap();
        // This must NOT return Err — that would indicate malformed ciphertext, not wrong key
        let result = decapsulate(&dk2, &ct);
        assert!(
            result.is_ok(),
            "implicit rejection: wrong key returns Ok, not Err"
        );
    }
}
