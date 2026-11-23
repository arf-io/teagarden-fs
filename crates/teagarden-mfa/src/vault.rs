use std::collections::HashMap;
use std::io::Write as IoWrite;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use base64ct::{Base64, Encoding};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{MfaError, Result};
use crate::factor::{derive_kwrap, FactorDescriptor, KeyFactor};

const VAULT_VERSION: u32 = 1;
const AAD_PREFIX: &[u8] = b"teagarden.v1:vault:";
/// Domain-separation context for the factor-secrets encryption key.
const FACTOR_SECRETS_CONTEXT: &str = "teagarden factor-secrets v1";
/// Domain-separation AAD for the factor-secrets ciphertext.
const FACTOR_SECRETS_AAD: &[u8] = b"teagarden.v1:factor-secrets";

/// Serialized MFA vault stored alongside the volume directory.
#[derive(Debug, Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    volume_id: String,
    /// How many wrapping factors are required and what their types are.
    ///
    /// SECURITY: these params are stored in plaintext. They MUST NOT contain
    /// secret material (TOTP seeds, private keys, etc.). Secrets are stored
    /// in `encrypted_factor_secrets` below.
    factor_descriptors: Vec<FactorDescriptor>,
    /// XChaCha20-Poly1305 ciphertext of the 32-byte `Kmaster`, base64.
    wrapped_key: String,
    /// 24-byte nonce for XChaCha20-Poly1305, base64.
    nonce: String,
    /// BLAKE3(Kmaster) as a sanity check after decryption, hex.
    commitment: String,
    /// XChaCha20-Poly1305-encrypted JSON blob of per-factor secret parameters.
    ///
    /// The plaintext is a JSON object mapping factor index (as string) to a
    /// `serde_json::Value` containing the sensitive params for that factor,
    /// e.g. `{"0": {"base32_secret": "JBSWY3DPEHPK3PXP"}}`.
    ///
    /// Encryption key = `blake3::derive_key(FACTOR_SECRETS_CONTEXT, &kwrap)`
    /// where `kwrap` is the same composite key used to wrap `Kmaster`. This
    /// means an attacker needs all factors to decrypt either the master key OR
    /// the TOTP secret — the plaintext vault file reveals neither.
    ///
    /// The nonce for this ciphertext is stored in `factor_secrets_nonce`.
    /// Present only when at least one factor has sensitive params.
    #[serde(skip_serializing_if = "Option::is_none")]
    encrypted_factor_secrets: Option<String>,
    /// 24-byte nonce for the `encrypted_factor_secrets` ciphertext, base64.
    #[serde(skip_serializing_if = "Option::is_none")]
    factor_secrets_nonce: Option<String>,
}

/// A local per-device vault that wraps the volume master key under multiple factors.
///
/// The vault file itself contains no secret material in plaintext — all TOTP
/// seeds and other sensitive factor data are stored in `encrypted_factor_secrets`,
/// which is XChaCha20-Poly1305-encrypted and requires all factors to decrypt.
pub struct MfaVault {
    path: PathBuf,
}

impl MfaVault {
    /// Load a vault from the given path (file must exist).
    pub fn load(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Returns the canonical vault path for a volume directory.
    pub fn path_for_volume(volume_dir: &Path) -> PathBuf {
        volume_dir.join("mfa_vault.json")
    }

    /// Returns whether a vault file is present at the given path.
    pub fn exists(path: &Path) -> bool {
        path.exists()
    }

    /// Create a new vault wrapping `kmaster` under all provided factors.
    ///
    /// Writes the vault JSON to `path` with mode 0o600 (owner read/write only)
    /// and returns a handle to it.
    pub fn create(
        kmaster: &[u8; 32],
        volume_id: &str,
        factors: &[Box<dyn KeyFactor>],
        path: impl Into<PathBuf>,
    ) -> Result<Self> {
        let path = path.into();

        // Derive composite wrapping key
        let kwrap = derive_kwrap_from_factors(factors)?;
        let kwrap = Zeroizing::new(kwrap);

        // Encrypt kmaster under Kwrap
        let mut nonce_bytes = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let cipher = XChaCha20Poly1305::new(Key::from_slice(kwrap.as_ref()));
        let nonce = XNonce::from_slice(&nonce_bytes);
        let aad = build_aad(volume_id);

        let ciphertext = cipher
            .encrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: kmaster.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| MfaError::Factor("key wrapping encryption failed".into()))?;

        // Commitment: domain-separated BLAKE3 derivation of kmaster for fast
        // post-decrypt verification. Using derive_key instead of the unkeyed
        // hash prevents commitment oracle attacks and adds domain separation.
        let commitment = hex::encode(blake3::derive_key(
            "teagarden.v1:vault-commitment",
            kmaster.as_ref(),
        ));

        // Build and encrypt the factor secrets blob (H14 fix).
        // Collect sensitive params from all factors (e.g. TOTP base32_secret).
        let (encrypted_factor_secrets, factor_secrets_nonce) = encrypt_factor_secrets(
            factors,
            <&[u8; 32]>::try_from(&kwrap[..])
                .map_err(|_| MfaError::Factor("kwrap wrong length".into()))?,
        )?;

        let vault = VaultFile {
            version: VAULT_VERSION,
            volume_id: volume_id.to_string(),
            factor_descriptors: factors.iter().map(|f| f.descriptor()).collect(),
            wrapped_key: Base64::encode_string(&ciphertext),
            nonce: Base64::encode_string(&nonce_bytes),
            commitment,
            encrypted_factor_secrets,
            factor_secrets_nonce,
        };

        let json = serde_json::to_string_pretty(&vault)?;

        // H13 fix: write with explicit 0o600 permissions, bypassing the process umask.
        // The vault may contain encrypted key material and (after H14) an encrypted
        // TOTP-seed blob — restrict access to the owning user only.
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(json.as_bytes())?;
        }

        Ok(Self { path })
    }

    /// Unwrap `Kmaster` by deriving `Kwrap` from the provided factors.
    ///
    /// For TOTP, the caller should pass both current-window and previous-window
    /// instances so that unwrapping works within the grace period.
    pub fn unwrap(&self, factors: &[Box<dyn KeyFactor>]) -> Result<[u8; 32]> {
        let json = std::fs::read_to_string(&self.path)?;
        let vault: VaultFile = serde_json::from_str(&json)?;

        if vault.version != VAULT_VERSION {
            return Err(MfaError::UnsupportedVersion(vault.version));
        }

        let kwrap = derive_kwrap_from_factors(factors)?;
        let kwrap = Zeroizing::new(kwrap);

        let ciphertext = Base64::decode_vec(&vault.wrapped_key)
            .map_err(|e| MfaError::Factor(format!("base64 decode: {e}")))?;
        let nonce_bytes = Base64::decode_vec(&vault.nonce)
            .map_err(|e| MfaError::Factor(format!("base64 decode: {e}")))?;

        let cipher = XChaCha20Poly1305::new(Key::from_slice(kwrap.as_ref()));
        let nonce = xnonce(&nonce_bytes, "vault nonce")?;
        let aad = build_aad(&vault.volume_id);

        let plaintext = cipher
            .decrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| MfaError::DecryptionFailed)?;

        if plaintext.len() != 32 {
            return Err(MfaError::DecryptionFailed);
        }

        let mut kmaster = [0u8; 32];
        kmaster.copy_from_slice(&plaintext);

        // Verify commitment — must use the same derive_key call as create().
        let actual = hex::encode(blake3::derive_key(
            "teagarden.v1:vault-commitment",
            &kmaster,
        ));
        if !constant_time_eq_str(&actual, &vault.commitment) {
            kmaster.zeroize_if_clear();
            return Err(MfaError::DecryptionFailed);
        }

        Ok(kmaster)
    }

    /// Return the plaintext factor descriptors stored in the vault.
    ///
    /// The returned descriptors do NOT contain sensitive parameters (e.g. TOTP
    /// seeds). Use `decrypt_factor_secrets` if you need to reconstruct factors
    /// from scratch (e.g. to re-enrol on a new device).
    pub fn descriptors(&self) -> Result<Vec<FactorDescriptor>> {
        let json = std::fs::read_to_string(&self.path)?;
        let vault: VaultFile = serde_json::from_str(&json)?;
        Ok(vault.factor_descriptors)
    }

    /// Decrypt and return the per-factor sensitive parameters.
    ///
    /// Returns a map of `factor_index → sensitive_params` for each factor that
    /// had sensitive params at creation time (e.g. TOTP factors include
    /// `{"base32_secret": "..."}`). Factors with no sensitive params are absent
    /// from the map.
    ///
    /// Requires all factors so that `Kwrap` can be derived; the same factors
    /// used to create the vault must be provided (correct but requires user
    /// interaction for TOTP).
    pub fn decrypt_factor_secrets(
        &self,
        factors: &[Box<dyn KeyFactor>],
    ) -> Result<HashMap<usize, serde_json::Value>> {
        let json = std::fs::read_to_string(&self.path)?;
        let vault: VaultFile = serde_json::from_str(&json)?;

        let (enc_blob, nonce_b64) =
            match (&vault.encrypted_factor_secrets, &vault.factor_secrets_nonce) {
                (Some(e), Some(n)) => (e, n),
                _ => return Ok(HashMap::new()),
            };

        let kwrap = derive_kwrap_from_factors(factors)?;
        let kwrap = Zeroizing::new(kwrap);

        let secrets_map = decrypt_factor_secrets_blob(
            enc_blob,
            nonce_b64,
            <&[u8; 32]>::try_from(&kwrap[..])
                .map_err(|_| MfaError::Factor("kwrap wrong length".into()))?,
        )?;
        Ok(secrets_map)
    }

    /// Delete the vault file (removes MFA protection; password alone suffices after).
    pub fn remove(&self) -> Result<()> {
        std::fs::remove_file(&self.path).map_err(MfaError::Io)
    }
}

/// Encrypt the per-factor sensitive params blob.
///
/// Returns `(None, None)` when no factor has sensitive params.
fn encrypt_factor_secrets(
    factors: &[Box<dyn KeyFactor>],
    kwrap: &[u8; 32],
) -> Result<(Option<String>, Option<String>)> {
    // Collect sensitive params indexed by factor position.
    let mut secrets: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    for (i, f) in factors.iter().enumerate() {
        if let Some(params) = f.sensitive_params() {
            secrets.insert(i.to_string(), params);
        }
    }

    if secrets.is_empty() {
        return Ok((None, None));
    }

    let plaintext = serde_json::to_vec(&serde_json::Value::Object(secrets))?;

    // Derive a dedicated encryption key from kwrap so the TOTP-secrets
    // ciphertext is domain-separated from the kmaster ciphertext.
    let secrets_key = blake3::derive_key(FACTOR_SECRETS_CONTEXT, kwrap);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&secrets_key));

    let mut nonce_bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: &plaintext,
                aad: FACTOR_SECRETS_AAD,
            },
        )
        .map_err(|_| MfaError::Factor("factor secrets encryption failed".into()))?;

    Ok((
        Some(Base64::encode_string(&ciphertext)),
        Some(Base64::encode_string(&nonce_bytes)),
    ))
}

/// Decrypt the factor secrets blob and return `factor_index → params` map.
fn decrypt_factor_secrets_blob(
    enc_b64: &str,
    nonce_b64: &str,
    kwrap: &[u8; 32],
) -> Result<HashMap<usize, serde_json::Value>> {
    let ciphertext = Base64::decode_vec(enc_b64)
        .map_err(|e| MfaError::Factor(format!("base64 decode factor secrets: {e}")))?;
    let nonce_bytes = Base64::decode_vec(nonce_b64)
        .map_err(|e| MfaError::Factor(format!("base64 decode factor secrets nonce: {e}")))?;

    let secrets_key = blake3::derive_key(FACTOR_SECRETS_CONTEXT, kwrap);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&secrets_key));
    let nonce = xnonce(&nonce_bytes, "factor secrets nonce")?;

    let plaintext = cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: &ciphertext,
                aad: FACTOR_SECRETS_AAD,
            },
        )
        .map_err(|_| MfaError::DecryptionFailed)?;

    let raw: serde_json::Value = serde_json::from_slice(&plaintext)?;
    let obj = raw
        .as_object()
        .ok_or_else(|| MfaError::Factor("factor secrets blob is not a JSON object".into()))?;

    let mut out = HashMap::new();
    for (k, v) in obj {
        let idx: usize = k.parse().map_err(|_| {
            MfaError::Factor(format!("invalid factor index key in secrets blob: {k}"))
        })?;
        out.insert(idx, v.clone());
    }
    Ok(out)
}

/// mfa-L7: the vault file is attacker-writable, and `XNonce::from_slice`
/// panics on any length but 24. Check first and return an error.
fn xnonce<'a>(bytes: &'a [u8], what: &str) -> Result<&'a XNonce> {
    if bytes.len() != 24 {
        return Err(MfaError::Factor(format!(
            "{what} is {} bytes, expected 24",
            bytes.len()
        )));
    }
    Ok(XNonce::from_slice(bytes))
}

fn derive_kwrap_from_factors(factors: &[Box<dyn KeyFactor>]) -> Result<[u8; 32]> {
    let mut contributions = Vec::with_capacity(factors.len());
    for f in factors {
        contributions.push(f.derive_contribution()?);
    }
    Ok(derive_kwrap(&contributions))
}

fn build_aad(volume_id: &str) -> Vec<u8> {
    let mut aad = AAD_PREFIX.to_vec();
    aad.extend_from_slice(volume_id.as_bytes());
    aad
}

fn constant_time_eq_str(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

trait ZeroizeArray {
    fn zeroize_if_clear(&mut self);
}

impl ZeroizeArray for [u8; 32] {
    fn zeroize_if_clear(&mut self) {
        use zeroize::Zeroize;
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factors::password::PasswordFactor;
    use crate::factors::totp::TotpFactor;
    use tempfile::TempDir;

    fn test_factor() -> Box<dyn KeyFactor> {
        Box::new(PasswordFactor::new("strong-test-password-here"))
    }

    #[test]
    fn create_and_unwrap_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.json");

        let kmaster = [0xAB_u8; 32];
        let factors: Vec<Box<dyn KeyFactor>> = vec![test_factor()];

        MfaVault::create(&kmaster, "test-volume-id", &factors, &path).unwrap();
        assert!(path.exists());

        let vault = MfaVault::load(&path);
        let recovered = vault.unwrap(&factors).unwrap();
        assert_eq!(recovered, kmaster);
    }

    #[test]
    fn vault_file_permissions_are_0o600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.json");
        let factors: Vec<Box<dyn KeyFactor>> = vec![test_factor()];

        MfaVault::create(&[0u8; 32], "vol-perms", &factors, &path).unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "vault file must be mode 0o600, got 0o{mode:03o}"
        );
    }

    #[test]
    fn totp_secret_not_in_plaintext_descriptor() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.json");

        let (totp_factor, b32) = TotpFactor::generate("teagarden", "test@example.com");
        // derive_contribution requires an OTP value; bind the current OTP.
        let otp = totp_factor.current_otp().unwrap();
        let bound =
            TotpFactor::from_base32_otp(&b32, &otp, "teagarden", "test@example.com").unwrap();
        let factors: Vec<Box<dyn KeyFactor>> = vec![Box::new(bound)];

        MfaVault::create(&[0xBB_u8; 32], "vol-totp", &factors, &path).unwrap();

        // Read the raw JSON and assert no TOTP secret leaks into plaintext.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("base32_secret"),
            "base32_secret must NOT appear in plaintext vault JSON (H14)"
        );
    }

    #[test]
    fn totp_secret_recoverable_via_decrypt_factor_secrets() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.json");

        let (totp_factor, original_b32) = TotpFactor::generate("teagarden", "user@example.com");
        let otp = totp_factor.current_otp().unwrap();

        // Bind the OTP for vault creation (derive_contribution requires it).
        let bound_for_create =
            TotpFactor::from_base32_otp(&original_b32, &otp, "teagarden", "user@example.com")
                .unwrap();
        let factors_create: Vec<Box<dyn KeyFactor>> = vec![Box::new(bound_for_create)];
        MfaVault::create(&[0xCC_u8; 32], "vol-totp-recover", &factors_create, &path).unwrap();

        // Same OTP used to decrypt the secrets blob (kwrap is derived from same factors).
        let bound_for_open =
            TotpFactor::from_base32_otp(&original_b32, &otp, "teagarden", "user@example.com")
                .unwrap();
        let vault = MfaVault::load(&path);
        let factors_open: Vec<Box<dyn KeyFactor>> = vec![Box::new(bound_for_open)];
        let secrets = vault.decrypt_factor_secrets(&factors_open).unwrap();

        let recovered_b32 = secrets[&0]["base32_secret"].as_str().unwrap();
        assert_eq!(recovered_b32, original_b32);
    }

    /// mfa-L7: the vault file is attacker-writable. A nonce of the wrong length
    /// made `XNonce::from_slice` panic; it must be an `Err`.
    fn tamper_field(path: &Path, field: &str, value: &str) {
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        v[field] = serde_json::Value::String(value.to_string());
        std::fs::write(path, serde_json::to_string(&v).unwrap()).unwrap();
    }

    #[test]
    fn short_wrap_nonce_is_an_error_not_a_panic() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.json");
        let factors: Vec<Box<dyn KeyFactor>> = vec![test_factor()];
        MfaVault::create(&[0xAB_u8; 32], "vol", &factors, &path).unwrap();
        tamper_field(&path, "nonce", &Base64::encode_string(&[0u8; 12]));
        let vault = MfaVault::load(&path);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            vault.unwrap(&factors).is_err()
        }));
        assert_eq!(
            r.ok(),
            Some(true),
            "a 12-byte nonce must be Err, not a panic"
        );
    }

    #[test]
    fn short_factor_secrets_nonce_is_an_error_not_a_panic() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.json");
        let (totp, b32) = TotpFactor::generate("teagarden", "user@example.com");
        let otp = totp.current_otp().unwrap();
        let make = || -> Vec<Box<dyn KeyFactor>> {
            vec![Box::new(
                TotpFactor::from_base32_otp(&b32, &otp, "teagarden", "user@example.com").unwrap(),
            )]
        };
        MfaVault::create(&[0xCC_u8; 32], "vol", &make(), &path).unwrap();
        tamper_field(
            &path,
            "factor_secrets_nonce",
            &Base64::encode_string(&[0u8; 5]),
        );
        let vault = MfaVault::load(&path);
        let factors = make();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            vault.decrypt_factor_secrets(&factors).is_err()
        }));
        assert_eq!(
            r.ok(),
            Some(true),
            "a 5-byte nonce must be Err, not a panic"
        );
    }

    #[test]
    fn wrong_factor_fails_decryption() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.json");

        let kmaster = [0xAB_u8; 32];
        let good_factors: Vec<Box<dyn KeyFactor>> = vec![test_factor()];
        MfaVault::create(&kmaster, "vol", &good_factors, &path).unwrap();

        let bad_factors: Vec<Box<dyn KeyFactor>> =
            vec![Box::new(PasswordFactor::new("wrong-password"))];
        let vault = MfaVault::load(&path);
        let result = vault.unwrap(&bad_factors);
        assert!(matches!(result, Err(MfaError::DecryptionFailed)));
    }

    #[test]
    fn two_factor_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.json");

        let kmaster = [0xCC_u8; 32];
        let factors: Vec<Box<dyn KeyFactor>> = vec![
            test_factor(),
            Box::new(crate::factors::hardware::HardwareSerialFactor::new()),
        ];

        MfaVault::create(&kmaster, "vol-multi", &factors, &path).unwrap();
        let vault = MfaVault::load(&path);
        let recovered = vault.unwrap(&factors).unwrap();
        assert_eq!(recovered, kmaster);
    }

    #[test]
    fn vault_remove() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.json");
        let factors: Vec<Box<dyn KeyFactor>> = vec![test_factor()];
        MfaVault::create(&[0u8; 32], "vol", &factors, &path).unwrap();

        let vault = MfaVault::load(&path);
        vault.remove().unwrap();
        assert!(!path.exists());
    }
}
