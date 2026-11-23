//! Passphrase slot: Argon2id stretch → derived KEK. Costs are stored PER SLOT
//! (so a slot can be tuned by re-enrolling without breaking others).

use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{MfaError, Result};

use super::super::protector::{Enrollment, KekTransport, SlotProtector};
use super::super::types::{context, Kek, SlotType};

/// Argon2id cost parameters, persisted per slot.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Argon2Cost {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Iterations (time cost).
    pub t: u32,
    /// Parallelism lanes.
    pub p: u32,
}

impl Default for Argon2Cost {
    fn default() -> Self {
        // mfa-M5: the cost for NEW slots matches the core password KDF default
        // (`teagarden_core::crypto::keys::Argon2Params::default()`: 256 MiB,
        // t=4, p=4). It used to be 64 MiB / t=2 / p=1, which made a passphrase
        // slot cheaper to grind than a password-rooted volume. Every slot stores
        // its own cost and unlock reads the stored one, so existing slots keep
        // opening at the cost they were enrolled with.
        Self {
            m_kib: 262_144,
            t: 4,
            p: 4,
        }
    }
}

/// Upper bounds on Argon2 cost, enforced BOTH at enroll and — critically — at
/// unlock, because the cost is read from the (attacker-writable) vault file: an
/// unbounded `m_kib`/`t` would let a crafted slot OOM/CPU-exhaust the victim's
/// own unlock attempt (audit finding E). 4 GiB / 16 passes / 16 lanes is far
/// above any legitimate interactive or server setting.
const MAX_M_KIB: u32 = 4 * 1024 * 1024; // 4 GiB
const MAX_T: u32 = 16;
const MAX_P: u32 = 16;

impl Argon2Cost {
    /// Reject absurd (hostile) cost parameters. Called before any Argon2 run.
    pub fn validate(&self) -> Result<()> {
        if self.m_kib < 8 || self.m_kib > MAX_M_KIB {
            return Err(MfaError::Factor(format!(
                "argon2 m_kib {} out of range [8, {MAX_M_KIB}]",
                self.m_kib
            )));
        }
        if self.t == 0 || self.t > MAX_T {
            return Err(MfaError::Factor(format!(
                "argon2 t {} out of range [1, {MAX_T}]",
                self.t
            )));
        }
        if self.p == 0 || self.p > MAX_P {
            return Err(MfaError::Factor(format!(
                "argon2 p {} out of range [1, {MAX_P}]",
                self.p
            )));
        }
        Ok(())
    }
}

/// Non-secret params stored in the slot.
#[derive(Serialize, Deserialize)]
struct PassphraseParams {
    argon2: Argon2Cost,
    /// 16-byte random salt, base64.
    salt_b64: String,
}

/// A passphrase protector. Holds the passphrase (zeroized) for enroll/unlock.
pub struct PassphraseProtector {
    passphrase: Zeroizing<Vec<u8>>,
    cost: Argon2Cost,
}

impl PassphraseProtector {
    /// New protector for the given passphrase and cost (use [`Argon2Cost::default`]).
    pub fn new(passphrase: impl Into<Vec<u8>>, cost: Argon2Cost) -> Self {
        Self {
            passphrase: Zeroizing::new(passphrase.into()),
            cost,
        }
    }

    fn derive_kek(&self, cost: &Argon2Cost, salt: &[u8]) -> Result<Kek> {
        // Bound the cost BEFORE constructing Params — at unlock this cost comes
        // from the untrusted vault file (audit finding E: DoS via huge m_kib/t).
        cost.validate()?;
        let params = Params::new(cost.m_kib, cost.t, cost.p, Some(32))
            .map_err(|e| MfaError::Factor(format!("argon2 params: {e}")))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(&self.passphrase, salt, out.as_mut_slice())
            .map_err(|e| MfaError::Factor(format!("argon2: {e}")))?;
        // Domain-separate the KEK from the raw Argon2 output.
        Ok(Kek::from_bytes(blake3::derive_key(
            context::KEK_PASSPHRASE,
            out.as_ref(),
        )))
    }
}

impl SlotProtector for PassphraseProtector {
    fn slot_type(&self) -> SlotType {
        SlotType::Passphrase
    }

    fn enroll(&mut self) -> Result<Enrollment> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let kek = self.derive_kek(&self.cost, &salt)?;
        let params = PassphraseParams {
            argon2: self.cost,
            salt_b64: b64(&salt),
        };
        Ok(Enrollment {
            params: serde_json::to_value(params).map_err(MfaError::Serialization)?,
            transport: KekTransport::Derived,
            kek,
        })
    }

    fn recover_kek(&self, params: &serde_json::Value, _transport: &KekTransport) -> Result<Kek> {
        let p: PassphraseParams =
            serde_json::from_value(params.clone()).map_err(MfaError::Serialization)?;
        let salt = unb64(&p.salt_b64)?;
        self.derive_kek(&p.argon2, &salt)
    }
}

/// Validate a persisted passphrase slot's params (Argon2 cost bounds + a
/// present, decodable salt) without any secret input. Called by the vault's
/// `load()` validator so a hostile slot is rejected up front.
pub fn validate_params(params: &serde_json::Value) -> Result<()> {
    let p: PassphraseParams =
        serde_json::from_value(params.clone()).map_err(MfaError::Serialization)?;
    p.argon2.validate()?;
    unb64(&p.salt_b64)?;
    Ok(())
}

fn b64(b: &[u8]) -> String {
    use base64ct::{Base64, Encoding};
    Base64::encode_string(b)
}

fn unb64(s: &str) -> Result<Vec<u8>> {
    use base64ct::{Base64, Encoding};
    Base64::decode_vec(s).map_err(|e| MfaError::Factor(format!("bad base64 salt: {e}")))
}
