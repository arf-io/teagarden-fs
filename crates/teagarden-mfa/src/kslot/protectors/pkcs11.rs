//! K3: PKCS#11 / HSM slot protector — a real hardware-security-module factor.
//!
//! This is the mechanism `systemd-cryptenroll --pkcs11-token` / Clevis-style HSM
//! enrollment use: a random per-slot KEK is **RSA-OAEP-encrypted to a keypair on
//! the token** at enroll, and **decrypted by the token** (which never exposes the
//! private key) at unlock. So the KEK is recoverable only by whoever holds the
//! HSM *and* its PIN ("something you have" + "something you know").
//!
//! Uses the `cryptoki` PKCS#11 bindings (feature `factor-pkcs11`) — the subprocess
//! route (openssl ↔ pkcs11-tool) was ruled out because RSA-OAEP parameters do not
//! interop through the CLI tools; going through one PKCS#11 API for both
//! `C_Encrypt` and `C_Decrypt` with explicit `CK_RSA_PKCS_OAEP_PARAMS`
//! (SHA-256 / MGF1-SHA256) guarantees the wrap round-trips.
//!
//! Transport: `KekTransport::EncryptedKek` carries the RSA-OAEP ciphertext of the
//! KEK; `params` record only the (public) token label + key id. No secret is stored
//! in the vault — recovering the KEK requires the token's private key + PIN.
//!
//! Per the trait contract the caller directs *when* this runs (a wrong PIN would
//! consume the token's login-retry counter), via the vault's *targeted* unlock —
//! never the speculative one (enforced by `SlotType::is_counter_free`).
//!
//! **Concurrency residual (low, documented):** each `enroll`/`recover_kek` loads
//! the module and calls `C_Initialize` … `C_Finalize` for the duration of one
//! operation. PKCS#11 `C_Finalize` is process-global per loaded module, so two
//! concurrent in-process operations on the *same* module could tear each other's
//! session down. In practice a volume's unlock is serialized (one factor at a
//! time), so this is latent; a shared/ref-counted context is the fix if concurrent
//! multi-slot HSM unlocks are ever added.
//!

use zeroize::Zeroizing;

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use crate::error::{MfaError, Result};

use super::super::protector::{Enrollment, KekTransport, SlotProtector};
use super::super::types::{Kek, SlotType};

/// RSA-OAEP wrap scheme ids recorded in the transport. We prefer SHA-256 (what a
/// real HSM supports) and fall back to SHA-1 (SoftHSM2 2.x rejects SHA-256 OAEP
/// with CKR_ARGUMENTS_BAD). The enroll-chosen scheme is stored so unlock uses the
/// same hash — a mismatch would fail the unwrap.
const SCHEME_SHA256: &str = "pkcs11-rsa-oaep-sha256";
const SCHEME_SHA1: &str = "pkcs11-rsa-oaep-sha1";

fn e(msg: impl std::fmt::Display) -> MfaError {
    MfaError::Pkcs11(msg.to_string())
}

/// Whether a cryptoki error is a "mechanism not supported / bad mechanism params"
/// rejection — the ONLY class of error for which falling back to a different OAEP
/// hash is legitimate. Any other error (transient token state, re-login required,
/// key/permission) must propagate so a fault can never silently downgrade the wrap
/// to SHA-1 (advisor: no silent weakening).
fn is_mechanism_rejected(err: &cryptoki::error::Error) -> bool {
    use cryptoki::error::{Error, RvError};
    matches!(
        err,
        Error::Pkcs11(RvError::MechanismInvalid, _)
            | Error::Pkcs11(RvError::MechanismParamInvalid, _)
            | Error::Pkcs11(RvError::ArgumentsBad, _)
    )
}

/// A PKCS#11 / HSM protector. The token label + key id (public, identifying WHICH
/// key) live in the slot params; the module path (where the provider `.so` is on
/// *this* machine) and the PIN (secret) are the protector's live inputs.
pub struct Pkcs11Protector {
    module_path: String,
    token_label: Option<String>,
    key_id: Vec<u8>,
    pin: Zeroizing<String>,
}

impl Pkcs11Protector {
    /// Construct a protector.
    ///
    /// * `module_path` — the PKCS#11 provider library (e.g.
    ///   `/usr/lib/softhsm/libsofthsm2.so`, or a real HSM's module).
    /// * `token_label` — select the token by label; `None` = the first token.
    /// * `key_id` — the CKA_ID of the RSA keypair on the token.
    /// * `pin` — the user PIN.
    pub fn new(
        module_path: impl Into<String>,
        token_label: Option<String>,
        key_id: Vec<u8>,
        pin: impl Into<String>,
    ) -> Self {
        Self {
            module_path: module_path.into(),
            token_label,
            key_id,
            pin: Zeroizing::new(pin.into()),
        }
    }

    /// Load the module, initialize, select the token, open a session and log in.
    /// The returned `(Pkcs11, Session)` must be kept alive together; the module is
    /// finalized when `Pkcs11` drops.
    fn login(&self, token_label: Option<&str>) -> Result<(Pkcs11, Session)> {
        let pkcs11 = Pkcs11::new(&self.module_path).map_err(e)?;
        pkcs11.initialize(CInitializeArgs::OsThreads).map_err(e)?;
        let slot = Self::select_slot(&pkcs11, token_label)?;
        let session = pkcs11.open_rw_session(slot).map_err(e)?;
        session
            .login(UserType::User, Some(&AuthPin::new(self.pin.to_string())))
            .map_err(e)?;
        Ok((pkcs11, session))
    }

    fn select_slot(pkcs11: &Pkcs11, token_label: Option<&str>) -> Result<Slot> {
        let slots = pkcs11.get_slots_with_token().map_err(e)?;
        match token_label {
            Some(label) => slots
                .into_iter()
                .find(|s| {
                    pkcs11
                        .get_token_info(*s)
                        .map(|ti| ti.label().trim() == label)
                        .unwrap_or(false)
                })
                .ok_or_else(|| e(format!("no PKCS#11 token with label {label:?}"))),
            None => slots
                .into_iter()
                .next()
                .ok_or_else(|| e("no PKCS#11 token present")),
        }
    }

    fn find_key(session: &Session, class: ObjectClass, key_id: &[u8]) -> Result<ObjectHandle> {
        let objs = session
            .find_objects(&[Attribute::Class(class), Attribute::Id(key_id.to_vec())])
            .map_err(e)?;
        objs.into_iter().next().ok_or_else(|| {
            e(format!(
                "no key with id {} on the token",
                hex::encode(key_id)
            ))
        })
    }

    /// The RSA-OAEP mechanism for a given stored scheme id.
    fn oaep_for(scheme: &str) -> Result<Mechanism<'static>> {
        let (hash, mgf) = match scheme {
            SCHEME_SHA256 => (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256),
            SCHEME_SHA1 => (MechanismType::SHA1, PkcsMgfType::MGF1_SHA1),
            other => return Err(e(format!("unknown pkcs11 OAEP scheme {other:?}"))),
        };
        Ok(Mechanism::RsaPkcsOaep(PkcsOaepParams::new(
            hash,
            mgf,
            PkcsOaepSource::empty(),
        )))
    }
}

impl SlotProtector for Pkcs11Protector {
    fn slot_type(&self) -> SlotType {
        SlotType::Pkcs11
    }

    fn enroll(&mut self) -> Result<Enrollment> {
        let (_pkcs11, session) = self.login(self.token_label.as_deref())?;
        let pubkey = Self::find_key(&session, ObjectClass::PUBLIC_KEY, &self.key_id)?;

        // Random KEK, wrapped to the token's RSA public key. Prefer SHA-256 OAEP
        // (real HSMs); fall back to SHA-1 ONLY when the token explicitly rejects the
        // SHA-256 mechanism (SoftHSM2 2.x → CKR_ARGUMENTS_BAD). Any other error
        // propagates — a transient/auth fault must not silently downgrade to SHA-1.
        let kek = Kek::random();
        let (scheme, ciphertext) =
            match session.encrypt(&Self::oaep_for(SCHEME_SHA256)?, pubkey, kek.as_bytes()) {
                Ok(ct) => (SCHEME_SHA256, ct),
                Err(err) if is_mechanism_rejected(&err) => (
                    SCHEME_SHA1,
                    session
                        .encrypt(&Self::oaep_for(SCHEME_SHA1)?, pubkey, kek.as_bytes())
                        .map_err(e)?,
                ),
                Err(err) => return Err(e(err)),
            };

        let params = serde_json::json!({
            "version": 1,
            "token_label": self.token_label,
            "key_id": hex::encode(&self.key_id),
        });
        Ok(Enrollment {
            params,
            transport: KekTransport::EncryptedKek {
                scheme: scheme.to_string(),
                ciphertext,
            },
            kek,
        })
    }

    fn recover_kek(&self, params: &serde_json::Value, transport: &KekTransport) -> Result<Kek> {
        let (scheme, ciphertext) = match transport {
            KekTransport::EncryptedKek { scheme, ciphertext } => (scheme.as_str(), ciphertext),
            _ => return Err(e("pkcs11 slot has a non-EncryptedKek transport")),
        };
        let mechanism = Self::oaep_for(scheme)?;
        // Token label + key id are authoritative from the slot params (vault data);
        // the module path + PIN come from this protector instance (machine + secret).
        let token_label = params.get("token_label").and_then(|v| v.as_str());
        let key_id = params
            .get("key_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| e("pkcs11 slot: missing key_id"))?;
        let key_id = hex::decode(key_id).map_err(|err| e(format!("bad key_id: {err}")))?;

        let (_pkcs11, session) = self.login(token_label)?;
        let privkey = Self::find_key(&session, ObjectClass::PRIVATE_KEY, &key_id)?;

        let plain = Zeroizing::new(
            session
                .decrypt(&mechanism, privkey, ciphertext)
                .map_err(e)?,
        );
        let arr: Zeroizing<[u8; 32]> = Zeroizing::new(
            plain
                .as_slice()
                .try_into()
                .map_err(|_| e("decrypted KEK is not 32 bytes"))?,
        );
        Ok(Kek::from_bytes(*arr))
    }
}
