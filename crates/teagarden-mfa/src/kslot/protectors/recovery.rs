//! Recovery slot: a 256-bit random secret rendered as a human-transcribable
//! 22-word sentence (reusing the core sentence encoding). The secret already has
//! full entropy, so the KEK is a domain-separated derivation of it — no stretch.
//!
//! Enrolling GENERATES a fresh recovery secret and returns its sentence to the
//! caller to display/store once; unlocking takes the sentence back.

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{MfaError, Result};

use super::super::protector::{Enrollment, KekTransport, SlotProtector};
use super::super::types::{context, Kek, SlotType};

/// A recovery-sentence protector.
pub struct RecoveryProtector {
    /// The 32-byte secret. On enroll this is generated; on unlock it is decoded
    /// from the user-supplied sentence.
    secret: Zeroizing<[u8; 32]>,
    /// Set after enroll: the sentence the caller must persist/display.
    enrolled_sentence: Option<Zeroizing<String>>,
}

impl RecoveryProtector {
    /// A protector that will GENERATE a fresh recovery secret at enroll.
    pub fn for_enroll() -> Self {
        let mut s = [0u8; 32];
        OsRng.fill_bytes(&mut s);
        Self {
            secret: Zeroizing::new(s),
            enrolled_sentence: None,
        }
    }

    /// A protector for UNLOCK, from a user-supplied recovery sentence.
    pub fn from_sentence(sentence: &str) -> Result<Self> {
        let wl = teagarden_core::sentence::wordlists::production_wordlists();
        let rl: Vec<std::collections::HashMap<String, u16>> = wl
            .iter()
            .map(|w| teagarden_core::sentence::wordlists::build_reverse_lookup(w))
            .collect();
        let rl_arr: [std::collections::HashMap<String, u16>; 4] = rl
            .try_into()
            .map_err(|_| MfaError::Factor("wordlist shape".into()))?;
        let mut decoded = Zeroizing::new(
            teagarden_core::sentence::decode::decode_ref_string(sentence, &wl, &rl_arr)
                .map_err(|e| MfaError::Factor(format!("invalid recovery sentence: {e}")))?,
        );
        let arr: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| MfaError::Factor("recovery secret is not 32 bytes".into()))?;
        use zeroize::Zeroize;
        decoded.zeroize(); // scrub the decoded Vec copy (audit D#1)
        Ok(Self {
            secret: Zeroizing::new(arr),
            enrolled_sentence: None,
        })
    }

    /// After [`SlotProtector::enroll`], the sentence to show the user once.
    pub fn enrolled_sentence(&self) -> Option<&str> {
        self.enrolled_sentence.as_deref().map(|s| s.as_str())
    }

    fn kek(&self) -> Kek {
        Kek::from_bytes(blake3::derive_key(
            context::KEK_RECOVERY,
            self.secret.as_ref(),
        ))
    }
}

impl SlotProtector for RecoveryProtector {
    fn slot_type(&self) -> SlotType {
        SlotType::Recovery
    }

    fn enroll(&mut self) -> Result<Enrollment> {
        let wl = teagarden_core::sentence::wordlists::production_wordlists();
        let sentence = teagarden_core::sentence::encode::encode_ref_string(&self.secret, &wl)
            .map_err(|e| MfaError::Factor(format!("recovery encode: {e}")))?;
        self.enrolled_sentence = Some(Zeroizing::new(sentence));
        let params = serde_json::json!({ "wordlist_version": 1 });
        Ok(Enrollment {
            params,
            transport: KekTransport::Derived,
            kek: self.kek(),
        })
    }

    fn recover_kek(&self, _params: &serde_json::Value, _transport: &KekTransport) -> Result<Kek> {
        Ok(self.kek())
    }
}
