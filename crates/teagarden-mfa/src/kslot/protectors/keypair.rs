//! Keypair slot: a random KEK encrypted to an asymmetric recipient (age X25519
//! or ssh-ed25519). The `EncryptedKek` transport stores the age ciphertext of
//! the KEK; unlock decrypts it with the private identity. ssh-rsa recipients are
//! rejected (RUSTSEC-2023-0071 in the underlying `rsa` crate).

use std::io::{Read, Write};
use std::str::FromStr;

use zeroize::Zeroizing;

use crate::error::{MfaError, Result};

use super::super::protector::{Enrollment, KekTransport, SlotProtector};
use super::super::types::{Kek, SlotType};

/// Scheme id stored in the transport.
const SCHEME: &str = "age";

enum Mode {
    /// Enrollment: encrypt a fresh KEK to this recipient.
    Enroll {
        recipient: Box<dyn age::Recipient>,
        recipient_str: String,
    },
    /// Unlock: decrypt the stored KEK ciphertext with this identity.
    Unlock { identity: Box<dyn age::Identity> },
}

/// A keypair (age / ssh-ed25519) protector.
pub struct KeypairProtector {
    mode: Mode,
}

impl KeypairProtector {
    /// A protector that, at enroll, encrypts a fresh KEK to `recipient_str`
    /// (an `age1…` X25519 recipient or an `ssh-ed25519 …` public key).
    pub fn for_enroll(recipient_str: &str) -> Result<Self> {
        let recipient = parse_recipient(recipient_str)?;
        Ok(Self {
            mode: Mode::Enroll {
                recipient,
                recipient_str: recipient_str.to_string(),
            },
        })
    }

    /// A protector for unlock, from an `AGE-SECRET-KEY-1…` identity string.
    pub fn for_unlock_age(identity_str: &str) -> Result<Self> {
        let id = age::x25519::Identity::from_str(identity_str)
            .map_err(|e| MfaError::Factor(format!("invalid age identity: {e}")))?;
        Ok(Self {
            mode: Mode::Unlock {
                identity: Box::new(id),
            },
        })
    }

    /// A protector for unlock, from an OpenSSH private key (ed25519), e.g. the
    /// bytes of `~/.ssh/id_ed25519`.
    pub fn for_unlock_ssh(private_key_pem: &[u8]) -> Result<Self> {
        let id = age::ssh::Identity::from_buffer(private_key_pem, None)
            .map_err(|e| MfaError::Factor(format!("invalid ssh identity: {e}")))?;
        Ok(Self {
            mode: Mode::Unlock {
                identity: Box::new(id),
            },
        })
    }
}

fn parse_recipient(s: &str) -> Result<Box<dyn age::Recipient>> {
    let s = s.trim();
    if s.starts_with("age1") {
        let r = age::x25519::Recipient::from_str(s)
            .map_err(|e| MfaError::Factor(format!("invalid age recipient: {e}")))?;
        Ok(Box::new(r))
    } else if s.starts_with("ssh-ed25519 ") {
        let r = age::ssh::Recipient::from_str(s)
            .map_err(|e| MfaError::Factor(format!("invalid ssh recipient: {e:?}")))?;
        Ok(Box::new(r))
    } else if s.starts_with("ssh-rsa ") {
        Err(MfaError::Factor(
            "ssh-rsa recipients are rejected (RUSTSEC-2023-0071); use ssh-ed25519 or an age key"
                .into(),
        ))
    } else {
        Err(MfaError::Factor(
            "unrecognized recipient (expected age1… or ssh-ed25519 …)".into(),
        ))
    }
}

fn age_encrypt(recipient: &dyn age::Recipient, plaintext: &[u8]) -> Result<Vec<u8>> {
    let enc = age::Encryptor::with_recipients(std::iter::once(recipient))
        .map_err(|e| MfaError::Factor(format!("age encryptor: {e}")))?;
    let mut out = Vec::new();
    let mut w = enc
        .wrap_output(&mut out)
        .map_err(|e| MfaError::Factor(format!("age wrap: {e}")))?;
    w.write_all(plaintext)
        .map_err(|e| MfaError::Factor(format!("age write: {e}")))?;
    w.finish()
        .map_err(|e| MfaError::Factor(format!("age finish: {e}")))?;
    Ok(out)
}

fn age_decrypt(identity: &dyn age::Identity, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let dec = age::Decryptor::new(ciphertext)
        .map_err(|e| MfaError::Factor(format!("age decryptor: {e}")))?;
    let mut r = dec
        .decrypt(std::iter::once(identity))
        .map_err(|e| MfaError::Factor(format!("age decrypt (wrong key?): {e}")))?;
    let mut out = Zeroizing::new(Vec::new());
    r.read_to_end(&mut out)
        .map_err(|e| MfaError::Factor(format!("age read: {e}")))?;
    Ok(out)
}

impl SlotProtector for KeypairProtector {
    fn slot_type(&self) -> SlotType {
        SlotType::Keypair
    }

    fn enroll(&mut self) -> Result<Enrollment> {
        let (recipient, recipient_str) = match &self.mode {
            Mode::Enroll {
                recipient,
                recipient_str,
            } => (recipient.as_ref(), recipient_str.clone()),
            Mode::Unlock { .. } => {
                return Err(MfaError::Factor(
                    "keypair protector built for unlock cannot enroll".into(),
                ))
            }
        };
        let kek = Kek::random();
        let ciphertext = age_encrypt(recipient, kek.as_bytes())?;
        Ok(Enrollment {
            params: serde_json::json!({ "recipient": recipient_str }),
            transport: KekTransport::EncryptedKek {
                scheme: SCHEME.to_string(),
                ciphertext,
            },
            kek,
        })
    }

    fn recover_kek(&self, _params: &serde_json::Value, transport: &KekTransport) -> Result<Kek> {
        let identity = match &self.mode {
            Mode::Unlock { identity } => identity.as_ref(),
            Mode::Enroll { .. } => {
                return Err(MfaError::Factor(
                    "keypair protector built for enroll cannot unlock".into(),
                ))
            }
        };
        let ciphertext = match transport {
            KekTransport::EncryptedKek { scheme, ciphertext } if scheme == SCHEME => ciphertext,
            _ => {
                return Err(MfaError::Factor(
                    "keypair slot transport is not an age-encrypted KEK".into(),
                ))
            }
        };
        let plain = age_decrypt(identity, ciphertext)?;
        let arr: Zeroizing<[u8; 32]> = Zeroizing::new(
            plain
                .as_slice()
                .try_into()
                .map_err(|_| MfaError::Factor("decrypted KEK is not 32 bytes".into()))?,
        );
        Ok(Kek::from_bytes(*arr))
    }
}
