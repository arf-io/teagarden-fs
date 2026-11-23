use serde::{Deserialize, Serialize};

use crate::error::Result;

/// A single key factor that contributes 32 bytes of entropy to `Kwrap`.
///
/// Factors are combined via `blake3::derive_key` — adding or removing any
/// factor invalidates the vault (intended behaviour: all factors required).
pub trait KeyFactor: Send + Sync {
    /// Stable identifier for this factor kind (e.g. `"password"`, `"totp"`),
    /// recorded in the descriptor so the factor can be reconstructed.
    fn factor_type(&self) -> &'static str;
    /// Returns the **plaintext** descriptor persisted in the vault JSON.
    ///
    /// MUST NOT include secret material (TOTP seed, private keys, etc.).
    /// Secret parameters are returned separately via `sensitive_params` and
    /// stored in the vault's `encrypted_factor_secrets` blob.
    fn descriptor(&self) -> FactorDescriptor;
    /// Returns any secret parameters that must be stored encrypted rather than
    /// in the plaintext descriptor.
    ///
    /// For most factors this returns `None`. `TotpFactor` returns
    /// `Some({"base32_secret": "..."})`.
    fn sensitive_params(&self) -> Option<serde_json::Value> {
        None
    }
    /// Produces the factor's 32-byte contribution.
    fn derive_contribution(&self) -> Result<[u8; 32]>;
}

/// Serialized description of a factor stored inside the vault file.
/// Contains no secret material — only parameters needed to re-derive the factor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactorDescriptor {
    /// Factor kind identifier matching `KeyFactor::factor_type`.
    pub factor_type: String,
    /// Non-secret parameters needed to re-derive the factor (salts, metadata).
    pub params: serde_json::Value,
}

impl FactorDescriptor {
    /// Construct a descriptor from a factor type and its non-secret parameters.
    pub fn new(factor_type: impl Into<String>, params: serde_json::Value) -> Self {
        Self {
            factor_type: factor_type.into(),
            params,
        }
    }
}

/// Derive the composite wrapping key from all factor contributions.
///
/// Uses `blake3::derive_key` with a fixed context string so the output is
/// domain-separated from all other BLAKE3 usages in the codebase.
pub fn derive_kwrap(contributions: &[[u8; 32]]) -> [u8; 32] {
    const CONTEXT: &str = "teagarden.v1:kwrap 2024-01-01";
    let mut ikm = Vec::with_capacity(contributions.len() * 32);
    for c in contributions {
        ikm.extend_from_slice(c);
    }
    blake3::derive_key(CONTEXT, &ikm)
}
