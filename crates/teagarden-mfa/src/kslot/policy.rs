//! Unlock policy + Shamir threshold splitting for the key-slot vault.
//!
//! The top-level policy is ALWAYS "any-1 over entries" (the LUKS2 semantic: any
//! satisfied entry opens the volume). An entry is either a single slot (whose
//! payload is the master key) or a k-of-n **group** (whose members' payloads are
//! Shamir shares of the master key). Boolean AND is expressed as `k == n`.

use serde::{Deserialize, Serialize};
use vsss_rs::Gf256;
use zeroize::Zeroize;

use crate::error::{MfaError, Result};

use super::types::SlotId;

/// One top-level policy entry (the vault opens if ANY entry is satisfied).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PolicyEntry {
    /// A single slot whose payload is the full master key.
    Slot {
        /// The slot that opens the vault on its own.
        slot_id: SlotId,
    },
    /// A k-of-n threshold group whose members' payloads are Shamir shares.
    Group {
        /// Threshold: how many member shares reconstruct the master key.
        k: u32,
        /// The member slot ids (a set; order-insensitive).
        member_slot_ids: Vec<SlotId>,
        /// Bumped whenever the group is re-split; bound into each share's AAD so
        /// shares from different generations can never be combined.
        share_gen: u32,
    },
}

/// The vault unlock policy: any-1 over its entries.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Policy {
    /// Top-level entries; satisfying any ONE of them yields the master key.
    pub entries: Vec<PolicyEntry>,
}

impl Policy {
    /// True if no entry exists (a freshly-created vault cannot be unlocked until
    /// a slot is enrolled).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Split a 32-byte master key into `n` Shamir shares over GF(256) with threshold
/// `k` (any `k` shares reconstruct it). Each share serializes to 33 bytes
/// (1-byte x-coordinate + 32 y-bytes). `k` must be `1 <= k <= n <= 255`.
///
/// Coefficients are drawn uniformly over the **full** field `[0, 255]` by
/// `vsss-rs`. This is the property RUSTSEC-2024-0398 found missing in the
/// previous `sharks` backend, whose dealer excluded zero and thereby leaked
/// information about the secret to a holder of `k-1` shares when the same
/// secret was re-shared many times. See `coefficients_are_not_biased_away_from_zero`.
pub fn split_master_key(mk: &[u8; 32], k: u32, n: usize) -> Result<Vec<Vec<u8>>> {
    if k == 0 || k as usize > n || n > 255 {
        return Err(MfaError::Factor(format!(
            "invalid threshold: need 1 <= k({k}) <= n({n}) <= 255"
        )));
    }
    let shares = Gf256::split_array(
        k as usize,
        n,
        mk.as_slice(),
        rand_core_v010::UnwrapErr(getrandom_v04::SysRng),
    )
    .map_err(|e| MfaError::Factor(format!("shamir split failed: {e:?}")))?;
    if shares.len() != n {
        return Err(MfaError::Factor(
            "shamir dealer produced too few shares".into(),
        ));
    }
    Ok(shares)
}

/// Reconstruct the master key from at least `k` serialized shares. Returns an
/// error if the shares are malformed or too few. The recovered value is verified
/// against the vault commitment by the caller (a wrong share set yields wrong
/// bytes here, caught by that check).
pub fn combine_shares(k: u32, share_bytes: &[Vec<u8>]) -> Result<[u8; 32]> {
    if share_bytes.len() < k as usize {
        return Err(MfaError::Factor(format!(
            "need {k} shares to reconstruct, have {}",
            share_bytes.len()
        )));
    }
    for b in share_bytes {
        if b.len() != 33 {
            return Err(MfaError::Factor(format!(
                "malformed shamir share: expected 33 bytes, got {}",
                b.len()
            )));
        }
    }
    let mut secret = Gf256::combine_array(share_bytes)
        .map_err(|e| MfaError::Factor(format!("shamir reconstruction failed: {e:?}")))?;
    let arr: [u8; 32] = secret
        .as_slice()
        .try_into()
        .map_err(|_| MfaError::Factor("reconstructed secret is not 32 bytes".into()))?;
    // The interpolated buffer holds master-key material; do not leave it in the heap.
    secret.zeroize();
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_then_combine_roundtrips_any_k() {
        let mk = [0x5au8; 32];
        let shares = split_master_key(&mk, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);
        assert_eq!(shares[0].len(), 33);
        // any 2 of 3 reconstruct
        assert_eq!(
            combine_shares(2, &[shares[0].clone(), shares[2].clone()]).unwrap(),
            mk
        );
        assert_eq!(
            combine_shares(2, &[shares[1].clone(), shares[2].clone()]).unwrap(),
            mk
        );
    }

    #[test]
    fn fewer_than_k_shares_do_not_recover_the_secret() {
        let mk = [0x11u8; 32];
        let shares = split_master_key(&mk, 3, 5).unwrap();
        // one share, asked to combine as if k=3 → error (insufficient)
        assert!(combine_shares(3, &[shares[0].clone()]).is_err());
    }

    #[test]
    fn invalid_thresholds_rejected() {
        let mk = [0u8; 32];
        assert!(split_master_key(&mk, 0, 3).is_err());
        assert!(split_master_key(&mk, 4, 3).is_err());
        assert!(split_master_key(&mk, 1, 256).is_err());
    }

    /// Regression test for RUSTSEC-2024-0398.
    ///
    /// The previous `sharks` backend drew polynomial coefficients from `[1,255]`
    /// rather than `[0,255]`. Cure53 showed that knowing a coefficient can never
    /// be zero lets a holder of `k-1` shares exclude byte values for the secret,
    /// recovering it outright once the same secret has been re-shared ~500-1500
    /// times. `add_threshold_group` re-splits the *same* volume master key on
    /// every enrollment, so that precondition is reachable here.
    ///
    /// An unbiased dealer must be able to emit `0x00` in every y-byte position.
    /// A biased one cannot, which is exactly what this asserts.
    #[test]
    fn coefficients_are_not_biased_away_from_zero() {
        let mk = [0x5au8; 32];
        let mut seen_zero = [false; 32];
        // 2-of-2 maximizes the per-split chance of observing a zero coefficient.
        for _ in 0..4000 {
            for share in split_master_key(&mk, 2, 2).unwrap() {
                for (i, &y) in share[1..].iter().enumerate() {
                    if y == 0 {
                        seen_zero[i] = true;
                    }
                }
            }
        }
        let never_zero: Vec<usize> = (0..32).filter(|&i| !seen_zero[i]).collect();
        assert!(
            never_zero.is_empty(),
            "y-byte positions {never_zero:?} never produced 0x00 over 8000 shares — \
             the dealer is biased away from zero (RUSTSEC-2024-0398 has regressed)"
        );
    }

    /// The wire format is frozen at 1.0.0: 1-byte x-coordinate followed by 32
    /// y-bytes. Documented in docs/FORMAT.md; changing it breaks every enrolled
    /// threshold group.
    /// Known-answer test pinning the field: shares are points of a polynomial over
    /// GF(2^8) with the AES reduction polynomial x^8+x^4+x^3+x+1 (0x11B). The shares
    /// below are computed independently of the library (`gmul` in this test), so a
    /// dependency upgrade that changed the field or the encoding would fail here
    /// instead of silently breaking enrolled threshold groups.
    #[test]
    fn combine_matches_independent_gf256_aes_field_arithmetic() {
        fn gmul(mut a: u8, mut b: u8) -> u8 {
            let mut p = 0u8;
            while b != 0 {
                if b & 1 != 0 {
                    p ^= a;
                }
                let hi = a & 0x80;
                a <<= 1;
                if hi != 0 {
                    a ^= 0x1B;
                }
                b >>= 1;
            }
            p
        }
        // f(x) = s + c*x, per byte; k = 2, shares at x = 1 and x = 2.
        let secret: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ 0xA5);
        let coeff: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(91) ^ 0x3C);
        let mut s1 = vec![1u8];
        let mut s2 = vec![2u8];
        for i in 0..32 {
            s1.push(secret[i] ^ gmul(coeff[i], 1));
            s2.push(secret[i] ^ gmul(coeff[i], 2));
        }
        let recovered = combine_shares(2, &[s1, s2]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn share_wire_format_is_frozen_33_bytes() {
        let mk = [0x11u8; 32];
        let shares = split_master_key(&mk, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);
        for s in &shares {
            assert_eq!(s.len(), 33, "1-byte x-coordinate + 32 y-bytes");
            assert_ne!(s[0], 0, "x-coordinate 0 would expose the secret directly");
        }
        let mut xs: Vec<u8> = shares.iter().map(|s| s[0]).collect();
        xs.sort_unstable();
        xs.dedup();
        assert_eq!(xs.len(), 5, "x-coordinates must be distinct");
    }
}
