//! Canonical, deterministic AAD + policy encoding for the key-slot vault.
//!
//! Everything that enters an AEAD AAD or a MAC input MUST be a byte-exact,
//! order-stable encoding — NOT `serde_json` of a map (whose key order is not
//! guaranteed), which would produce intermittent unlock failures that pass a
//! happy-path test and fail in the field (advisor R3). All integers are
//! little-endian; variable-length fields are length-prefixed.

use super::policy::{Policy, PolicyEntry};
use super::types::{context, PayloadKind, SlotId, SlotType};

/// Deterministic AAD binding a slot payload to its identity within this vault.
///
/// Binds `vault_uuid ‖ slot_id ‖ slot_type ‖ share_gen ‖ payload_kind` so that a
/// wrapped payload cannot be:
/// - moved to a different vault (`vault_uuid`),
/// - relabelled to a different slot or factor kind (`slot_id`, `slot_type`),
/// - mixed with shares from a different threshold generation (`share_gen`), or
/// - reinterpreted (a Shamir share swapped in where a master key is expected, or
///   vice versa — `payload_kind`).
///
/// The full policy is deliberately NOT bound here (that would force re-wrapping
/// every slot on any policy edit, which is impossible for `Derived` factors
/// without their live input). Policy integrity is a separate MK-keyed MAC
/// ([`policy_mac`]); downgrade is additionally defeated because payload *content*
/// (master key vs. share) is fixed at enroll and cannot change without MK, and
/// the reconstructed MK is verified against `mk_commitment`.
pub fn slot_aad(
    vault_uuid: &[u8; 16],
    slot_id: SlotId,
    slot_type: SlotType,
    share_gen: u32,
    payload_kind: PayloadKind,
) -> Vec<u8> {
    let mut a = Vec::with_capacity(context::SLOT_WRAP.len() + 16 + 4 + 1 + 4 + 1);
    a.extend_from_slice(context::SLOT_WRAP);
    a.extend_from_slice(vault_uuid);
    a.extend_from_slice(&slot_id.to_le_bytes());
    a.push(slot_type.tag());
    a.extend_from_slice(&share_gen.to_le_bytes());
    a.push(payload_kind.tag());
    a
}

/// Deterministic canonical encoding of a [`Policy`] — the input to the policy
/// MAC. Member slot ids within a group are sorted (a group is a set), so the
/// encoding is stable under member reordering; top-level entry order is
/// preserved (it is the stored order, and reordering entries is a policy edit).
pub fn canonical_policy_bytes(policy: &Policy) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&(policy.entries.len() as u32).to_le_bytes());
    for e in &policy.entries {
        match e {
            PolicyEntry::Slot { slot_id } => {
                b.push(0u8);
                b.extend_from_slice(&slot_id.to_le_bytes());
            }
            PolicyEntry::Group {
                k,
                member_slot_ids,
                share_gen,
            } => {
                b.push(1u8);
                b.extend_from_slice(&k.to_le_bytes());
                let mut members = member_slot_ids.clone();
                members.sort_unstable();
                b.extend_from_slice(&(members.len() as u32).to_le_bytes());
                for m in members {
                    b.extend_from_slice(&m.to_le_bytes());
                }
                b.extend_from_slice(&share_gen.to_le_bytes());
            }
        }
    }
    b
}

/// The policy-integrity MAC: keyed BLAKE3 over the canonical policy bytes under a
/// key derived from MK. Rewriting the policy (a downgrade) without MK produces a
/// MAC mismatch, detected after MK recovery.
pub fn policy_mac(mk: &[u8; 32], policy: &Policy) -> [u8; 32] {
    let mac_key = blake3::derive_key(context::POLICY_MAC, mk);
    blake3::keyed_hash(&mac_key, &canonical_policy_bytes(policy)).into()
}

/// Commitment to MK for constant-time post-recovery verification (domain-separated
/// derivation, never the bare hash — no commitment-oracle).
pub fn mk_commitment(mk: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(context::MK_COMMITMENT, mk)
}
