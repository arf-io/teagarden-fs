//! Crash recovery (P1.11) — implemented on the device itself, not here: see
//! [`crate::device::TeaGardenDevice::open`] (same-machine: superblock + catalog +
//! staging replay, unconfirmed-segment re-framing) and
//! [`crate::device::TeaGardenDevice::recover_from_head`] (fresh-machine: rebuild
//! from the cloud `DeviceHead` at the barrier-consistent watermark). This module
//! is reserved for the P3.2 head-discovery/pinning bootstrap.
