//! Conditional cloud WAL chain — present ONLY in the opt-in cloud-durable flush
//! mode (P1.7/P1.7a), which is NOT yet implemented: the shipped default barrier
//! is the local staging fsync (D8, [`crate::staging`]). This module stays empty
//! until `DurabilityMode::Cloud` lands; nothing else references it.
