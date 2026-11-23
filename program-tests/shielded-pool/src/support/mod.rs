//! Shared shielded-pool test fixtures and backend helpers.
//!
//! - [`runtime`]: LiteSVM setup and account sizing.
//! - [`fixtures`]: initialized pool environments and builders.
//! - [`transact`]: transact fixtures and tree helpers.
//! - [`cache`]: a transact that spends from a cache instead of the state tree.
//! - [`merge`]: real merge proofs at every supported shape.
//! - [`ring`]: real ring transact proofs on both policy-ring rails.
//! - [`localnet`]: Solana RPC and indexing helpers.
//! - [`mollusk`]: Mollusk snapshot fixtures.
//! - [`forester`]: local-validator nullifier-tree driver.
//! - [`transfer_fee`]: Token-2022 transfer-fee mint fixtures.

pub mod cache;
pub mod fixtures;
pub mod merge;
pub mod mollusk;
pub mod ring;
pub mod runtime;
pub mod transact;
pub mod transfer_fee;

#[cfg(feature = "localnet")]
pub mod forester;
#[cfg(feature = "localnet")]
pub mod localnet;
