//! the ibc pieces that stellar and its counterparty must compute the same way.
//!
//! - [`commitment`]: where a packet, receipt or acknowledgement lives, and the hash stored there.
//! - [`smt`]: the sparse merkle tree that folds that state into one root.
//! - [`proof`]: how one entry of the tree is proven, written and checked.

#![warn(missing_docs)]

/// ibc v2 commitment paths and hashes, as `ICS24Host.sol` defines them.
pub mod commitment;
/// write, read and check proofs in the format the stellar light client verifies.
pub mod proof;
/// the 64-level sparse merkle tree the stellar ibc router keeps.
pub mod smt;
