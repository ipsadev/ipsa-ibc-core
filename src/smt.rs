use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use sha2::{Digest, Sha256};

/// how many levels the tree has, and so how many siblings a proof carries.
pub const TREE_DEPTH: usize = 64;
/// the length of every hash in the tree.
pub const HASH_SIZE: usize = 32;
/// the hash of an empty subtree, and the root of an empty tree.
pub const EMPTY: [u8; HASH_SIZE] = [0u8; HASH_SIZE];

/// why a proof could not be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofError {
    /// the key is not in the tree, so it cannot be proven present.
    KeyAbsent,
    /// the key is in the tree, so it cannot be proven absent.
    KeyPresent,
    /// another key sits at this key's position, so neither proof exists.
    IndexTakenByAnotherKey,
}

impl fmt::Display for ProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::KeyAbsent => "the key is not in the tree",
            Self::KeyPresent => "the key is in the tree",
            Self::IndexTakenByAnotherKey => {
                "another key occupies this key's index, so neither proof exists"
            }
        };

        formatter.write_str(reason)
    }
}

impl std::error::Error for ProofError {}

/// proof that a key is in the tree with a given value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipProof {
    /// the key being proven.
    pub key: Vec<u8>,
    /// `sha256` of the key.
    pub key_hash: [u8; HASH_SIZE],
    /// `sha256` of the value stored under the key.
    pub value_hash: [u8; HASH_SIZE],
    /// the sibling hash at each level, from the leaf up to the root.
    pub siblings: Vec<[u8; HASH_SIZE]>,
}

/// proof that a key is not in the tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonMembershipProof {
    /// the key being proven absent.
    pub key: Vec<u8>,
    /// `sha256` of the key.
    pub key_hash: [u8; HASH_SIZE],
    /// the sibling hash at each level, from the empty slot up to the root.
    pub siblings: Vec<[u8; HASH_SIZE]>,
}

/// a sparse merkle tree, kept the same way as the stellar ibc router keeps it.
///
/// a key's position is the first 8 bytes of `sha256(key)`.
#[derive(Default)]
pub struct Smt {
    leaves: BTreeMap<u64, ([u8; HASH_SIZE], [u8; HASH_SIZE])>,
}

impl Smt {
    /// an empty tree.
    pub fn new() -> Self {
        Self::default()
    }

    /// store a value under a key, replacing any value already there.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) {
        let key_hash = sha256(key);
        let value_hash = sha256(value);

        self.leaves
            .insert(key_index_from_hash(&key_hash), (key_hash, value_hash));
    }

    /// take a key out of the tree.
    pub fn remove(&mut self, key: &[u8]) {
        self.leaves.remove(&key_index(key));
    }

    /// the hash of the whole tree.
    pub fn root(&self) -> [u8; HASH_SIZE] {
        if self.leaves.is_empty() {
            return EMPTY;
        }

        let levels = self.materialize_levels();

        *levels[TREE_DEPTH].get(&0).unwrap_or(&EMPTY)
    }

    /// prove that a key is in the tree.
    pub fn generate_membership_proof(&self, key: &[u8]) -> Result<MembershipProof, ProofError> {
        let key_hash = sha256(key);
        let index = key_index_from_hash(&key_hash);

        let Some(&(stored_key_hash, stored_value_hash)) = self.leaves.get(&index) else {
            return Err(ProofError::KeyAbsent);
        };

        if stored_key_hash != key_hash {
            return Err(ProofError::IndexTakenByAnotherKey);
        }

        Ok(MembershipProof {
            key: key.to_vec(),
            key_hash,
            value_hash: stored_value_hash,
            siblings: self.siblings_for(index),
        })
    }

    /// prove that a key is not in the tree.
    pub fn generate_non_membership_proof(
        &self,
        key: &[u8],
    ) -> Result<NonMembershipProof, ProofError> {
        let key_hash = sha256(key);
        let index = key_index_from_hash(&key_hash);

        match self.leaves.get(&index) {
            Some((stored_key_hash, _)) if *stored_key_hash == key_hash => {
                Err(ProofError::KeyPresent)
            }
            Some(_) => Err(ProofError::IndexTakenByAnotherKey),
            None => Ok(NonMembershipProof {
                key: key.to_vec(),
                key_hash,
                siblings: self.siblings_for(index),
            }),
        }
    }

    fn materialize_levels(&self) -> Vec<BTreeMap<u64, [u8; HASH_SIZE]>> {
        let mut levels: Vec<BTreeMap<u64, [u8; HASH_SIZE]>> =
            (0..=TREE_DEPTH).map(|_| BTreeMap::new()).collect();

        for (&index, &(key_hash, value_hash)) in &self.leaves {
            levels[0].insert(index, leaf_hash(key_hash, value_hash));
        }

        for height in 1..=TREE_DEPTH {
            let parents: BTreeSet<u64> =
                levels[height - 1].keys().map(|index| index >> 1).collect();

            for parent in parents {
                let left_index = parent << 1;
                let right_index = left_index | 1;
                let left = *levels[height - 1].get(&left_index).unwrap_or(&EMPTY);
                let right = *levels[height - 1].get(&right_index).unwrap_or(&EMPTY);
                let node = inner_hash(left, right);

                if node != EMPTY {
                    levels[height].insert(parent, node);
                }
            }
        }

        levels
    }

    fn siblings_for(&self, index: u64) -> Vec<[u8; HASH_SIZE]> {
        let levels = self.materialize_levels();
        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        let mut position = index;

        for level in levels.iter().take(TREE_DEPTH) {
            siblings.push(*level.get(&(position ^ 1)).unwrap_or(&EMPTY));
            position >>= 1;
        }

        siblings
    }
}

/// check that `siblings` lead from `key` and `value` to `root`.
///
/// an empty value is never accepted.
pub fn verify_membership(
    root: &[u8; HASH_SIZE],
    key: &[u8],
    value: &[u8],
    siblings: &[[u8; HASH_SIZE]],
) -> bool {
    if value.is_empty() || siblings.len() != TREE_DEPTH {
        return false;
    }

    let leaf = leaf_hash(sha256(key), sha256(value));

    fold_siblings(key_index(key), leaf, siblings) == *root
}

/// check that `siblings` lead from an empty slot at `key` to `root`.
pub fn verify_non_membership(
    root: &[u8; HASH_SIZE],
    key: &[u8],
    siblings: &[[u8; HASH_SIZE]],
) -> bool {
    if siblings.len() != TREE_DEPTH {
        return false;
    }

    fold_siblings(key_index(key), EMPTY, siblings) == *root
}

/// a key's position in the tree.
pub fn key_index(key: &[u8]) -> u64 {
    key_index_from_hash(&sha256(key))
}

/// a key's position in the tree, from its `sha256`.
pub fn key_index_from_hash(key_hash: &[u8; HASH_SIZE]) -> u64 {
    let mut prefix = [0u8; 8];

    prefix.copy_from_slice(&key_hash[..8]);

    u64::from_be_bytes(prefix)
}

fn sha256(data: &[u8]) -> [u8; HASH_SIZE] {
    Sha256::digest(data).into()
}

fn leaf_hash(key_hash: [u8; HASH_SIZE], value_hash: [u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();

    hasher.update([0x00]);
    hasher.update(key_hash);
    hasher.update(value_hash);

    hasher.finalize().into()
}

fn inner_hash(left: [u8; HASH_SIZE], right: [u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    if left == EMPTY && right == EMPTY {
        return EMPTY;
    }

    let mut hasher = Sha256::new();

    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);

    hasher.finalize().into()
}

fn fold_siblings(
    index: u64,
    leaf: [u8; HASH_SIZE],
    siblings: &[[u8; HASH_SIZE]],
) -> [u8; HASH_SIZE] {
    let mut current = leaf;
    let mut position = index;

    for sibling in siblings {
        current = if position & 1 == 0 {
            inner_hash(current, *sibling)
        } else {
            inner_hash(*sibling, current)
        };
        position >>= 1;
    }

    current
}
