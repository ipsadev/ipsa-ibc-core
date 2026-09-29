use std::fmt;

use ics23::{
    commitment_proof::Proof, CommitmentProof, ExistenceProof, HashOp, InnerOp, LeafOp,
    NonExistenceProof,
};
use prost::Message;
use sha2::{Digest, Sha256};

use crate::smt::{
    key_index_from_hash, verify_membership, verify_non_membership, MembershipProof,
    NonMembershipProof, HASH_SIZE,
};

/// the protobuf message a proof is sent in.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MerkleProof {
    /// the proofs it carries; only the first is read.
    #[prost(message, repeated, tag = "1")]
    pub proofs: Vec<CommitmentProof>,
}

/// why proof bytes could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// the bytes are not a valid protobuf message.
    Wire(String),
    /// the message holds no proof.
    NoProof,
    /// a membership proof was expected.
    NotAnExistenceProof,
    /// a non-membership proof was expected.
    NotANonExistenceProof,
    /// the non-membership proof is missing the path it is checked with.
    MissingExistenceProof,
    /// a non-membership proof must carry an empty value.
    NonEmptyAbsentValue,
    /// a step of the path does not hold exactly one sibling.
    MalformedStep,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(reason) => write!(formatter, "MerkleProof: {reason}"),
            Self::NoProof => formatter.write_str("the MerkleProof holds no proof"),
            Self::NotAnExistenceProof => formatter.write_str("expected an existence proof"),
            Self::NotANonExistenceProof => formatter.write_str("expected a non-existence proof"),
            Self::MissingExistenceProof => {
                formatter.write_str("the non-existence proof has no existence proof on its left")
            }
            Self::NonEmptyAbsentValue => {
                formatter.write_str("an absence proof must carry an empty value")
            }
            Self::MalformedStep => {
                formatter.write_str("a path step is neither a left nor a right sibling")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// why a proof was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationError {
    /// the proof bytes could not be read.
    Decode(DecodeError),
    /// the proof is for another key.
    KeyMismatch,
    /// the proof is for another value.
    ValueMismatch,
    /// the proof does not lead to the root.
    RootMismatch,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => error.fmt(formatter),
            Self::KeyMismatch => formatter.write_str("the proof is for another key"),
            Self::ValueMismatch => formatter.write_str("the proof commits to another value"),
            Self::RootMismatch => formatter.write_str("the proof does not fold to the root"),
        }
    }
}

impl std::error::Error for VerificationError {}

impl From<DecodeError> for VerificationError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

/// the parts of a membership proof read from its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedMembershipProof {
    /// the key the proof is for.
    pub key: Vec<u8>,
    /// the value the proof commits to: `sha256` of the stored value.
    pub value: Vec<u8>,
    /// the sibling hash at each level, from the leaf up to the root.
    pub siblings: Vec<[u8; HASH_SIZE]>,
}

/// the parts of a non-membership proof read from its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedNonMembershipProof {
    /// the key the proof is for.
    pub key: Vec<u8>,
    /// the sibling hash at each level, from the empty slot up to the root.
    pub siblings: Vec<[u8; HASH_SIZE]>,
}

/// read a membership proof from its bytes.
pub fn decode_membership_proof(bytes: &[u8]) -> Result<DecodedMembershipProof, DecodeError> {
    let Proof::Exist(existence) = first_proof(bytes)? else {
        return Err(DecodeError::NotAnExistenceProof);
    };

    Ok(DecodedMembershipProof {
        siblings: siblings(&existence.path)?,
        key: existence.key,
        value: existence.value,
    })
}

/// read a non-membership proof from its bytes.
pub fn decode_non_membership_proof(bytes: &[u8]) -> Result<DecodedNonMembershipProof, DecodeError> {
    let Proof::Nonexist(absence) = first_proof(bytes)? else {
        return Err(DecodeError::NotANonExistenceProof);
    };
    let existence = absence.left.ok_or(DecodeError::MissingExistenceProof)?;

    if !existence.value.is_empty() {
        return Err(DecodeError::NonEmptyAbsentValue);
    }

    Ok(DecodedNonMembershipProof {
        key: absence.key,
        siblings: siblings(&existence.path)?,
    })
}

/// check proof bytes show `key` holding `value` under `root`.
///
/// these are the stellar light client's own checks.
pub fn verify_membership_proof(
    root: &[u8; HASH_SIZE],
    bytes: &[u8],
    key: &[u8],
    value: &[u8],
) -> Result<(), VerificationError> {
    let proof = decode_membership_proof(bytes)?;
    let value_hash: [u8; HASH_SIZE] = Sha256::digest(value).into();

    if proof.key != key {
        return Err(VerificationError::KeyMismatch);
    }

    if proof.value != value_hash {
        return Err(VerificationError::ValueMismatch);
    }

    if !verify_membership(root, key, value, &proof.siblings) {
        return Err(VerificationError::RootMismatch);
    }

    Ok(())
}

/// check proof bytes show `key` is absent under `root`.
pub fn verify_non_membership_proof(
    root: &[u8; HASH_SIZE],
    bytes: &[u8],
    key: &[u8],
) -> Result<(), VerificationError> {
    let proof = decode_non_membership_proof(bytes)?;

    if proof.key != key {
        return Err(VerificationError::KeyMismatch);
    }

    if !verify_non_membership(root, key, &proof.siblings) {
        return Err(VerificationError::RootMismatch);
    }

    Ok(())
}

fn first_proof(bytes: &[u8]) -> Result<Proof, DecodeError> {
    let merkle =
        MerkleProof::decode(bytes).map_err(|error| DecodeError::Wire(error.to_string()))?;

    merkle
        .proofs
        .into_iter()
        .next()
        .and_then(|commitment| commitment.proof)
        .ok_or(DecodeError::NoProof)
}

fn siblings(path: &[InnerOp]) -> Result<Vec<[u8; HASH_SIZE]>, DecodeError> {
    path.iter().map(sibling).collect()
}

fn sibling(step: &InnerOp) -> Result<[u8; HASH_SIZE], DecodeError> {
    let right_sibling = step.prefix == [0x01] && step.suffix.len() == HASH_SIZE;
    let left_sibling =
        step.suffix.is_empty() && step.prefix.len() == 1 + HASH_SIZE && step.prefix[0] == 0x01;

    let bytes = if right_sibling {
        &step.suffix[..]
    } else if left_sibling {
        &step.prefix[1..]
    } else {
        return Err(DecodeError::MalformedStep);
    };

    let mut sibling = [0u8; HASH_SIZE];

    sibling.copy_from_slice(bytes);

    Ok(sibling)
}

/// write a membership proof as bytes for the stellar light client.
pub fn serialize_membership_proof(proof: &MembershipProof) -> Vec<u8> {
    let existence = existence_proof(
        &proof.key,
        &proof.value_hash,
        &proof.siblings,
        key_index_from_hash(&proof.key_hash),
    );

    encode(Proof::Exist(existence))
}

/// write a non-membership proof as bytes for the stellar light client.
pub fn serialize_non_membership_proof(proof: &NonMembershipProof) -> Vec<u8> {
    let existence = existence_proof(
        &proof.key,
        &[],
        &proof.siblings,
        key_index_from_hash(&proof.key_hash),
    );

    encode(Proof::Nonexist(NonExistenceProof {
        key: proof.key.clone(),
        left: Some(existence),
        right: None,
    }))
}

fn encode(proof: Proof) -> Vec<u8> {
    MerkleProof {
        proofs: vec![CommitmentProof { proof: Some(proof) }],
    }
    .encode_to_vec()
}

fn existence_proof(
    key: &[u8],
    value: &[u8],
    siblings: &[[u8; HASH_SIZE]],
    index: u64,
) -> ExistenceProof {
    let mut path = Vec::with_capacity(siblings.len());
    let mut position = index;

    for sibling in siblings {
        path.push(inner_operation(sibling, position & 1 == 0));
        position >>= 1;
    }

    ExistenceProof {
        key: key.to_vec(),
        value: value.to_vec(),
        leaf: Some(LeafOp {
            hash: HashOp::Sha256 as i32,
            prehash_key: HashOp::NoHash as i32,
            prehash_value: HashOp::NoHash as i32,
            length: 0,
            prefix: Vec::new(),
        }),
        path,
    }
}

fn inner_operation(sibling: &[u8; HASH_SIZE], current_is_left: bool) -> InnerOp {
    if current_is_left {
        return InnerOp {
            hash: HashOp::Sha256 as i32,
            prefix: vec![0x01],
            suffix: sibling.to_vec(),
        };
    }

    let mut prefix = Vec::with_capacity(1 + HASH_SIZE);

    prefix.push(0x01);
    prefix.extend_from_slice(sibling);

    InnerOp {
        hash: HashOp::Sha256 as i32,
        prefix,
        suffix: Vec::new(),
    }
}
