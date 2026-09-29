use ics23::{
    commitment_proof::Proof, CommitmentProof, ExistenceProof, HashOp, InnerOp, LeafOp,
    NonExistenceProof,
};
use prost::Message;

use crate::smt::{key_index_from_hash, MembershipProof, NonMembershipProof, HASH_SIZE};

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MerkleProof {
    #[prost(message, repeated, tag = "1")]
    pub proofs: Vec<CommitmentProof>,
}

pub fn serialize_membership_proof(proof: &MembershipProof) -> Vec<u8> {
    let existence = existence_proof(
        &proof.key,
        &proof.value_hash,
        &proof.siblings,
        key_index_from_hash(&proof.key_hash),
    );

    encode(Proof::Exist(existence))
}

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
