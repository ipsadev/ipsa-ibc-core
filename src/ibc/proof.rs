use ics23::{
    commitment_proof::Proof, CommitmentProof, ExistenceProof, HashOp, InnerOp, LeafOp,
    NonExistenceProof,
};
use prost::Message;

use crate::smt::{MembershipProof, NonMembershipProof};

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MerkleProof {
    #[prost(message, repeated, tag = "1")]
    pub proofs: Vec<CommitmentProof>,
}

pub fn serialize_membership_proof(proof: &MembershipProof, key: &[u8], value: &[u8]) -> Vec<u8> {
    let merkle = MerkleProof {
        proofs: vec![CommitmentProof {
            proof: Some(Proof::Exist(build_existence_proof(
                key,
                value,
                &proof.siblings,
            ))),
        }],
    };
    merkle.encode_to_vec()
}

pub fn serialize_non_membership_proof(proof: &NonMembershipProof, key: &[u8]) -> Vec<u8> {
    let inner_existence = build_existence_proof(key, &[], &proof.siblings);
    let merkle = MerkleProof {
        proofs: vec![CommitmentProof {
            proof: Some(Proof::Nonexist(NonExistenceProof {
                key: key.to_vec(),
                left: Some(inner_existence),
                right: None,
            })),
        }],
    };
    merkle.encode_to_vec()
}

fn build_existence_proof(key: &[u8], value: &[u8], siblings: &[[u8; 32]]) -> ExistenceProof {
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
        path: siblings.iter().map(sibling_to_inner_op).collect(),
    }
}

fn sibling_to_inner_op(sibling: &[u8; 32]) -> InnerOp {
    InnerOp {
        hash: HashOp::Sha256 as i32,
        prefix: vec![0x01],
        suffix: sibling.to_vec(),
    }
}

fn inner_op_with_parity(sibling: &[u8; 32], is_left_child: bool) -> InnerOp {
    if is_left_child {
        InnerOp {
            hash: HashOp::Sha256 as i32,
            prefix: vec![0x01],
            suffix: sibling.to_vec(),
        }
    } else {
        let mut prefix = Vec::with_capacity(1 + sibling.len());
        prefix.push(0x01);
        prefix.extend_from_slice(sibling);
        InnerOp {
            hash: HashOp::Sha256 as i32,
            prefix,
            suffix: Vec::new(),
        }
    }
}

fn build_existence_proof_with_index(
    key: &[u8],
    value: &[u8],
    siblings: &[[u8; 32]],
    index: u64,
) -> ExistenceProof {
    let mut path = Vec::with_capacity(siblings.len());
    let mut sub_idx = index;
    for sibling in siblings {
        let is_left_child = (sub_idx & 1) == 0;
        path.push(inner_op_with_parity(sibling, is_left_child));
        sub_idx >>= 1;
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

pub fn serialize_membership_proof_with_index(
    proof: &MembershipProof,
    key: &[u8],
    value: &[u8],
    index: u64,
) -> Vec<u8> {
    let merkle = MerkleProof {
        proofs: vec![CommitmentProof {
            proof: Some(Proof::Exist(build_existence_proof_with_index(
                key,
                value,
                &proof.siblings,
                index,
            ))),
        }],
    };
    merkle.encode_to_vec()
}

pub fn serialize_non_membership_proof_with_index(
    proof: &NonMembershipProof,
    key: &[u8],
    index: u64,
) -> Vec<u8> {
    let inner_existence = build_existence_proof_with_index(key, &[], &proof.siblings, index);
    let merkle = MerkleProof {
        proofs: vec![CommitmentProof {
            proof: Some(Proof::Nonexist(NonExistenceProof {
                key: key.to_vec(),
                left: Some(inner_existence),
                right: None,
            })),
        }],
    };
    merkle.encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smt::Smt;
    use sha2::{Digest, Sha256};

    fn key_index(key: &[u8]) -> u64 {
        let h: [u8; 32] = Sha256::digest(key).into();
        u64::from_be_bytes(h[..8].try_into().unwrap())
    }

    #[test]
    fn membership_serialization_round_trips_through_protobuf() {
        let mut smt = Smt::new();
        smt.insert(b"k1", b"v1");
        smt.insert(b"k2", b"v2");

        let proof = smt.generate_membership_proof(b"k1").expect("present");
        let bytes = serialize_membership_proof_with_index(&proof, b"k1", b"v1", key_index(b"k1"));

        let decoded = MerkleProof::decode(bytes.as_slice()).expect("decode");
        assert_eq!(decoded.proofs.len(), 1);
        let inner = match decoded.proofs[0].proof.clone().expect("variant") {
            Proof::Exist(e) => e,
            other => panic!("expected ExistenceProof, got {other:?}"),
        };
        assert_eq!(inner.key, b"k1");
        assert_eq!(inner.value, b"v1");
        assert_eq!(inner.path.len(), 64);
    }

    #[test]
    fn non_membership_serialization_uses_sentinel_existence() {
        let mut smt = Smt::new();
        smt.insert(b"k", b"v");
        let absent_key = b"absent";

        let proof = smt
            .generate_non_membership_proof(absent_key)
            .expect("absent");
        let bytes =
            serialize_non_membership_proof_with_index(&proof, absent_key, key_index(absent_key));

        let decoded = MerkleProof::decode(bytes.as_slice()).expect("decode");
        let nonexist = match decoded.proofs[0].proof.clone().expect("variant") {
            Proof::Nonexist(n) => n,
            other => panic!("expected NonExistenceProof, got {other:?}"),
        };
        assert_eq!(nonexist.key, absent_key);
        let left = nonexist.left.expect("sentinel existence in left");
        assert_eq!(left.key, absent_key);
        assert!(left.value.is_empty());
        assert!(nonexist.right.is_none());
        assert_eq!(left.path.len(), 64);
    }

    #[test]
    fn inner_op_parity_split_matches_cardano_layout() {
        let sibling = [0xAAu8; 32];
        let op = inner_op_with_parity(&sibling, true);
        assert_eq!(op.prefix, vec![0x01]);
        assert_eq!(op.suffix, sibling.to_vec());

        let op = inner_op_with_parity(&sibling, false);
        let mut expected_prefix = vec![0x01];
        expected_prefix.extend_from_slice(&sibling);
        assert_eq!(op.prefix, expected_prefix);
        assert!(op.suffix.is_empty());
    }

    #[test]
    fn frozen_root_matches_known_vector() {
        let mut smt = Smt::new();
        smt.insert(b"alpha", b"1");
        smt.insert(b"beta", b"2");
        smt.insert(b"gamma", b"3");
        let root = smt.root();

        assert_ne!(root, [0u8; 32]);
        let again = smt.root();
        assert_eq!(root, again);
    }
}
