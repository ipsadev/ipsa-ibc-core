use ics23::{commitment_proof::Proof, CommitmentProof, ExistenceProof, InnerOp, NonExistenceProof};
use ipsa_ibc_core::{
    proof::{
        decode_membership_proof, decode_non_membership_proof, serialize_membership_proof,
        serialize_non_membership_proof, verify_membership_proof, verify_non_membership_proof,
        DecodeError, MerkleProof, VerificationError,
    },
    smt::{Smt, TREE_DEPTH},
};
use prost::Message;
use sha2::{Digest, Sha256};

fn populated() -> Smt {
    let mut tree = Smt::new();

    for position in 0u8..16 {
        tree.insert(&[b'k', position], &[b'v', position]);
    }

    tree
}

fn encode(proof: Proof) -> Vec<u8> {
    MerkleProof {
        proofs: vec![CommitmentProof { proof: Some(proof) }],
    }
    .encode_to_vec()
}

fn existence(key: &[u8], value: &[u8], path: Vec<InnerOp>) -> ExistenceProof {
    ExistenceProof {
        key: key.to_vec(),
        value: value.to_vec(),
        leaf: None,
        path,
    }
}

fn right_sibling() -> InnerOp {
    InnerOp {
        hash: 1,
        prefix: vec![0x01],
        suffix: vec![0xaa; 32],
    }
}

#[test]
fn a_decoded_membership_proof_is_the_one_serialised() {
    let tree = populated();
    let proof = tree.generate_membership_proof(&[b'k', 4]).unwrap();
    let decoded = decode_membership_proof(&serialize_membership_proof(&proof)).unwrap();

    assert_eq!(decoded.key, proof.key);
    assert_eq!(decoded.value, proof.value_hash.to_vec());
    assert_eq!(decoded.siblings, proof.siblings);
}

#[test]
fn a_decoded_non_membership_proof_is_the_one_serialised() {
    let tree = populated();
    let proof = tree.generate_non_membership_proof(b"absent").unwrap();
    let decoded = decode_non_membership_proof(&serialize_non_membership_proof(&proof)).unwrap();

    assert_eq!(decoded.key, proof.key);
    assert_eq!(decoded.siblings, proof.siblings);
}

#[test]
fn every_membership_proof_the_tree_builds_verifies() {
    let tree = populated();
    let root = tree.root();

    for position in 0u8..16 {
        let key = [b'k', position];
        let bytes = serialize_membership_proof(&tree.generate_membership_proof(&key).unwrap());

        assert_eq!(
            verify_membership_proof(&root, &bytes, &key, &[b'v', position]),
            Ok(())
        );
    }
}

#[test]
fn every_non_membership_proof_the_tree_builds_verifies() {
    let tree = populated();
    let root = tree.root();

    for position in 100u8..116 {
        let key = [b'k', position];
        let bytes =
            serialize_non_membership_proof(&tree.generate_non_membership_proof(&key).unwrap());

        assert_eq!(verify_non_membership_proof(&root, &bytes, &key), Ok(()));
    }
}

#[test]
fn a_proof_for_another_key_is_refused() {
    let tree = populated();
    let bytes = serialize_membership_proof(&tree.generate_membership_proof(&[b'k', 1]).unwrap());

    assert_eq!(
        verify_membership_proof(&tree.root(), &bytes, &[b'k', 2], &[b'v', 2]),
        Err(VerificationError::KeyMismatch)
    );
}

#[test]
fn a_claimed_value_the_proof_does_not_commit_to_is_refused() {
    let tree = populated();
    let key = [b'k', 1];
    let bytes = serialize_membership_proof(&tree.generate_membership_proof(&key).unwrap());

    assert_eq!(
        verify_membership_proof(&tree.root(), &bytes, &key, b"another value"),
        Err(VerificationError::ValueMismatch)
    );
}

#[test]
fn a_forged_value_hash_is_refused_at_the_root() {
    let tree = populated();
    let key = [b'k', 1];
    let claimed = b"another value";
    let mut forged = tree.generate_membership_proof(&key).unwrap();

    forged.value_hash = Sha256::digest(claimed).into();

    assert_eq!(
        verify_membership_proof(
            &tree.root(),
            &serialize_membership_proof(&forged),
            &key,
            claimed
        ),
        Err(VerificationError::RootMismatch)
    );
}

#[test]
fn a_proof_against_another_root_is_refused() {
    let tree = populated();
    let key = [b'k', 1];
    let bytes = serialize_membership_proof(&tree.generate_membership_proof(&key).unwrap());

    assert_eq!(
        verify_membership_proof(&[0xbb; 32], &bytes, &key, &[b'v', 1]),
        Err(VerificationError::RootMismatch)
    );
}

#[test]
fn an_empty_value_cannot_be_proven() {
    let mut tree = Smt::new();

    tree.insert(b"key", b"");

    let bytes = serialize_membership_proof(&tree.generate_membership_proof(b"key").unwrap());

    assert_eq!(
        verify_membership_proof(&tree.root(), &bytes, b"key", b""),
        Err(VerificationError::RootMismatch)
    );
}

#[test]
fn an_absence_proof_for_a_present_key_is_refused() {
    let tree = populated();
    let key = [b'k', 3];
    let present = tree.generate_membership_proof(&key).unwrap();
    let bytes = encode(Proof::Nonexist(NonExistenceProof {
        key: key.to_vec(),
        left: Some(existence(
            &key,
            b"",
            decode_membership_proof(&serialize_membership_proof(&present))
                .unwrap()
                .siblings
                .iter()
                .map(|sibling| InnerOp {
                    hash: 1,
                    prefix: vec![0x01],
                    suffix: sibling.to_vec(),
                })
                .collect(),
        )),
        right: None,
    }));

    assert_eq!(
        verify_non_membership_proof(&tree.root(), &bytes, &key),
        Err(VerificationError::RootMismatch)
    );
}

#[test]
fn bytes_that_are_not_a_proof_are_refused() {
    assert!(matches!(
        decode_membership_proof(&[0xff, 0xff, 0xff]),
        Err(DecodeError::Wire(_))
    ));
}

#[test]
fn a_merkle_proof_holding_nothing_is_refused() {
    let empty = MerkleProof { proofs: Vec::new() }.encode_to_vec();

    assert_eq!(decode_membership_proof(&empty), Err(DecodeError::NoProof));
    assert_eq!(
        decode_non_membership_proof(&empty),
        Err(DecodeError::NoProof)
    );
}

#[test]
fn the_wrong_kind_of_proof_is_refused() {
    let tree = populated();
    let membership =
        serialize_membership_proof(&tree.generate_membership_proof(&[b'k', 1]).unwrap());
    let absence =
        serialize_non_membership_proof(&tree.generate_non_membership_proof(b"x").unwrap());

    assert_eq!(
        decode_non_membership_proof(&membership),
        Err(DecodeError::NotANonExistenceProof)
    );
    assert_eq!(
        decode_membership_proof(&absence),
        Err(DecodeError::NotAnExistenceProof)
    );
}

#[test]
fn an_absence_proof_without_its_path_is_refused() {
    let bytes = encode(Proof::Nonexist(NonExistenceProof {
        key: b"key".to_vec(),
        left: None,
        right: Some(existence(b"key", b"", vec![right_sibling(); TREE_DEPTH])),
    }));

    assert_eq!(
        decode_non_membership_proof(&bytes),
        Err(DecodeError::MissingExistenceProof)
    );
}

#[test]
fn an_absence_proof_carrying_a_value_is_refused() {
    let bytes = encode(Proof::Nonexist(NonExistenceProof {
        key: b"key".to_vec(),
        left: Some(existence(
            b"key",
            b"value",
            vec![right_sibling(); TREE_DEPTH],
        )),
        right: None,
    }));

    assert_eq!(
        decode_non_membership_proof(&bytes),
        Err(DecodeError::NonEmptyAbsentValue)
    );
}

#[test]
fn a_step_that_is_neither_side_is_refused() {
    let mut path = vec![right_sibling(); TREE_DEPTH];

    path[10] = InnerOp {
        hash: 1,
        prefix: vec![0x01, 0x02],
        suffix: vec![0xaa; 32],
    };

    let bytes = encode(Proof::Exist(existence(b"key", &[0; 32], path)));

    assert_eq!(
        decode_membership_proof(&bytes),
        Err(DecodeError::MalformedStep)
    );
}

#[test]
fn a_short_path_decodes_but_never_verifies() {
    let tree = populated();
    let key = [b'k', 1];
    let proof = tree.generate_membership_proof(&key).unwrap();
    let mut path: Vec<InnerOp> = proof
        .siblings
        .iter()
        .map(|sibling| InnerOp {
            hash: 1,
            prefix: vec![0x01],
            suffix: sibling.to_vec(),
        })
        .collect();

    path.pop();

    let bytes = encode(Proof::Exist(existence(&key, &proof.value_hash, path)));

    assert_eq!(
        decode_membership_proof(&bytes).unwrap().siblings.len(),
        TREE_DEPTH - 1
    );
    assert_eq!(
        verify_membership_proof(&tree.root(), &bytes, &key, &[b'v', 1]),
        Err(VerificationError::RootMismatch)
    );
}
