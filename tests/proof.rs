use ics23::commitment_proof::Proof;
use ipsa_ibc_core::{
    proof::{serialize_membership_proof, serialize_non_membership_proof, MerkleProof},
    smt::{key_index, Smt, TREE_DEPTH},
};
use prost::Message;
use sha2::{Digest, Sha256};

const GOLDEN: &str = include_str!("fixtures/gateway-proofs-0.1.0-before-api-change.txt");

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|position| u8::from_str_radix(&text[position..position + 2], 16).unwrap())
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn golden_tree(size: usize) -> Smt {
    let mut tree = Smt::new();

    for position in 0..size {
        let key = format!("07-tendermint-0\x01{position:016}");
        let value = Sha256::digest(format!("commitment {position}"));

        tree.insert(key.as_bytes(), &value);
    }

    tree
}

fn inner_tag(bytes: &[u8]) -> u8 {
    assert_eq!(bytes[0], 0x0a, "MerkleProof.proofs is field 1");

    let mut position = 1;

    while bytes[position] & 0x80 != 0 {
        position += 1;
    }

    bytes[position + 1]
}

fn only_proof(bytes: &[u8]) -> Proof {
    let decoded = MerkleProof::decode(bytes).unwrap();

    assert_eq!(decoded.proofs.len(), 1);

    decoded.proofs[0].proof.clone().unwrap()
}

#[test]
fn the_new_api_writes_the_bytes_the_gateway_wrote_before() {
    let mut checked = 0;

    for line in GOLDEN.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        let [kind, size, key, root, expected] = fields[..] else {
            panic!("malformed fixture line: {line}");
        };
        let tree = golden_tree(size.parse().unwrap());
        let key = decode_hex(key);

        assert_eq!(encode_hex(&tree.root()), root, "root for tree of {size}");

        let bytes = match kind {
            "membership" => {
                serialize_membership_proof(&tree.generate_membership_proof(&key).unwrap())
            }
            "non-membership" => {
                serialize_non_membership_proof(&tree.generate_non_membership_proof(&key).unwrap())
            }
            other => panic!("unknown kind {other}"),
        };

        assert_eq!(encode_hex(&bytes), expected, "{kind} proof, tree of {size}");
        checked += 1;
    }

    assert_eq!(checked, 22);
}

#[test]
fn a_membership_proof_carries_the_value_hash_not_the_value() {
    let mut tree = Smt::new();

    tree.insert(b"key", b"value");

    let Proof::Exist(existence) = only_proof(&serialize_membership_proof(
        &tree.generate_membership_proof(b"key").unwrap(),
    )) else {
        panic!("expected an existence proof");
    };

    assert_eq!(existence.key, b"key");
    assert_eq!(existence.value, Sha256::digest(b"value").to_vec());
    assert_eq!(existence.path.len(), TREE_DEPTH);
}

#[test]
fn each_step_records_which_side_the_sibling_is_on() {
    let mut tree = Smt::new();

    tree.insert(b"k1", b"v1");
    tree.insert(b"k2", b"v2");

    let Proof::Exist(existence) = only_proof(&serialize_membership_proof(
        &tree.generate_membership_proof(b"k1").unwrap(),
    )) else {
        panic!("expected an existence proof");
    };

    let mut position = key_index(b"k1");

    for step in &existence.path {
        if position & 1 == 0 {
            assert_eq!(step.prefix, vec![0x01]);
            assert_eq!(step.suffix.len(), 32);
        } else {
            assert_eq!(step.prefix.len(), 33);
            assert_eq!(step.prefix[0], 0x01);
            assert!(step.suffix.is_empty());
        }
        position >>= 1;
    }
}

#[test]
fn a_non_membership_proof_is_the_key_folded_from_the_empty_leaf() {
    let mut tree = Smt::new();

    tree.insert(b"present", b"value");

    let bytes =
        serialize_non_membership_proof(&tree.generate_non_membership_proof(b"absent").unwrap());
    let Proof::Nonexist(absence) = only_proof(&bytes) else {
        panic!("expected a non-existence proof");
    };

    assert_eq!(absence.key, b"absent");
    assert!(absence.right.is_none());

    let left = absence.left.unwrap();

    assert_eq!(left.key, b"absent");
    assert!(left.value.is_empty());
    assert_eq!(left.path.len(), TREE_DEPTH);
}

#[test]
fn the_non_membership_tag_is_field_two() {
    let bytes =
        serialize_non_membership_proof(&Smt::new().generate_non_membership_proof(b"k").unwrap());

    assert_eq!(
        inner_tag(&bytes),
        0x12,
        "CommitmentProof.nonexist is field 2"
    );
}

#[test]
fn the_membership_tag_is_field_one() {
    let mut tree = Smt::new();

    tree.insert(b"k", b"v");

    let bytes = serialize_membership_proof(&tree.generate_membership_proof(b"k").unwrap());

    assert_eq!(inner_tag(&bytes), 0x0a, "CommitmentProof.exist is field 1");
}
