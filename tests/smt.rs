use ipsa_core::smt::{
    key_index, verify_membership, verify_non_membership, ProofError, Smt, EMPTY, TREE_DEPTH,
};

fn tree(entries: &[(&[u8], &[u8])]) -> Smt {
    let mut tree = Smt::new();

    for (key, value) in entries {
        tree.insert(key, value);
    }

    tree
}

#[test]
fn an_empty_tree_has_the_zero_root() {
    assert_eq!(Smt::new().root(), EMPTY);
}

#[test]
fn an_empty_value_is_stored_as_the_router_stores_it() {
    let mut tree = Smt::new();

    tree.insert(b"key", b"");

    assert_ne!(tree.root(), EMPTY);

    let proof = tree.generate_membership_proof(b"key").unwrap();

    assert!(
        !verify_membership(&tree.root(), &proof.key, b"", &proof.siblings),
        "an empty value is refused by the verifier, as the light client refuses it"
    );
}

#[test]
fn removing_a_key_restores_the_previous_root() {
    let mut tree = tree(&[(b"k1", b"v1")]);
    let before = tree.root();

    tree.insert(b"k2", b"v2");
    tree.remove(b"k2");

    assert_eq!(tree.root(), before);
}

#[test]
fn inserting_again_overwrites_the_value() {
    let mut tree = tree(&[(b"key", b"v1")]);
    let first = tree.root();

    tree.insert(b"key", b"v2");

    assert_ne!(tree.root(), first);

    tree.insert(b"key", b"v1");

    assert_eq!(tree.root(), first);
}

#[test]
fn a_membership_proof_carries_its_key_and_verifies() {
    let tree = tree(&[(b"k1", b"v1"), (b"k2", b"v2"), (b"k3", b"v3")]);
    let proof = tree.generate_membership_proof(b"k2").unwrap();

    assert_eq!(proof.key, b"k2");
    assert_eq!(proof.siblings.len(), TREE_DEPTH);
    assert!(verify_membership(
        &tree.root(),
        &proof.key,
        b"v2",
        &proof.siblings
    ));
}

#[test]
fn a_membership_proof_rejects_another_value_or_root() {
    let tree = tree(&[(b"key", b"value")]);
    let proof = tree.generate_membership_proof(b"key").unwrap();

    assert!(!verify_membership(
        &tree.root(),
        &proof.key,
        b"wrong",
        &proof.siblings
    ));
    assert!(!verify_membership(
        &[0xAA; 32],
        &proof.key,
        b"value",
        &proof.siblings
    ));
}

#[test]
fn a_membership_proof_rejects_a_substituted_key() {
    let tree = tree(&[(b"key", b"value")]);
    let mut proof = tree.generate_membership_proof(b"key").unwrap();

    proof.key = b"other".to_vec();

    assert!(!verify_membership(
        &tree.root(),
        &proof.key,
        b"value",
        &proof.siblings
    ));
}

#[test]
fn a_membership_proof_rejects_a_short_path() {
    let tree = tree(&[(b"key", b"value")]);
    let mut proof = tree.generate_membership_proof(b"key").unwrap();

    proof.siblings.pop();

    assert!(!verify_membership(
        &tree.root(),
        &proof.key,
        b"value",
        &proof.siblings
    ));
}

#[test]
fn an_absent_key_has_no_membership_proof() {
    assert_eq!(
        Smt::new().generate_membership_proof(b"absent"),
        Err(ProofError::KeyAbsent)
    );
}

#[test]
fn a_non_membership_proof_verifies_for_an_absent_key() {
    let tree = tree(&[(b"k1", b"v1"), (b"k2", b"v2")]);
    let proof = tree.generate_non_membership_proof(b"absent").unwrap();

    assert_eq!(proof.key, b"absent");
    assert!(verify_non_membership(
        &tree.root(),
        &proof.key,
        &proof.siblings
    ));
}

#[test]
fn a_present_key_has_no_non_membership_proof() {
    let tree = tree(&[(b"key", b"value")]);

    assert_eq!(
        tree.generate_non_membership_proof(b"key"),
        Err(ProofError::KeyPresent)
    );
}

#[test]
fn a_non_membership_proof_cannot_be_reused_for_a_present_key() {
    let tree = tree(&[(b"key", b"value")]);
    let mut proof = tree.generate_non_membership_proof(b"absent").unwrap();

    proof.key = b"key".to_vec();

    assert!(!verify_non_membership(
        &tree.root(),
        &proof.key,
        &proof.siblings
    ));
}

#[test]
fn an_empty_tree_proves_any_key_absent() {
    let tree = Smt::new();
    let proof = tree.generate_non_membership_proof(b"anything").unwrap();

    assert!(verify_non_membership(&EMPTY, &proof.key, &proof.siblings));
}

#[test]
fn a_stale_proof_fails_after_the_value_changes() {
    let mut tree = tree(&[(b"key", b"v1")]);
    let stale = tree.generate_membership_proof(b"key").unwrap();

    tree.insert(b"key", b"v2");

    assert!(!verify_membership(
        &tree.root(),
        &stale.key,
        b"v1",
        &stale.siblings
    ));

    let fresh = tree.generate_membership_proof(b"key").unwrap();

    assert!(verify_membership(
        &tree.root(),
        &fresh.key,
        b"v2",
        &fresh.siblings
    ));
}

#[test]
fn the_index_is_the_first_eight_bytes_of_the_key_hash() {
    assert_eq!(key_index(b"a"), 0xca97_8112_ca1b_bdca);
}
