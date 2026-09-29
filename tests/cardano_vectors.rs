use ipsa_core::smt::{Smt, EMPTY, HASH_SIZE, TREE_DEPTH};

fn hex32(s: &str) -> [u8; HASH_SIZE] {
    assert_eq!(s.len(), 64, "expected 64 hex chars, got {}", s.len());
    let mut out = [0u8; HASH_SIZE];
    for i in 0..HASH_SIZE {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .unwrap_or_else(|_| panic!("bad hex {s:?}"));
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn assert_sibling_layout(label: &str, siblings: &[[u8; HASH_SIZE]], non_zero: &[(usize, &str)]) {
    assert_eq!(
        siblings.len(),
        TREE_DEPTH,
        "{label}: expected {TREE_DEPTH} siblings",
    );

    let want: std::collections::HashMap<usize, [u8; HASH_SIZE]> =
        non_zero.iter().map(|(i, h)| (*i, hex32(h))).collect();

    for (i, actual) in siblings.iter().enumerate() {
        let expected = want.get(&i).copied().unwrap_or(EMPTY);
        assert_eq!(
            *actual,
            expected,
            "{label}: sibling[{i}] mismatch\n  rust   : {}\n  cardano: {}",
            hex(actual),
            hex(&expected),
        );
    }
}

#[test]
fn single_leaf_membership_matches_cardano() {
    let mut smt = Smt::new();
    smt.insert(b"a", &[0x01]);

    assert_eq!(
        smt.root(),
        hex32("85690e9fa0e51e6150d058db755d4a912cdabf584b27d15434a8afe61b619f24"),
        "single_leaf_membership root mismatch",
    );

    let proof = smt.generate_membership_proof(b"a").expect("present");
    assert_sibling_layout("single_leaf_membership/a", &proof.siblings, &[]);
}

#[test]
fn two_leaf_membership_matches_cardano() {
    let mut smt = Smt::new();
    smt.insert(b"a", &[0x01]);
    smt.insert(b"b", &[0x02]);

    assert_eq!(
        smt.root(),
        hex32("03fb13fc919c662a0822d832c90345055da830e1cc91072a1bcd83757a2d2fa3"),
        "two_leaf_membership root mismatch",
    );

    let proof_a = smt.generate_membership_proof(b"a").expect("present");
    assert_sibling_layout(
        "two_leaf_membership/a",
        &proof_a.siblings,
        &[(
            63,
            "215155b0125720cea3da7e3c0a61386f7e441ec6069ace9e5eb6ae840d9ea385",
        )],
    );

    let proof_b = smt.generate_membership_proof(b"b").expect("present");
    assert_sibling_layout(
        "two_leaf_membership/b",
        &proof_b.siblings,
        &[(
            63,
            "68648e2f65bc1ef21eece768b978098cbfe19d411d5f4bd52168fef8b84ece94",
        )],
    );
}

#[test]
fn three_leaf_membership_matches_cardano() {
    let mut smt = Smt::new();
    smt.insert(b"a", &[0x01]);
    smt.insert(b"b", &[0x02]);
    smt.insert(b"c", &[0x03]);

    assert_eq!(
        smt.root(),
        hex32("6bd45fec4a9bc495cfd2d3290a82fc247a7d93337068da62af90fc509d93f87c"),
        "three_leaf_membership root mismatch",
    );

    let proof_a = smt.generate_membership_proof(b"a").expect("present");
    assert_sibling_layout(
        "three_leaf_membership/a",
        &proof_a.siblings,
        &[(
            63,
            "e2c6348574256ac8cbde08a5142ef9075b08da167d05ffa3e1513870daa7741d",
        )],
    );

    let proof_b = smt.generate_membership_proof(b"b").expect("present");
    assert_sibling_layout(
        "three_leaf_membership/b",
        &proof_b.siblings,
        &[
            (
                60,
                "ff5de0137786d33f0cb119abd8b47ac47b4710a07be9170ba5760bd42e50d951",
            ),
            (
                63,
                "68648e2f65bc1ef21eece768b978098cbfe19d411d5f4bd52168fef8b84ece94",
            ),
        ],
    );

    let proof_c = smt.generate_membership_proof(b"c").expect("present");
    assert_sibling_layout(
        "three_leaf_membership/c",
        &proof_c.siblings,
        &[
            (
                60,
                "bd5863cfb78b54a5d5a62161703a49602b8c18b52affc4faca8a2c7306075655",
            ),
            (
                63,
                "68648e2f65bc1ef21eece768b978098cbfe19d411d5f4bd52168fef8b84ece94",
            ),
        ],
    );
}

#[test]
fn absence_single_leaf_matches_cardano() {
    let mut smt = Smt::new();
    smt.insert(b"present", &hex32_to_bytes("deadbeef"));

    assert_eq!(
        smt.root(),
        hex32("ca3768566d33243b3f60cb61fa98b308af967829d19833b58a988a5acd0ba348"),
        "absence_single_leaf root mismatch",
    );

    let proof = smt
        .generate_non_membership_proof(b"absent")
        .expect("absent");
    assert_sibling_layout(
        "absence_single_leaf/absent",
        &proof.siblings,
        &[(
            60,
            "a2faed5a56f4b35d2b4519980d2f9c0dbe05e8b3b47234f5686e77e6ef7a81c1",
        )],
    );
}

#[test]
fn multi_leaf_with_absence_matches_cardano() {
    let mut smt = Smt::new();
    smt.insert(b"alpha", &[0x01]);
    smt.insert(b"beta", &[0x02]);
    smt.insert(b"gamma", &[0x03]);
    smt.insert(b"delta", &[0x04]);
    smt.insert(b"epsilon", &[0x05]);
    smt.insert(b"zeta", &[0x06]);
    smt.insert(b"eta", &[0x07]);
    smt.insert(b"theta", &[0x08]);
    smt.insert(b"iota", &[0x09]);
    smt.insert(b"kappa", &[0x0a]);

    assert_eq!(
        smt.root(),
        hex32("8ac9c9d4785f2180eea4ef34532cf555fd18ffed4932ad9bc7b735c0e5b61b4b"),
        "multi_leaf_with_absence root mismatch",
    );

    let proof_alpha = smt.generate_membership_proof(b"alpha").expect("present");
    assert_sibling_layout(
        "multi_leaf_with_absence/alpha",
        &proof_alpha.siblings,
        &[
            (
                60,
                "d200bb2414c93599584ac07482dbc13cd141f721a58420cedbeed117dbff454b",
            ),
            (
                61,
                "c991061bfda8004681899a6c278f46d040ee3ca85165621da3fb4aa1e598fa93",
            ),
            (
                62,
                "4e232e9f39bcbbcb97b5d7f863aafdf0b75124bdba6cc76da525e921d0b35d77",
            ),
            (
                63,
                "fbf8c19cc263d87e8b70f868f902d7f76f73e5d00e6ae156a390b50c9e740204",
            ),
        ],
    );

    let proof_theta = smt.generate_membership_proof(b"theta").expect("present");
    assert_sibling_layout(
        "multi_leaf_with_absence/theta",
        &proof_theta.siblings,
        &[
            (
                56,
                "448b2048de792c140c4cfa05714b5a4369f946487674ed8788eae81e9337f0eb",
            ),
            (
                60,
                "fd182b6cf5cf440979b7e93bb1774ff54e8f9ff282b18a1a70a411277854aaad",
            ),
            (
                61,
                "c991061bfda8004681899a6c278f46d040ee3ca85165621da3fb4aa1e598fa93",
            ),
            (
                62,
                "4e232e9f39bcbbcb97b5d7f863aafdf0b75124bdba6cc76da525e921d0b35d77",
            ),
            (
                63,
                "fbf8c19cc263d87e8b70f868f902d7f76f73e5d00e6ae156a390b50c9e740204",
            ),
        ],
    );

    let proof_lambda = smt
        .generate_non_membership_proof(b"lambda")
        .expect("absent");
    assert_sibling_layout(
        "multi_leaf_with_absence/lambda",
        &proof_lambda.siblings,
        &[
            (
                59,
                "08cabf13c64e097d1f9fd0c40971b90d93c394332b072c017cea739dd2eb6252",
            ),
            (
                60,
                "2e90238210c6ddb7f1d60e9959e395d656f5f07a8081b7a7148f8076f3086947",
            ),
            (
                61,
                "54497050df9a77bffa1341acdecd8e63101aff27cbbfdea4a4f461c0717fcc1f",
            ),
            (
                63,
                "915d79b33e765a483d270edb290442549b17befc63e4665bfa4d75e0c37d5873",
            ),
        ],
    );
}

fn hex32_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
