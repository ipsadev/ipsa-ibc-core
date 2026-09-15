use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const TREE_DEPTH: usize = 64;
const HASH_SIZE: usize = 32;
const EMPTY: [u8; HASH_SIZE] = [0u8; HASH_SIZE];

pub struct Smt {
    leaves: BTreeMap<u64, ([u8; HASH_SIZE], [u8; HASH_SIZE])>,
}

impl Default for Smt {
    fn default() -> Self {
        Self::new()
    }
}

impl Smt {
    pub fn new() -> Self {
        Self {
            leaves: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, key: &[u8], value: &[u8]) {
        if value.is_empty() {
            self.remove(key);
            return;
        }
        let key_hash = sha256(key);
        let value_hash = sha256(value);
        let idx = key_index_from_hash(&key_hash);
        self.leaves.insert(idx, (key_hash, value_hash));
    }

    pub fn update(&mut self, key: &[u8], value: &[u8]) {
        self.insert(key, value);
    }

    pub fn remove(&mut self, key: &[u8]) {
        let idx = key_index(key);
        self.leaves.remove(&idx);
    }

    pub fn root(&self) -> [u8; HASH_SIZE] {
        if self.leaves.is_empty() {
            return EMPTY;
        }
        let levels = self.materialize_levels();
        *levels[TREE_DEPTH].get(&0).unwrap_or(&EMPTY)
    }

    pub fn generate_membership_proof(&self, key: &[u8]) -> Option<MembershipProof> {
        let key_hash = sha256(key);
        let idx = key_index_from_hash(&key_hash);
        let (stored_kh, stored_vh) = *self.leaves.get(&idx)?;
        if stored_kh != key_hash {
            return None;
        }
        Some(MembershipProof {
            key_hash,
            value_hash: stored_vh,
            siblings: self.siblings_for(idx),
        })
    }

    pub fn generate_non_membership_proof(&self, key: &[u8]) -> Option<NonMembershipProof> {
        let key_hash = sha256(key);
        let idx = key_index_from_hash(&key_hash);
        if let Some((stored_kh, _)) = self.leaves.get(&idx) {
            if *stored_kh == key_hash {
                return None;
            }

            return None;
        }
        Some(NonMembershipProof {
            key_hash,
            siblings: self.siblings_for(idx),
        })
    }

    pub fn verify_membership(
        root: &[u8; HASH_SIZE],
        proof: &MembershipProof,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        if value.is_empty() {
            return false;
        }
        let key_hash = sha256(key);
        if key_hash != proof.key_hash {
            return false;
        }
        let value_hash = sha256(value);
        if value_hash != proof.value_hash {
            return false;
        }
        if proof.siblings.len() != TREE_DEPTH {
            return false;
        }
        let idx = key_index_from_hash(&key_hash);
        let computed = fold_siblings(idx, leaf_hash(key_hash, value_hash), &proof.siblings);
        computed == *root
    }

    pub fn verify_non_membership(
        root: &[u8; HASH_SIZE],
        proof: &NonMembershipProof,
        key: &[u8],
    ) -> bool {
        let key_hash = sha256(key);
        if key_hash != proof.key_hash {
            return false;
        }
        if proof.siblings.len() != TREE_DEPTH {
            return false;
        }
        let idx = key_index_from_hash(&key_hash);
        let computed = fold_siblings(idx, EMPTY, &proof.siblings);
        computed == *root
    }

    fn materialize_levels(&self) -> Vec<BTreeMap<u64, [u8; HASH_SIZE]>> {
        let mut levels: Vec<BTreeMap<u64, [u8; HASH_SIZE]>> =
            (0..=TREE_DEPTH).map(|_| BTreeMap::new()).collect();

        for (&idx, &(kh, vh)) in &self.leaves {
            levels[0].insert(idx, leaf_hash(kh, vh));
        }

        for h in 1..=TREE_DEPTH {
            let parents: BTreeSet<u64> = levels[h - 1].keys().map(|i| i >> 1).collect();
            for pidx in parents {
                let left_idx = pidx << 1;
                let right_idx = left_idx | 1;
                let left = *levels[h - 1].get(&left_idx).unwrap_or(&EMPTY);
                let right = *levels[h - 1].get(&right_idx).unwrap_or(&EMPTY);
                let p = inner_hash(left, right);
                if p != EMPTY {
                    levels[h].insert(pidx, p);
                }
            }
        }

        levels
    }

    fn siblings_for(&self, idx: u64) -> Vec<[u8; HASH_SIZE]> {
        let levels = self.materialize_levels();
        let mut out = Vec::with_capacity(TREE_DEPTH);
        let mut i = idx;
        for level in levels.iter().take(TREE_DEPTH) {
            let sibling_idx = i ^ 1;
            out.push(*level.get(&sibling_idx).unwrap_or(&EMPTY));
            i >>= 1;
        }
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipProof {
    pub key_hash: [u8; HASH_SIZE],
    pub value_hash: [u8; HASH_SIZE],
    pub siblings: Vec<[u8; HASH_SIZE]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonMembershipProof {
    pub key_hash: [u8; HASH_SIZE],
    pub siblings: Vec<[u8; HASH_SIZE]>,
}

fn sha256(data: &[u8]) -> [u8; HASH_SIZE] {
    Sha256::digest(data).into()
}

fn key_index(key: &[u8]) -> u64 {
    key_index_from_hash(&sha256(key))
}

fn key_index_from_hash(key_hash: &[u8; HASH_SIZE]) -> u64 {
    u64::from_be_bytes(key_hash[..8].try_into().expect("sha256 has 32 bytes"))
}

fn leaf_hash(key_hash: [u8; HASH_SIZE], value_hash: [u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(key_hash);
    h.update(value_hash);
    h.finalize().into()
}

fn inner_hash(left: [u8; HASH_SIZE], right: [u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    if left == EMPTY && right == EMPTY {
        return EMPTY;
    }
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn fold_siblings(idx: u64, leaf: [u8; HASH_SIZE], siblings: &[[u8; HASH_SIZE]]) -> [u8; HASH_SIZE] {
    let mut current = leaf;
    let mut sub_idx = idx;
    for sibling in siblings {
        current = if sub_idx & 1 == 0 {
            inner_hash(current, *sibling)
        } else {
            inner_hash(*sibling, current)
        };
        sub_idx >>= 1;
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_is_zeros() {
        assert_eq!(Smt::new().root(), EMPTY);
    }

    #[test]
    fn empty_value_is_treated_as_remove() {
        let mut smt = Smt::new();
        smt.insert(b"k", b"v");
        let with_v = smt.root();
        smt.insert(b"k", b"");
        assert_eq!(smt.root(), EMPTY);
        smt.insert(b"k", b"v");
        assert_eq!(smt.root(), with_v);
    }

    #[test]
    fn insert_remove_restores_root() {
        let mut smt = Smt::new();
        smt.insert(b"k1", b"v1");
        let root_before = smt.root();
        smt.insert(b"k2", b"v2");
        smt.remove(b"k2");
        assert_eq!(smt.root(), root_before);
    }

    #[test]
    fn two_entries_root_differs_from_single() {
        let mut smt = Smt::new();
        smt.insert(b"k1", b"v1");
        let r1 = smt.root();
        smt.insert(b"k2", b"v2");
        let r2 = smt.root();
        assert_ne!(r1, r2);
    }

    #[test]
    fn update_changes_root_and_overwrites_value() {
        let mut smt = Smt::new();
        smt.insert(b"k", b"v1");
        let root_v1 = smt.root();

        smt.update(b"k", b"v2");
        let root_v2 = smt.root();
        assert_ne!(root_v1, root_v2);

        smt.update(b"k", b"v1");
        assert_eq!(smt.root(), root_v1);
    }

    #[test]
    fn membership_proof_round_trips_for_present_key() {
        let mut smt = Smt::new();
        smt.insert(b"k1", b"v1");
        smt.insert(b"k2", b"v2");
        smt.insert(b"k3", b"v3");

        let root = smt.root();
        let proof = smt.generate_membership_proof(b"k2").expect("present");
        assert_eq!(proof.siblings.len(), TREE_DEPTH);
        assert!(Smt::verify_membership(&root, &proof, b"k2", b"v2"));
    }

    #[test]
    fn membership_proof_rejects_wrong_value() {
        let mut smt = Smt::new();
        smt.insert(b"k", b"v");
        let root = smt.root();
        let proof = smt.generate_membership_proof(b"k").expect("present");
        assert!(!Smt::verify_membership(&root, &proof, b"k", b"wrong"));
    }

    #[test]
    fn membership_proof_rejects_wrong_root() {
        let mut smt = Smt::new();
        smt.insert(b"k", b"v");
        let proof = smt.generate_membership_proof(b"k").expect("present");
        let bogus_root = [0xAAu8; HASH_SIZE];
        assert!(!Smt::verify_membership(&bogus_root, &proof, b"k", b"v"));
    }

    #[test]
    fn membership_proof_for_absent_key_returns_none() {
        let smt = Smt::new();
        assert!(smt.generate_membership_proof(b"absent").is_none());
    }

    #[test]
    fn non_membership_proof_round_trips_for_absent_key() {
        let mut smt = Smt::new();
        smt.insert(b"k1", b"v1");
        smt.insert(b"k2", b"v2");

        let root = smt.root();
        let proof = smt
            .generate_non_membership_proof(b"absent")
            .expect("absent");
        assert_eq!(proof.siblings.len(), TREE_DEPTH);
        assert!(Smt::verify_non_membership(&root, &proof, b"absent"));
    }

    #[test]
    fn non_membership_proof_for_present_key_returns_none() {
        let mut smt = Smt::new();
        smt.insert(b"k", b"v");
        assert!(smt.generate_non_membership_proof(b"k").is_none());
    }

    #[test]
    fn non_membership_proof_against_empty_tree_verifies_zero_root() {
        let smt = Smt::new();
        let root = smt.root();
        assert_eq!(root, EMPTY);
        let proof = smt
            .generate_non_membership_proof(b"anything")
            .expect("absent");
        assert!(Smt::verify_non_membership(&root, &proof, b"anything"));
    }

    #[test]
    fn membership_proof_after_update_uses_new_value() {
        let mut smt = Smt::new();
        smt.insert(b"k", b"v1");
        let stale = smt.generate_membership_proof(b"k").expect("present");
        smt.update(b"k", b"v2");
        let root = smt.root();
        assert!(!Smt::verify_membership(&root, &stale, b"k", b"v1"));
        let fresh = smt.generate_membership_proof(b"k").expect("present");
        assert!(Smt::verify_membership(&root, &fresh, b"k", b"v2"));
    }
}

#[cfg(test)]
mod cardano_byte_compat {
    use super::*;

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

    fn assert_sibling_layout(
        label: &str,
        siblings: &[[u8; HASH_SIZE]],
        non_zero: &[(usize, &str)],
    ) {
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
}
