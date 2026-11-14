# ipsa-ibc-core

> **Archived.** This code now lives in the [`ipsa`](https://github.com/ipsadev/ipsa) repository, as the `core` module of the [`ipsa`](https://crates.io/crates/ipsa) crate. This repository is read-only and gets no further fixes or releases.

The commitment paths, the fixed-depth sparse Merkle tree and its ICS-23 proofs moved into `ipsa` unchanged, at version 0.1.2. The modules have the same names, functions, types and errors, and produce the same bytes.

## Moving to `ipsa`

Swap the dependency for `ipsa` with only the `core` feature. That keeps the dependencies to `sha2`, `ics23` and `prost`, as before:

```toml
ipsa = { version = "0.2", default-features = false, features = ["core"] }
```

Then change the import paths from `ipsa_ibc_core::` to `ipsa::core::`:

```rust
use ipsa::core::{proof::serialize_membership_proof, smt::Smt};

let mut tree = Smt::new();
tree.insert(b"path", b"commitment");

let proof = tree.generate_membership_proof(b"path")?;
let bytes = serialize_membership_proof(&proof);
```

- `ipsa_ibc_core::commitment` becomes `ipsa::core::commitment`
- `ipsa_ibc_core::smt` becomes `ipsa::core::smt`
- `ipsa_ibc_core::proof` becomes `ipsa::core::proof`

The `ipsa` README covers the module and the crate's other features. Raise issues and pull requests on [ipsadev/ipsa](https://github.com/ipsadev/ipsa).

## License

Copyright 2026 Amanda Gonsalves. Licensed under the [Apache License 2.0](LICENSE).
