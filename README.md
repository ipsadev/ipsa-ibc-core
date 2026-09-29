# ipsa-ibc-core

The IBC pieces that both sides of a bridge have to agree on.

Commitment paths say where a packet lives in state. The sparse Merkle tree says
how that state is hashed into a single root. The ICS-23 serializer turns a path
through that tree into a proof another chain can check. Get any of the three
wrong on one side and proofs stop verifying.

## What it does

| Module | What it answers |
|---|---|
| `commitment` | where does this packet, receipt or acknowledgement live |
| `smt` | what is the root of this state, and what proves one entry |
| `proof` | how is that proof written so another chain can read it |

They need nothing but hashing and protobuf: `sha2`, `ics23` and `prost`, 41
packages in the lockfile. That is the point. The Soroban router, the `08-wasm`
light client and the gateway all have to produce the same bytes, and a crate
that small is one each of them can afford to depend on.

```toml
ipsa-ibc-core = "0.1"
```

Only the primitives live here. Talking to Stellar and Cosmos — Soroban values,
IBC messages, client states, the api client, the gateway's view of the router's
tree — belongs to the services that do it, in `ipsa-backend`.

## Using it

```rust
use ipsa_ibc_core::{proof::serialize_membership_proof, smt::Smt};

let mut tree = Smt::new();
tree.insert(b"path", b"commitment");

let proof = tree.generate_membership_proof(b"path")?;
let bytes = serialize_membership_proof(&proof);
```

A proof carries the key it was generated for, and the serialisers take nothing
else: they write the value's **hash**, which is what the light client compares,
and derive each step's side from the key's index. There is no way to hand them a
raw value, a different key or a wrong index.

Generating a proof says why it cannot exist: `KeyAbsent`, `KeyPresent`, or
`IndexTakenByAnotherKey`.

## Verifying

The crate verifies what it produces, at two levels:

| Function | Takes | For |
|---|---|---|
| `smt::verify_membership`, `smt::verify_non_membership` | a key, a value, 64 siblings | code that already holds the siblings, such as the SP1 membership program |
| `proof::verify_membership_proof`, `proof::verify_non_membership_proof` | proof bytes, the path, the claimed value | a light client checking a relayed proof |
| `proof::decode_membership_proof`, `proof::decode_non_membership_proof` | proof bytes | a verifier that wants the parts, e.g. to build its own error |

The byte-level verifiers apply exactly the Stellar `08-wasm` light client's
checks: the proof's key must be the path, the proof's value must be `sha256` of
the claimed value, an empty value is never provable, the path must have 64
steps, and it must fold to the root from the key's index. Before this was
released they were run against the light client's own `merkle.rs` and `smt.rs`
over 109,500 proofs — valid ones, every byte flipped, truncated and extended —
and agreed on every verdict.

Fields the check never reads — the declared hash operation, the leaf
description, and which side a step claims its sibling is on — can change without
changing the verdict, because the fold is always rebuilt from the key, the value
and the siblings. That makes a proof's bytes malleable, never its meaning.



`commitment` is IBC v2's commitment scheme as `ICS24Host.sol` defines it: the
three paths (`client ‖ 0x01/0x02/0x03 ‖ big-endian sequence`), the payload and
packet commitments, the acknowledgement commitment, and the universal error
acknowledgement. `tests/commitment.rs` checks each against vectors produced by
`ICS24Host.sol` itself, in `tests/fixtures/ics24-host-vectors.txt`. To regenerate
them, put `tests/fixtures/ICS24HostVectors.t.sol` in a Foundry project whose
remappings point `ibc/` at `ibc-solidity/contracts/` and run `forge test -vv`.

An acknowledgement commitment needs at least one acknowledgement, as on
Solidity; an empty list is `CommitmentError::NoAcknowledgements`.

A receipt's value is the one byte `RECEIPT_SENTINEL` on Stellar, where
`ICS24Host.sol` stores `keccak256(abi.encode(packet))`. Both are valid: a
receipt is only ever proven absent, so its value is never compared.



A leaf's position is the first 8 bytes of `sha256(key)`, as on the router, so two
keys can in principle share one. The tree then holds whichever was written last,
and for the other key neither proof exists — `generate_*_proof` returns
`IndexTakenByAnotherKey` instead of a proof. Finding such a pair takes around
2⁶⁴ hashes for a chosen key, so it is not tested; it is recorded here because
it is the one case where membership and non-membership are both unavailable.

An empty value is stored like any other, as the router stores it; removal is
`remove`.



The proofs are carried in ICS-23 message types, but they are not generic ICS-23
proofs: the leaf is `sha256(0x00 ‖ sha256(key) ‖ sha256(value))`, and a
non-membership proof is the key's path folded from the empty leaf. The one
verifier is the Stellar `08-wasm` light client, so the format can only change on
both sides at once.

## License

Licensed under the
[Apache License 2.0](https://github.com/ipsadev/ipsa-core/blob/main/LICENSE).
