# ipsa-core

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

Those three need nothing but hashing and protobuf. Everything else is behind the
`chains` feature: the Soroban and Cosmos types, the RPC client, the codecs.

```toml
# just the primitives, 65 dependencies
ipsa-core = { version = "0.1", default-features = false }

# with the Stellar and Cosmos plumbing, 430
ipsa-core = "0.1"
```

The split is enforced in CI, because the primitives are what a light client has
to match and they should stay cheap to depend on.

## License

Licensed under the
[Apache License 2.0](https://github.com/ipsadev/ipsa-core/blob/main/LICENSE).
