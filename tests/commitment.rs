use ipsa_ibc_core::commitment::{
    acknowledgement_commitment, acknowledgement_commitment_path, packet_commitment,
    packet_commitment_path, packet_receipt_path, payload_commitment, CommitmentError,
    ACKNOWLEDGEMENT_COMMITMENT_DISCRIMINATOR, PACKET_COMMITMENT_DISCRIMINATOR,
    PACKET_RECEIPT_DISCRIMINATOR, RECEIPT_SENTINEL, UNIVERSAL_ERROR_ACKNOWLEDGEMENT,
    UNIVERSAL_ERROR_ACKNOWLEDGEMENT_PREIMAGE,
};
use sha2::{Digest, Sha256};

const ICS24_HOST: &str = include_str!("fixtures/ics24-host-vectors.txt");

fn solidity(name: &str) -> String {
    ICS24_HOST
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name} ")))
        .unwrap_or_else(|| panic!("no vector {name}"))
        .to_string()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn transfer_payload(encoding: &str, value: &[u8]) -> [u8; 32] {
    payload_commitment(
        b"transfer",
        b"transfer",
        b"ics20-1",
        encoding.as_bytes(),
        value,
    )
}

#[test]
fn a_packet_with_one_payload_commits_as_ics24_host_does() {
    let payload = transfer_payload("application/x-solidity-abi", &[0xde, 0xad, 0xbe, 0xef]);

    assert_eq!(
        encode_hex(&packet_commitment(
            b"stellar-testnet-1",
            1_790_301_922,
            &[payload]
        )),
        solidity("packet-one-payload")
    );
}

#[test]
fn a_packet_with_two_payloads_commits_as_ics24_host_does() {
    let payloads = [
        transfer_payload("application/json", br#"{"denom":"native"}"#),
        transfer_payload("application/x-solidity-abi", b""),
    ];

    assert_eq!(
        encode_hex(&packet_commitment(b"08-wasm-1", 0, &payloads)),
        solidity("packet-two-payloads")
    );
}

#[test]
fn acknowledgements_commit_as_ics24_host_does() {
    assert_eq!(
        encode_hex(&acknowledgement_commitment(&[b"ok"]).unwrap()),
        solidity("ack-one")
    );
    assert_eq!(
        encode_hex(
            &acknowledgement_commitment(&[&[0x01][..], &UNIVERSAL_ERROR_ACKNOWLEDGEMENT[..]])
                .unwrap()
        ),
        solidity("ack-two")
    );
}

#[test]
fn an_empty_acknowledgement_list_is_refused_as_ics24_host_refuses_it() {
    let none: [&[u8]; 0] = [];

    assert_eq!(
        acknowledgement_commitment(&none),
        Err(CommitmentError::NoAcknowledgements)
    );
}

#[test]
fn the_universal_error_acknowledgement_is_ics24_hosts() {
    assert_eq!(
        encode_hex(&UNIVERSAL_ERROR_ACKNOWLEDGEMENT),
        solidity("universal-error-ack")
    );
    assert_eq!(
        UNIVERSAL_ERROR_ACKNOWLEDGEMENT,
        <[u8; 32]>::from(Sha256::digest(UNIVERSAL_ERROR_ACKNOWLEDGEMENT_PREIMAGE))
    );
}

#[test]
fn paths_are_laid_out_as_ics24_host_lays_them_out() {
    assert_eq!(
        encode_hex(&packet_commitment_path(b"sepolia-0", 7)),
        solidity("path-commitment")
    );
    assert_eq!(
        encode_hex(&packet_receipt_path(b"stellar-testnet-1", 7)),
        solidity("path-receipt")
    );
    assert_eq!(
        encode_hex(&acknowledgement_commitment_path(
            b"stellar-testnet-1",
            u64::MAX
        )),
        solidity("path-acknowledgement")
    );
}

#[test]
fn the_discriminators_are_the_ics24_ones() {
    assert_eq!(PACKET_COMMITMENT_DISCRIMINATOR, 0x01);
    assert_eq!(PACKET_RECEIPT_DISCRIMINATOR, 0x02);
    assert_eq!(ACKNOWLEDGEMENT_COMMITMENT_DISCRIMINATOR, 0x03);
}

#[test]
fn the_receipt_is_the_single_byte_the_router_stores() {
    assert_eq!(RECEIPT_SENTINEL, [0x01]);
}

#[test]
fn every_payload_field_is_committed() {
    let base = payload_commitment(b"src", b"dst", b"v1", b"json", b"hello");

    for changed in [
        payload_commitment(b"SRC", b"dst", b"v1", b"json", b"hello"),
        payload_commitment(b"src", b"DST", b"v1", b"json", b"hello"),
        payload_commitment(b"src", b"dst", b"v2", b"json", b"hello"),
        payload_commitment(b"src", b"dst", b"v1", b"cbor", b"hello"),
        payload_commitment(b"src", b"dst", b"v1", b"json", b"HELLO"),
    ] {
        assert_ne!(base, changed);
    }
}
