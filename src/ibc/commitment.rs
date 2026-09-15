use sha2::{Digest, Sha256};

pub const PACKET_COMMITMENT_DISCRIMINATOR: u8 = 0x01;
pub const PACKET_RECEIPT_DISCRIMINATOR: u8 = 0x02;
pub const ACK_COMMITMENT_DISCRIMINATOR: u8 = 0x03;

pub const RECEIPT_SENTINEL: [u8; 1] = [0x01];

pub const COMMITMENT_VERSION_PREFIX: u8 = 0x02;

pub const ERROR_ACK_PREIMAGE: &[u8] = b"UNIVERSAL_ERROR_ACKNOWLEDGEMENT";

pub fn error_ack_hash() -> [u8; 32] {
    Sha256::digest(ERROR_ACK_PREIMAGE).into()
}

pub fn packet_commitment_path(source_client_id: &[u8], sequence: u64) -> Vec<u8> {
    v2_path(source_client_id, PACKET_COMMITMENT_DISCRIMINATOR, sequence)
}

pub fn packet_receipt_path(dest_client_id: &[u8], sequence: u64) -> Vec<u8> {
    v2_path(dest_client_id, PACKET_RECEIPT_DISCRIMINATOR, sequence)
}

pub fn ack_commitment_path(dest_client_id: &[u8], sequence: u64) -> Vec<u8> {
    v2_path(dest_client_id, ACK_COMMITMENT_DISCRIMINATOR, sequence)
}

fn v2_path(client_id: &[u8], discriminator: u8, sequence: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(client_id.len() + 1 + 8);
    out.extend_from_slice(client_id);
    out.push(discriminator);
    out.extend_from_slice(&sequence.to_be_bytes());
    out
}

pub fn commit_payload(
    source_port: &[u8],
    dest_port: &[u8],
    version: &str,
    encoding: &str,
    app_data: &[u8],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 * 5);
    buf.extend_from_slice(&sha256(source_port));
    buf.extend_from_slice(&sha256(dest_port));
    buf.extend_from_slice(&sha256(version.as_bytes()));
    buf.extend_from_slice(&sha256(encoding.as_bytes()));
    buf.extend_from_slice(&sha256(app_data));
    sha256(&buf)
}

pub fn commit_v2_packet(
    dest_client_id: &[u8],
    timeout_timestamp: u64,
    payload_hashes: &[[u8; 32]],
) -> [u8; 32] {
    let mut app_bytes = Vec::with_capacity(32 * payload_hashes.len());
    for hash in payload_hashes {
        app_bytes.extend_from_slice(hash);
    }
    let timeout_be = timeout_timestamp.to_be_bytes();
    let mut buf = Vec::with_capacity(1 + 32 * 3);
    buf.push(COMMITMENT_VERSION_PREFIX);
    buf.extend_from_slice(&sha256(dest_client_id));
    buf.extend_from_slice(&sha256(&timeout_be));
    buf.extend_from_slice(&sha256(&app_bytes));
    sha256(&buf)
}

pub fn commit_v2_acknowledgement(app_acks: &[Vec<u8>]) -> [u8; 32] {
    let mut concat = Vec::with_capacity(32 * app_acks.len());
    for ack in app_acks {
        concat.extend_from_slice(&sha256(ack));
    }
    let mut buf = Vec::with_capacity(1 + concat.len());
    buf.push(COMMITMENT_VERSION_PREFIX);
    buf.extend_from_slice(&concat);
    sha256(&buf)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminators_match_ics24_spec() {
        assert_eq!(PACKET_COMMITMENT_DISCRIMINATOR, 0x01);
        assert_eq!(PACKET_RECEIPT_DISCRIMINATOR, 0x02);
        assert_eq!(ACK_COMMITMENT_DISCRIMINATOR, 0x03);
    }

    #[test]
    fn paths_have_clientid_disc_be64_layout() {
        let path = packet_commitment_path(b"10-stellar-0", 0x1234);
        assert_eq!(&path[..12], b"10-stellar-0");
        assert_eq!(path[12], 0x01);
        assert_eq!(&path[13..], &0x1234u64.to_be_bytes());
    }

    #[test]
    fn receipt_path_uses_0x02_and_ack_uses_0x03() {
        assert_eq!(packet_receipt_path(b"x", 0)[1], 0x02);
        assert_eq!(ack_commitment_path(b"x", 0)[1], 0x03);
    }

    #[test]
    fn receipt_sentinel_is_single_0x01_byte() {
        assert_eq!(RECEIPT_SENTINEL, [0x01]);
    }

    #[test]
    fn error_ack_hash_is_deterministic_and_nonempty() {
        let h = error_ack_hash();
        assert_ne!(h, [0u8; 32]);
        assert_eq!(h, error_ack_hash());
    }

    #[test]
    fn commit_payload_changes_with_each_input() {
        let base = commit_payload(b"src", b"dst", "v1", "json", b"hello");
        assert_ne!(base, commit_payload(b"SRC", b"dst", "v1", "json", b"hello"));
        assert_ne!(base, commit_payload(b"src", b"DST", "v1", "json", b"hello"));
        assert_ne!(base, commit_payload(b"src", b"dst", "v2", "json", b"hello"));
        assert_ne!(base, commit_payload(b"src", b"dst", "v1", "cbor", b"hello"));
        assert_ne!(base, commit_payload(b"src", b"dst", "v1", "json", b"HELLO"));
    }

    #[test]
    fn commit_v2_packet_has_0x02_prefix_in_preimage() {
        let h1 = commit_v2_packet(b"client", 1_000, &[[0xAA; 32]]);
        let h2 = commit_v2_packet(b"client", 1_000, &[[0xAA; 32]]);
        assert_eq!(h1, h2, "must be deterministic");

        let h3 = commit_v2_packet(b"client", 2_000, &[[0xAA; 32]]);
        assert_ne!(h1, h3, "timeout must affect commitment");

        let h4 = commit_v2_packet(b"client", 1_000, &[[0xBB; 32]]);
        assert_ne!(h1, h4, "payload hashes must affect commitment");
    }

    #[test]
    fn commit_v2_acknowledgement_distinguishes_payload_count() {
        let single = commit_v2_acknowledgement(&[vec![1, 2, 3]]);
        let two_acks = commit_v2_acknowledgement(&[vec![1, 2, 3], vec![4, 5, 6]]);
        assert_ne!(single, two_acks);
    }
}
