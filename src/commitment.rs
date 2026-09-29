use std::fmt;

use sha2::{Digest, Sha256};

/// the byte after the client id in a packet commitment path.
pub const PACKET_COMMITMENT_DISCRIMINATOR: u8 = 0x01;
/// the byte after the client id in a packet receipt path.
pub const PACKET_RECEIPT_DISCRIMINATOR: u8 = 0x02;
/// the byte after the client id in an acknowledgement commitment path.
pub const ACKNOWLEDGEMENT_COMMITMENT_DISCRIMINATOR: u8 = 0x03;

/// the first byte hashed into packet and acknowledgement commitments.
pub const COMMITMENT_VERSION_PREFIX: u8 = 0x02;

/// the value the stellar router stores for a receipt.
///
/// a receipt is only ever proven absent, so its value is never compared.
pub const RECEIPT_SENTINEL: [u8; 1] = [0x01];

/// the text hashed to make [`UNIVERSAL_ERROR_ACKNOWLEDGEMENT`].
pub const UNIVERSAL_ERROR_ACKNOWLEDGEMENT_PREIMAGE: &[u8] = b"UNIVERSAL_ERROR_ACKNOWLEDGEMENT";

/// the acknowledgement written when a packet fails: `sha256` of its preimage.
pub const UNIVERSAL_ERROR_ACKNOWLEDGEMENT: [u8; 32] = [
    0x47, 0x74, 0xd4, 0xa5, 0x75, 0x99, 0x3f, 0x96, 0x3b, 0x1c, 0x06, 0x57, 0x37, 0x36, 0x61, 0x7a,
    0x45, 0x7a, 0xbe, 0xf8, 0x58, 0x91, 0x78, 0xdb, 0x8d, 0x10, 0xc9, 0x4b, 0x4a, 0xb5, 0x11, 0xab,
];

/// why a commitment could not be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentError {
    /// an acknowledgement commitment needs at least one acknowledgement.
    NoAcknowledgements,
}

impl fmt::Display for CommitmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAcknowledgements => formatter
                .write_str("an acknowledgement commitment needs at least one acknowledgement"),
        }
    }
}

impl std::error::Error for CommitmentError {}

/// where a sent packet's commitment lives: `source client ‖ 0x01 ‖ sequence`.
pub fn packet_commitment_path(source_client: &[u8], sequence: u64) -> Vec<u8> {
    path(source_client, PACKET_COMMITMENT_DISCRIMINATOR, sequence)
}

/// where a received packet's receipt lives: `destination client ‖ 0x02 ‖ sequence`.
pub fn packet_receipt_path(destination_client: &[u8], sequence: u64) -> Vec<u8> {
    path(destination_client, PACKET_RECEIPT_DISCRIMINATOR, sequence)
}

/// where an acknowledgement's commitment lives: `destination client ‖ 0x03 ‖ sequence`.
pub fn acknowledgement_commitment_path(destination_client: &[u8], sequence: u64) -> Vec<u8> {
    path(
        destination_client,
        ACKNOWLEDGEMENT_COMMITMENT_DISCRIMINATOR,
        sequence,
    )
}

/// the hash of one payload, from the hashes of its five fields.
pub fn payload_commitment(
    source_port: &[u8],
    destination_port: &[u8],
    version: &[u8],
    encoding: &[u8],
    value: &[u8],
) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(32 * 5);

    for field in [source_port, destination_port, version, encoding, value] {
        preimage.extend_from_slice(&sha256(field));
    }

    sha256(&preimage)
}

/// the hash stored for a sent packet.
///
/// `payload_commitments` are the packet's payloads, each hashed with [`payload_commitment`].
pub fn packet_commitment(
    destination_client: &[u8],
    timeout_timestamp: u64,
    payload_commitments: &[[u8; 32]],
) -> [u8; 32] {
    let payloads = payload_commitments.concat();
    let mut preimage = Vec::with_capacity(1 + 32 * 3);

    preimage.push(COMMITMENT_VERSION_PREFIX);
    preimage.extend_from_slice(&sha256(destination_client));
    preimage.extend_from_slice(&sha256(&timeout_timestamp.to_be_bytes()));
    preimage.extend_from_slice(&sha256(&payloads));

    sha256(&preimage)
}

/// the hash stored for a packet's acknowledgements, one per payload.
///
/// fails when the list is empty.
pub fn acknowledgement_commitment<Acknowledgement: AsRef<[u8]>>(
    acknowledgements: &[Acknowledgement],
) -> Result<[u8; 32], CommitmentError> {
    if acknowledgements.is_empty() {
        return Err(CommitmentError::NoAcknowledgements);
    }

    let mut preimage = Vec::with_capacity(1 + 32 * acknowledgements.len());

    preimage.push(COMMITMENT_VERSION_PREFIX);

    for acknowledgement in acknowledgements {
        preimage.extend_from_slice(&sha256(acknowledgement.as_ref()));
    }

    Ok(sha256(&preimage))
}

fn path(client: &[u8], discriminator: u8, sequence: u64) -> Vec<u8> {
    let mut path = Vec::with_capacity(client.len() + 1 + 8);

    path.extend_from_slice(client);
    path.push(discriminator);
    path.extend_from_slice(&sequence.to_be_bytes());

    path
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
