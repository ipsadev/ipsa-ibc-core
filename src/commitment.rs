use std::fmt;

use sha2::{Digest, Sha256};

pub const PACKET_COMMITMENT_DISCRIMINATOR: u8 = 0x01;
pub const PACKET_RECEIPT_DISCRIMINATOR: u8 = 0x02;
pub const ACKNOWLEDGEMENT_COMMITMENT_DISCRIMINATOR: u8 = 0x03;

pub const COMMITMENT_VERSION_PREFIX: u8 = 0x02;

pub const RECEIPT_SENTINEL: [u8; 1] = [0x01];

pub const UNIVERSAL_ERROR_ACKNOWLEDGEMENT_PREIMAGE: &[u8] = b"UNIVERSAL_ERROR_ACKNOWLEDGEMENT";

pub const UNIVERSAL_ERROR_ACKNOWLEDGEMENT: [u8; 32] = [
    0x47, 0x74, 0xd4, 0xa5, 0x75, 0x99, 0x3f, 0x96, 0x3b, 0x1c, 0x06, 0x57, 0x37, 0x36, 0x61, 0x7a,
    0x45, 0x7a, 0xbe, 0xf8, 0x58, 0x91, 0x78, 0xdb, 0x8d, 0x10, 0xc9, 0x4b, 0x4a, 0xb5, 0x11, 0xab,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentError {
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

pub fn packet_commitment_path(source_client: &[u8], sequence: u64) -> Vec<u8> {
    path(source_client, PACKET_COMMITMENT_DISCRIMINATOR, sequence)
}

pub fn packet_receipt_path(destination_client: &[u8], sequence: u64) -> Vec<u8> {
    path(destination_client, PACKET_RECEIPT_DISCRIMINATOR, sequence)
}

pub fn acknowledgement_commitment_path(destination_client: &[u8], sequence: u64) -> Vec<u8> {
    path(
        destination_client,
        ACKNOWLEDGEMENT_COMMITMENT_DISCRIMINATOR,
        sequence,
    )
}

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
