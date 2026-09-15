use anyhow::{anyhow, Result};
use soroban_client::xdr::ScVal;

use crate::conversion::{
    scval_as_bytes, scval_as_map, scval_as_string, scval_as_symbol, scval_as_u64, scval_field,
    scval_from_xdr,
};

pub const SEND_PACKET: &str = "send_packet";
pub const WRITE_ACK: &str = "write_ack";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload {
    pub source_port: String,
    pub dest_port: String,
    pub version: String,
    pub encoding: String,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub sequence: u64,
    pub source_client: String,
    pub dest_client: String,
    pub timeout_timestamp: u64,
    pub payloads: Vec<Payload>,
}

#[derive(Clone, Debug)]
pub struct PacketEvent {
    pub kind: String,
    pub tx_hash: String,
    pub ledger: u32,
    pub packet: Packet,
    pub acknowledgements: Vec<Vec<u8>>,
}

pub fn event_kind(topics_xdr: &[Vec<u8>]) -> Option<String> {
    scval_from_xdr(topics_xdr.first()?)
        .ok()
        .as_ref()
        .and_then(scval_as_symbol)
}

pub fn decode_packet(value_xdr: &[u8]) -> Result<Packet> {
    let value = scval_from_xdr(value_xdr)?;
    let root = scval_as_map(&value).ok_or_else(|| anyhow!("event body is not a map"))?;
    let packet = scval_field(root, "packet")
        .and_then(scval_as_map)
        .ok_or_else(|| anyhow!("event body has no packet field"))?;

    let sequence = scval_field(packet, "sequence")
        .and_then(scval_as_u64)
        .ok_or_else(|| anyhow!("packet has no sequence"))?;
    let source_client = scval_field(packet, "source_client")
        .and_then(scval_as_string)
        .ok_or_else(|| anyhow!("packet has no source_client"))?;
    let dest_client = scval_field(packet, "dest_client")
        .and_then(scval_as_string)
        .ok_or_else(|| anyhow!("packet has no dest_client"))?;
    let timeout_timestamp = scval_field(packet, "timeout_timestamp")
        .and_then(scval_as_u64)
        .ok_or_else(|| anyhow!("packet has no timeout_timestamp"))?;

    let payloads = match scval_field(packet, "payloads") {
        Some(ScVal::Vec(Some(items))) => items
            .0
            .iter()
            .map(decode_payload)
            .collect::<Result<Vec<_>>>()?,
        _ => return Err(anyhow!("packet has no payloads")),
    };

    Ok(Packet {
        sequence,
        source_client,
        dest_client,
        timeout_timestamp,
        payloads,
    })
}

fn decode_payload(value: &ScVal) -> Result<Payload> {
    let map = scval_as_map(value).ok_or_else(|| anyhow!("payload is not a map"))?;

    let field = |name: &str| {
        scval_field(map, name)
            .and_then(scval_as_string)
            .ok_or_else(|| anyhow!("payload has no {name}"))
    };

    Ok(Payload {
        source_port: field("source_port")?,
        dest_port: field("dest_port")?,
        version: field("version")?,
        encoding: field("encoding")?,
        value: scval_field(map, "value")
            .and_then(scval_as_bytes)
            .ok_or_else(|| anyhow!("payload has no value"))?,
    })
}

pub fn decode_acknowledgements(value_xdr: &[u8]) -> Vec<Vec<u8>> {
    let Ok(value) = scval_from_xdr(value_xdr) else {
        return Vec::new();
    };
    let Some(root) = scval_as_map(&value) else {
        return Vec::new();
    };

    match scval_field(root, "acknowledgements") {
        Some(ScVal::Vec(Some(items))) => items.0.iter().filter_map(scval_as_bytes).collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEND_PACKET_EVENT: &[u8] = &[
        0, 0, 0, 17, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 15, 0, 0, 0, 6, 112, 97, 99, 107, 101, 116,
        0, 0, 0, 0, 0, 17, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 15, 0, 0, 0, 11, 100, 101, 115, 116,
        95, 99, 108, 105, 101, 110, 116, 0, 0, 0, 0, 14, 0, 0, 0, 9, 48, 56, 45, 119, 97, 115, 109,
        45, 48, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 8, 112, 97, 121, 108, 111, 97, 100, 115, 0, 0, 0,
        16, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 17, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 15, 0, 0, 0, 9,
        100, 101, 115, 116, 95, 112, 111, 114, 116, 0, 0, 0, 0, 0, 0, 14, 0, 0, 0, 8, 116, 114, 97,
        110, 115, 102, 101, 114, 0, 0, 0, 15, 0, 0, 0, 8, 101, 110, 99, 111, 100, 105, 110, 103, 0,
        0, 0, 14, 0, 0, 0, 16, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 106, 115,
        111, 110, 0, 0, 0, 15, 0, 0, 0, 11, 115, 111, 117, 114, 99, 101, 95, 112, 111, 114, 116, 0,
        0, 0, 0, 14, 0, 0, 0, 8, 116, 114, 97, 110, 115, 102, 101, 114, 0, 0, 0, 15, 0, 0, 0, 5,
        118, 97, 108, 117, 101, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 168, 123, 34, 100, 101, 110, 111,
        109, 34, 58, 34, 88, 76, 77, 34, 44, 34, 97, 109, 111, 117, 110, 116, 34, 58, 34, 49, 48,
        48, 48, 34, 44, 34, 115, 101, 110, 100, 101, 114, 34, 58, 34, 71, 65, 80, 67, 74, 50, 71,
        88, 71, 73, 89, 50, 86, 82, 76, 75, 54, 87, 52, 68, 68, 89, 52, 52, 51, 82, 51, 74, 68, 77,
        74, 51, 75, 53, 76, 81, 66, 77, 85, 74, 76, 52, 76, 68, 83, 88, 51, 52, 77, 88, 81, 77, 83,
        72, 86, 68, 34, 44, 34, 114, 101, 99, 101, 105, 118, 101, 114, 34, 58, 34, 99, 111, 115,
        109, 111, 115, 49, 99, 108, 113, 102, 100, 116, 103, 116, 48, 112, 120, 121, 54, 102, 56,
        118, 106, 121, 107, 99, 120, 109, 118, 113, 103, 112, 113, 117, 119, 55, 50, 104, 108, 52,
        113, 108, 55, 100, 34, 44, 34, 109, 101, 109, 111, 34, 58, 34, 34, 125, 0, 0, 0, 15, 0, 0,
        0, 7, 118, 101, 114, 115, 105, 111, 110, 0, 0, 0, 0, 14, 0, 0, 0, 7, 105, 99, 115, 50, 48,
        45, 49, 0, 0, 0, 0, 15, 0, 0, 0, 8, 115, 101, 113, 117, 101, 110, 99, 101, 0, 0, 0, 5, 0,
        0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 15, 0, 0, 0, 13, 115, 111, 117, 114, 99, 101, 95, 99, 108,
        105, 101, 110, 116, 0, 0, 0, 0, 0, 0, 14, 0, 0, 0, 15, 48, 55, 45, 116, 101, 110, 100, 101,
        114, 109, 105, 110, 116, 45, 53, 0, 0, 0, 0, 15, 0, 0, 0, 17, 116, 105, 109, 101, 111, 117,
        116, 95, 116, 105, 109, 101, 115, 116, 97, 109, 112, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 106,
        100, 32, 55,
    ];

    #[test]
    fn decodes_the_hermes_reference_packet() {
        let packet = decode_packet(SEND_PACKET_EVENT).expect("decode");

        assert_eq!(packet.sequence, 1);
        assert_eq!(packet.source_client, "07-tendermint-5");
        assert_eq!(packet.dest_client, "08-wasm-0");
        assert_eq!(packet.timeout_timestamp, 1_784_946_743);
        assert_eq!(packet.payloads.len(), 1);

        let payload = &packet.payloads[0];
        assert_eq!(payload.source_port, "transfer");
        assert_eq!(payload.dest_port, "transfer");
        assert_eq!(payload.version, "ics20-1");
        assert_eq!(payload.encoding, "application/json");

        let value: serde_json::Value =
            serde_json::from_slice(&payload.value).expect("ics20 payload is json");
        assert_eq!(value["denom"], "XLM");
        assert_eq!(value["amount"], "1000");
        assert_eq!(
            value["sender"],
            "GAPCJ2GXGIY2VRLK6W4DDY443R3JDMJ3K5LQBMUJL4LDSX34MXQMSHVD"
        );
        assert_eq!(
            value["receiver"],
            "cosmos1clqfdtgt0pxy6f8vjykcxmvqgpquw72hl4ql7d"
        );
    }

    #[test]
    fn rejects_a_body_without_a_packet() {
        assert!(decode_packet(&[0, 0, 0, 1]).is_err());
    }
}
