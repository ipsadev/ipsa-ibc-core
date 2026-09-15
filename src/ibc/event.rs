use crate::conversion::{
    scval_as_bytes, scval_as_map, scval_as_string, scval_as_symbol, scval_as_u64, scval_field,
    scval_from_xdr,
};
use soroban_client::xdr::{ScMap, ScVal};

fn first_payload_ports(packet: &ScMap) -> (String, String) {
    let default = || ("transfer".to_string(), "transfer".to_string());

    let Some(ScVal::Vec(Some(payloads))) = scval_field(packet, "payloads") else {
        return default();
    };
    let Some(payload) = payloads.0.first().and_then(scval_as_map) else {
        return default();
    };

    (
        scval_field(payload, "source_port")
            .and_then(scval_as_string)
            .unwrap_or_else(|| "transfer".to_string()),
        scval_field(payload, "dest_port")
            .and_then(scval_as_string)
            .unwrap_or_else(|| "transfer".to_string()),
    )
}

pub fn event_attributes(topics_xdr: &[Vec<u8>], value_xdr: &[u8]) -> Option<String> {
    let kind = scval_from_xdr(topics_xdr.first()?)
        .ok()
        .as_ref()
        .and_then(scval_as_symbol)?;

    let value = scval_from_xdr(value_xdr).ok()?;
    let root = scval_as_map(&value)?;

    if let Some(packet) = scval_field(root, "packet").and_then(scval_as_map) {
        let sequence = scval_field(packet, "sequence")
            .and_then(scval_as_u64)
            .unwrap_or(0);
        let source_client = scval_field(packet, "source_client")
            .and_then(scval_as_string)
            .unwrap_or_default();
        let dest_client = scval_field(packet, "dest_client")
            .and_then(scval_as_string)
            .unwrap_or_default();
        let (source_port, dest_port) = first_payload_ports(packet);

        let mut text = format!("type={kind}\npacket_sequence={sequence}\n");
        if !source_client.is_empty() {
            text.push_str(&format!("packet_src_channel={source_client}\n"));
        }
        if !dest_client.is_empty() {
            text.push_str(&format!("packet_dst_channel={dest_client}\n"));
        }
        text.push_str(&format!(
            "packet_src_port={source_port}\npacket_dst_port={dest_port}\n"
        ));

        return Some(text);
    }

    let mut text = format!("type={kind}\n");

    let topic = |index: usize| {
        topics_xdr
            .get(index)
            .and_then(|raw| scval_from_xdr(raw).ok())
    };

    let client_id = scval_field(root, "client_id")
        .and_then(scval_as_string)
        .or_else(|| topic(1).as_ref().and_then(scval_as_string));
    if let Some(client_id) = client_id {
        text.push_str(&format!("client_id={client_id}\n"));
        text.push_str(&format!("packet_dst_channel={client_id}\n"));
    }

    let sequence = scval_field(root, "sequence")
        .and_then(scval_as_u64)
        .or_else(|| topic(2).as_ref().and_then(scval_as_u64));
    if let Some(sequence) = sequence {
        text.push_str(&format!("packet_sequence={sequence}\n"));
    }

    if let Some(ack) = first_acknowledgement(root) {
        text.push_str(&format!("acknowledgement={ack}\n"));
    }

    Some(text)
}

fn first_acknowledgement(root: &ScMap) -> Option<String> {
    let ScVal::Vec(Some(acks)) = scval_field(root, "acknowledgements")? else {
        return None;
    };

    let bytes = acks.0.first().and_then(scval_as_bytes)?;

    String::from_utf8(bytes).ok()
}
