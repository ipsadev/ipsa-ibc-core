use ibc_proto::cosmos::tx::v1beta1::TxBody;
use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::core::client::v1::Height as RawHeight;
use prost::Message;
use soroban_client::xdr::ScVal;

use crate::conversion::{scval_bytes, scval_string, scval_struct, scval_vec};
use crate::ibc::v2_msgs::{Acknowledgement, Packet as V2Packet};

pub use ibc_proto::cosmos::tx::v1beta1::TxBody as ProtoTxBody;
pub use ibc_proto::google::protobuf::Any as ProtoAny;
pub use ibc_proto::ibc::core::client::v1::{MsgCreateClient, MsgUpdateClient};
pub use ibc_proto::ibc::lightclients::wasm::v1::{
    ClientMessage as WasmClientMessage, ClientState as WasmClientState,
    ConsensusState as WasmConsensusState,
};
pub use prost::Message as ProtoMessage;

use super::packet::{PacketEvent, SEND_PACKET, WRITE_ACK};
use super::v2_msgs::{MsgAcknowledgement, MsgRecvPacket, MsgTimeout, Packet, Payload};

pub const TYPE_URL_CREATE_CLIENT: &str = "/ibc.core.client.v1.MsgCreateClient";
pub const TYPE_URL_UPDATE_CLIENT: &str = "/ibc.core.client.v1.MsgUpdateClient";
pub const TYPE_URL_WASM_CLIENT_MESSAGE: &str = "/ibc.lightclients.wasm.v1.ClientMessage";
pub const TYPE_URL_WASM_CLIENT_STATE: &str = "/ibc.lightclients.wasm.v1.ClientState";
pub const TYPE_URL_WASM_CONSENSUS_STATE: &str = "/ibc.lightclients.wasm.v1.ConsensusState";

pub fn wasm_client_state(client_state: Vec<u8>, checksum: Vec<u8>, latest_height: u64) -> Any {
    let wrapped = WasmClientState {
        data: client_state,
        checksum,
        latest_height: Some(RawHeight {
            revision_number: 0,
            revision_height: latest_height,
        }),
    };

    Any {
        type_url: TYPE_URL_WASM_CLIENT_STATE.to_string(),
        value: wrapped.encode_to_vec(),
    }
}

pub fn wasm_consensus_state(consensus_state: Vec<u8>) -> Any {
    Any {
        type_url: TYPE_URL_WASM_CONSENSUS_STATE.to_string(),
        value: WasmConsensusState {
            data: consensus_state,
        }
        .encode_to_vec(),
    }
}

pub fn create_client_msg(client_state: Any, consensus_state: Any, signer: &str) -> Any {
    let msg = MsgCreateClient {
        client_state: Some(client_state),
        consensus_state: Some(consensus_state),
        signer: signer.to_string(),
    };

    Any {
        type_url: TYPE_URL_CREATE_CLIENT.to_string(),
        value: msg.encode_to_vec(),
    }
}

pub fn wasm_client_message(header: Vec<u8>) -> Any {
    Any {
        type_url: TYPE_URL_WASM_CLIENT_MESSAGE.to_string(),
        value: WasmClientMessage { data: header }.encode_to_vec(),
    }
}

pub fn update_client_msg(client_id: &str, client_message: Any, signer: &str) -> Any {
    let msg = MsgUpdateClient {
        client_id: client_id.to_string(),
        client_message: Some(client_message),
        signer: signer.to_string(),
    };

    Any {
        type_url: TYPE_URL_UPDATE_CLIENT.to_string(),
        value: msg.encode_to_vec(),
    }
}

pub fn to_proto_packet(packet: &super::packet::Packet) -> Packet {
    Packet {
        sequence: packet.sequence,
        source_client: packet.source_client.clone(),
        dest_client: packet.dest_client.clone(),
        timeout_timestamp: packet.timeout_timestamp,
        payloads: packet
            .payloads
            .iter()
            .map(|payload| Payload {
                source_port: payload.source_port.clone(),
                dest_port: payload.dest_port.clone(),
                version: payload.version.clone(),
                encoding: payload.encoding.clone(),
                value: payload.value.clone(),
            })
            .collect(),
    }
}

pub fn recv_msg(event: &PacketEvent, signer: &str) -> MsgRecvPacket {
    MsgRecvPacket {
        packet: Some(to_proto_packet(&event.packet)),
        proof_commitment: Vec::new(),
        proof_height: None,
        signer: signer.to_string(),
    }
}

pub fn ack_msg(event: &PacketEvent, signer: &str) -> MsgAcknowledgement {
    MsgAcknowledgement {
        packet: Some(to_proto_packet(&event.packet)),
        acknowledgements: event.acknowledgements.clone(),
        proof_acked: Vec::new(),
        proof_height: None,
        signer: signer.to_string(),
    }
}

pub fn recv_msgs(events: &[PacketEvent], signer: &str) -> Vec<MsgRecvPacket> {
    events
        .iter()
        .filter(|event| event.kind == SEND_PACKET)
        .map(|event| recv_msg(event, signer))
        .collect()
}

pub fn ack_msgs(events: &[PacketEvent], signer: &str) -> Vec<MsgAcknowledgement> {
    events
        .iter()
        .filter(|event| event.kind == WRITE_ACK)
        .map(|event| ack_msg(event, signer))
        .collect()
}

pub fn encode_msgs(messages: Vec<Any>) -> Vec<u8> {
    TxBody {
        messages,
        ..Default::default()
    }
    .encode_to_vec()
}

pub fn encode_tx_body(
    update_client: Option<Any>,
    recv: Vec<MsgRecvPacket>,
    ack: Vec<MsgAcknowledgement>,
) -> Vec<u8> {
    encode_tx_body_with_timeouts(update_client, recv, ack, Vec::new())
}

pub fn encode_tx_body_with_timeouts(
    update_client: Option<Any>,
    recv: Vec<MsgRecvPacket>,
    ack: Vec<MsgAcknowledgement>,
    timeout: Vec<MsgTimeout>,
) -> Vec<u8> {
    encode_msgs(
        update_client
            .into_iter()
            .chain(recv.into_iter().map(Any::from))
            .chain(ack.into_iter().map(Any::from))
            .chain(timeout.into_iter().map(Any::from))
            .collect(),
    )
}

pub fn encode_packet(packet: &V2Packet) -> Vec<u8> {
    packet.encode_to_vec()
}

pub fn decode_packet(bytes: &[u8]) -> Result<V2Packet, prost::DecodeError> {
    V2Packet::decode(bytes)
}

pub fn decode_acknowledgement(bytes: &[u8]) -> Result<Vec<Vec<u8>>, prost::DecodeError> {
    Acknowledgement::decode(bytes).map(|a| a.app_acknowledgements)
}

pub fn merkle_proof_from_ops(ops: Vec<Vec<u8>>) -> Result<Vec<u8>, prost::DecodeError> {
    let mut proofs = Vec::with_capacity(ops.len());
    for op in ops {
        proofs.push(ics23::CommitmentProof::decode(op.as_slice())?);
    }
    Ok(ibc_proto::ibc::core::commitment::v1::MerkleProof { proofs }.encode_to_vec())
}

pub fn packet_to_scval(packet: &V2Packet) -> anyhow::Result<ScVal> {
    let mut payloads = Vec::with_capacity(packet.payloads.len());
    for payload in &packet.payloads {
        payloads.push(scval_struct(vec![
            ("dest_port", scval_string(&payload.dest_port)?),
            ("encoding", scval_string(&payload.encoding)?),
            ("source_port", scval_string(&payload.source_port)?),
            ("value", scval_bytes(&payload.value)?),
            ("version", scval_string(&payload.version)?),
        ])?);
    }

    scval_struct(vec![
        ("dest_client", scval_string(&packet.dest_client)?),
        ("payloads", scval_vec(payloads)?),
        ("sequence", ScVal::U64(packet.sequence)),
        ("source_client", scval_string(&packet.source_client)?),
        ("timeout_timestamp", ScVal::U64(packet.timeout_timestamp)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ibc::packet::{Packet as EventPacket, Payload as EventPayload};
    use crate::ibc::v2_msgs::TYPE_URL_RECV_PACKET;

    fn reference_event() -> PacketEvent {
        PacketEvent {
            kind: SEND_PACKET.to_string(),
            tx_hash: "2c20a54f9381f365ccd40356732da798fa77e3e91826ce0b5322764989167589".to_string(),
            ledger: 3_785_597,
            acknowledgements: Vec::new(),
            packet: EventPacket {
                sequence: 1,
                source_client: "07-tendermint-5".to_string(),
                dest_client: "08-wasm-0".to_string(),
                timeout_timestamp: 1_784_946_743,
                payloads: vec![EventPayload {
                    source_port: "transfer".to_string(),
                    dest_port: "transfer".to_string(),
                    version: "ics20-1".to_string(),
                    encoding: "application/json".to_string(),
                    value: br#"{"denom":"XLM","amount":"1000"}"#.to_vec(),
                }],
            },
        }
    }

    #[test]
    fn builds_a_recv_msg_matching_the_hermes_reference() {
        let signer = "cosmos1mz5kk8dh85ss9dlx5e99cvkl60x92fkmtk6rxj";
        let msgs = recv_msgs(&[reference_event()], signer);

        assert_eq!(msgs.len(), 1);
        let packet = msgs[0].packet.as_ref().unwrap();
        assert_eq!(packet.sequence, 1);
        assert_eq!(packet.source_client, "07-tendermint-5");
        assert_eq!(packet.dest_client, "08-wasm-0");
        assert_eq!(packet.timeout_timestamp, 1_784_946_743);
        assert_eq!(packet.payloads.len(), 1);
        assert_eq!(packet.payloads[0].version, "ics20-1");
        assert_eq!(packet.payloads[0].encoding, "application/json");
        assert_eq!(msgs[0].signer, signer);
    }

    #[test]
    fn messages_are_built_without_proofs() {
        let recv = recv_msgs(&[reference_event()], "cosmos1abc");

        assert!(recv[0].proof_commitment.is_empty());
        assert_eq!(recv[0].proof_height, None);
    }

    #[test]
    fn ack_msgs_select_write_ack_events_only() {
        let send = reference_event();
        let mut write_ack = reference_event();
        write_ack.kind = WRITE_ACK.to_string();
        write_ack.acknowledgements = vec![b"\x01".to_vec()];

        let acks = ack_msgs(&[send, write_ack], "cosmos1abc");

        assert_eq!(acks.len(), 1);
        assert_eq!(acks[0].acknowledgements, vec![b"\x01".to_vec()]);
        assert!(acks[0].proof_acked.is_empty());
    }

    #[test]
    fn a_header_is_wrapped_for_the_wasm_client() {
        let any = wasm_client_message(b"header-bytes".to_vec());

        assert_eq!(any.type_url, TYPE_URL_WASM_CLIENT_MESSAGE);
        let inner = WasmClientMessage::decode(any.value.as_slice()).unwrap();
        assert_eq!(inner.data, b"header-bytes");
    }

    #[test]
    fn an_update_carries_the_client_id_and_wrapped_header() {
        let any = update_client_msg(
            "08-wasm-0",
            wasm_client_message(b"header-bytes".to_vec()),
            "cosmos1abc",
        );

        assert_eq!(any.type_url, TYPE_URL_UPDATE_CLIENT);
        let msg = MsgUpdateClient::decode(any.value.as_slice()).unwrap();
        assert_eq!(msg.client_id, "08-wasm-0");
        assert_eq!(msg.signer, "cosmos1abc");

        let carried = msg.client_message.unwrap();
        assert_eq!(carried.type_url, TYPE_URL_WASM_CLIENT_MESSAGE);
        assert_eq!(
            WasmClientMessage::decode(carried.value.as_slice())
                .unwrap()
                .data,
            b"header-bytes"
        );
    }

    #[test]
    fn tx_body_puts_update_client_first() {
        let update = Any {
            type_url: "/ibc.core.client.v1.MsgUpdateClient".to_string(),
            value: Vec::new(),
        };
        let recv = recv_msgs(&[reference_event()], "cosmos1abc");

        let bytes = encode_tx_body(Some(update), recv, Vec::new());
        let body = TxBody::decode(bytes.as_slice()).unwrap();

        assert_eq!(body.messages.len(), 2);
        assert_eq!(
            body.messages[0].type_url,
            "/ibc.core.client.v1.MsgUpdateClient"
        );
        assert_eq!(body.messages[1].type_url, TYPE_URL_RECV_PACKET);
    }
}
