use ibc_proto::google::protobuf::Any;
use prost::Message;

pub const TYPE_URL_RECV_PACKET: &str = "/ibc.core.channel.v2.MsgRecvPacket";
pub const TYPE_URL_ACKNOWLEDGEMENT: &str = "/ibc.core.channel.v2.MsgAcknowledgement";
pub const TYPE_URL_TIMEOUT: &str = "/ibc.core.channel.v2.MsgTimeout";

#[derive(Clone, PartialEq, Eq, Message)]
pub struct Height {
    #[prost(uint64, tag = "1")]
    pub revision_number: u64,
    #[prost(uint64, tag = "2")]
    pub revision_height: u64,
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct Payload {
    #[prost(string, tag = "1")]
    pub source_port: String,
    #[prost(string, tag = "2")]
    pub dest_port: String,
    #[prost(string, tag = "3")]
    pub version: String,
    #[prost(string, tag = "4")]
    pub encoding: String,
    #[prost(bytes = "vec", tag = "5")]
    pub value: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct Acknowledgement {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub app_acknowledgements: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct Packet {
    #[prost(uint64, tag = "1")]
    pub sequence: u64,
    #[prost(string, tag = "2")]
    pub source_client: String,
    #[prost(string, tag = "3")]
    pub dest_client: String,
    #[prost(uint64, tag = "4")]
    pub timeout_timestamp: u64,
    #[prost(message, repeated, tag = "5")]
    pub payloads: Vec<Payload>,
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct MsgRecvPacket {
    #[prost(message, optional, tag = "1")]
    pub packet: Option<Packet>,
    #[prost(bytes = "vec", tag = "2")]
    pub proof_commitment: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub proof_height: Option<Height>,
    #[prost(string, tag = "4")]
    pub signer: String,
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct MsgAcknowledgement {
    #[prost(message, optional, tag = "1")]
    pub packet: Option<Packet>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub acknowledgements: Vec<Vec<u8>>,
    #[prost(bytes = "vec", tag = "3")]
    pub proof_acked: Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub proof_height: Option<Height>,
    #[prost(string, tag = "5")]
    pub signer: String,
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct MsgTimeout {
    #[prost(message, optional, tag = "1")]
    pub packet: Option<Packet>,
    #[prost(bytes = "vec", tag = "2")]
    pub proof_unreceived: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub proof_height: Option<Height>,
    #[prost(string, tag = "4")]
    pub signer: String,
}

macro_rules! impl_into_any {
    ($msg:ty, $url:expr) => {
        impl From<$msg> for Any {
            fn from(value: $msg) -> Self {
                Any {
                    type_url: $url.to_string(),
                    value: value.encode_to_vec(),
                }
            }
        }
    };
}

impl_into_any!(MsgRecvPacket, TYPE_URL_RECV_PACKET);
impl_into_any!(MsgAcknowledgement, TYPE_URL_ACKNOWLEDGEMENT);
impl_into_any!(MsgTimeout, TYPE_URL_TIMEOUT);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recv_packet_encodes_into_any() {
        let msg = MsgRecvPacket {
            packet: Some(Packet {
                sequence: 1,
                source_client: "07-tendermint-5".to_string(),
                dest_client: "08-wasm-0".to_string(),
                timeout_timestamp: 1_784_946_743,
                payloads: vec![Payload {
                    source_port: "transfer".to_string(),
                    dest_port: "transfer".to_string(),
                    version: "ics20-1".to_string(),
                    encoding: "application/json".to_string(),
                    value: b"{}".to_vec(),
                }],
            }),
            proof_commitment: b"mock".to_vec(),
            proof_height: Some(Height {
                revision_number: 0,
                revision_height: 3_785_598,
            }),
            signer: "cosmos1mz5kk8dh85ss9dlx5e99cvkl60x92fkmtk6rxj".to_string(),
        };

        let any: Any = msg.clone().into();
        assert_eq!(any.type_url, TYPE_URL_RECV_PACKET);
        assert_eq!(MsgRecvPacket::decode(any.value.as_slice()).unwrap(), msg);
    }
}
