use anyhow::{anyhow, Result};
use ibc::clients::tendermint::client_state::ClientState as TmClientState;
use ibc::primitives::proto::{Any, Protobuf};
use ibc_proto::ibc::lightclients::tendermint::v1::ClientState as RawTmClientState;

pub const TENDERMINT_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.tendermint.v1.ClientState";

#[derive(Clone, Debug)]
pub enum AnyClientState {
    Tendermint(TmClientState),
}

impl Protobuf<Any> for AnyClientState {}

impl TryFrom<Any> for AnyClientState {
    type Error = anyhow::Error;

    fn try_from(raw: Any) -> Result<Self> {
        match raw.type_url.as_str() {
            TENDERMINT_CLIENT_STATE_TYPE_URL => Ok(AnyClientState::Tendermint(
                Protobuf::<RawTmClientState>::decode_vec(raw.value.as_slice())
                    .map_err(|e| anyhow!("decode tendermint client state: {e}"))?,
            )),
            other => Err(anyhow!("unknown client state type_url: {other}")),
        }
    }
}

impl From<AnyClientState> for Any {
    fn from(value: AnyClientState) -> Self {
        match value {
            AnyClientState::Tendermint(cs) => Any {
                type_url: TENDERMINT_CLIENT_STATE_TYPE_URL.to_string(),
                value: Protobuf::<RawTmClientState>::encode_vec(cs),
            },
        }
    }
}

impl From<TmClientState> for AnyClientState {
    fn from(cs: TmClientState) -> Self {
        AnyClientState::Tendermint(cs)
    }
}

impl AnyClientState {
    pub fn decode_value(bytes: &[u8]) -> Result<Self> {
        let cs = Protobuf::<RawTmClientState>::decode_vec(bytes)
            .map_err(|e| anyhow!("decode tendermint client state value: {e}"))?;
        Ok(AnyClientState::Tendermint(cs))
    }

    pub fn encode_value(&self) -> Vec<u8> {
        match self {
            AnyClientState::Tendermint(cs) => Protobuf::<RawTmClientState>::encode_vec(cs.clone()),
        }
    }

    pub fn chain_id(&self) -> String {
        match self {
            AnyClientState::Tendermint(cs) => cs.inner().chain_id.to_string(),
        }
    }

    pub fn revision_number(&self) -> u64 {
        match self {
            AnyClientState::Tendermint(cs) => cs.inner().latest_height.revision_number(),
        }
    }

    pub fn latest_height(&self) -> u64 {
        match self {
            AnyClientState::Tendermint(cs) => cs.inner().latest_height.revision_height(),
        }
    }
}
