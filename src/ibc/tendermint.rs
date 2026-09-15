use anyhow::{anyhow, Context, Result};

use ibc::core::commitment_types::specs::ProofSpecs;

use crate::ibc::client_state::AnyClientState;
use crate::ibc::consensus_state::AnyConsensusState;
use ibc_proto::ibc::core::client::v1::Height as RawHeight;
use ibc_proto::ibc::lightclients::tendermint::v1::Header as RawTmHeader;
use prost::Message;
use serde_json::Value;
use tendermint::block::signed_header::SignedHeader;
use tendermint::validator::{Info as ValidatorInfo, Set as ValidatorSet};

pub fn header_proto(
    commit: &Value,
    validators: &Value,
    trusted_height: u64,
    revision_number: u64,
) -> Result<Vec<u8>> {
    let signed_header: SignedHeader = serde_json::from_value(
        commit
            .get("signed_header")
            .cloned()
            .ok_or_else(|| anyhow!("/commit carries no signed_header"))?,
    )
    .context("signed_header is not a tendermint SignedHeader")?;

    let infos: Vec<ValidatorInfo> = serde_json::from_value(
        validators
            .get("validators")
            .cloned()
            .ok_or_else(|| anyhow!("/validators carries no validators"))?,
    )
    .context("validators are not tendermint validator info")?;

    if infos.is_empty() {
        return Err(anyhow!("/validators returned an empty set"));
    }

    let proposer = signed_header.header.proposer_address;
    let set = ValidatorSet::new(
        infos.clone(),
        infos.iter().find(|v| v.address == proposer).cloned(),
    );

    let header = RawTmHeader {
        signed_header: Some(signed_header.into()),
        validator_set: Some(set.clone().into()),
        trusted_height: Some(RawHeight {
            revision_number,
            revision_height: trusted_height,
        }),
        trusted_validators: Some(set.into()),
    };

    Ok(header.encode_to_vec())
}

pub struct TendermintBootstrap {
    pub chain_id: String,
    pub height: u64,
    pub trusting_period_secs: u64,
    pub unbonding_period_secs: u64,
    pub max_clock_drift_secs: u64,
}

#[derive(Debug)]
pub struct TendermintGenesis {
    pub client_state_xdr: Vec<u8>,
    pub consensus_state_xdr: Vec<u8>,
    pub chain_id: String,
    pub height: u64,
}

#[allow(deprecated)]
pub fn tendermint_genesis(
    header_proto: &[u8],
    params: &TendermintBootstrap,
) -> Result<TendermintGenesis> {
    use ibc_proto::ibc::core::commitment::v1::MerkleRoot;
    use ibc_proto::ibc::lightclients::tendermint::v1::{
        ClientState as RawClientState, ConsensusState as RawConsensusState, Fraction,
    };

    let header = RawTmHeader::decode(header_proto)
        .context("the cosmos header does not decode as a tendermint Header")?;

    let signed = header
        .signed_header
        .ok_or_else(|| anyhow!("the cosmos header carries no signed_header"))?;
    let inner = signed
        .header
        .ok_or_else(|| anyhow!("the signed header carries no header"))?;

    let chain_id = if params.chain_id.is_empty() {
        inner.chain_id.clone()
    } else {
        params.chain_id.clone()
    };

    if chain_id != inner.chain_id {
        return Err(anyhow!(
            "configured chain id {chain_id} does not match the header's {}",
            inner.chain_id
        ));
    }

    let height = u64::try_from(inner.height)
        .map_err(|_| anyhow!("the header height {} is negative", inner.height))?;

    let client_state = RawClientState {
        chain_id: chain_id.clone(),
        trust_level: Some(Fraction {
            numerator: 1,
            denominator: 3,
        }),
        trusting_period: Some(seconds(params.trusting_period_secs)),
        unbonding_period: Some(seconds(params.unbonding_period_secs)),
        max_clock_drift: Some(seconds(params.max_clock_drift_secs)),
        frozen_height: Some(RawHeight {
            revision_number: 0,
            revision_height: 0,
        }),
        latest_height: Some(RawHeight {
            revision_number: revision_of(&chain_id),
            revision_height: height,
        }),
        proof_specs: ProofSpecs::cosmos().into(),
        upgrade_path: vec!["upgrade".to_string(), "upgradedIBCState".to_string()],
        allow_update_after_expiry: false,
        allow_update_after_misbehaviour: false,
    };

    let timestamp = inner
        .time
        .ok_or_else(|| anyhow!("the header carries no time"))?;

    let consensus_state = RawConsensusState {
        timestamp: Some(timestamp),
        root: Some(MerkleRoot {
            hash: inner.app_hash.clone(),
        }),
        next_validators_hash: inner.next_validators_hash.clone(),
    };

    let client_state_xdr = AnyClientState::decode_value(&client_state.encode_to_vec())
        .context("re-reading the client state we just built")?
        .to_soroban_xdr()
        .context("client state to soroban xdr")?;

    let consensus_state_xdr = AnyConsensusState::decode_value(&consensus_state.encode_to_vec())
        .context("re-reading the consensus state we just built")?
        .to_soroban_xdr()
        .context("consensus state to soroban xdr")?;

    Ok(TendermintGenesis {
        client_state_xdr,
        consensus_state_xdr,
        chain_id,
        height,
    })
}

fn seconds(secs: u64) -> ibc_proto::google::protobuf::Duration {
    ibc_proto::google::protobuf::Duration {
        seconds: i64::try_from(secs).unwrap_or(i64::MAX),
        nanos: 0,
    }
}

// ibc-go reads the revision from the chain id's trailing -N, and a client whose
// revision disagrees rejects every header it is later given.
fn revision_of(chain_id: &str) -> u64 {
    chain_id
        .rsplit_once('-')
        .and_then(|(_, tail)| tail.parse().ok())
        .unwrap_or(0)
}
