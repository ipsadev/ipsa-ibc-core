use anyhow::{anyhow, Result};
use ibc::clients::tendermint::client_state::ClientState as TmClientState;
use ibc::clients::tendermint::consensus_state::ConsensusState as TmConsensusState;
use ibc::core::commitment_types::specs::ProofSpecs;
use ibc_proto::google::protobuf::{Duration, Timestamp};
use ibc_proto::ibc::core::client::v1::Height as RawHeight;
use ibc_proto::ibc::core::commitment::v1::MerkleRoot;
use ibc_proto::ibc::lightclients::tendermint::v1::{
    ClientState as RawTmClientState, ConsensusState as RawTmConsensusState, Fraction,
    Header as RawTmHeader,
};
use prost::Message;
use soroban_client::xdr::{ScMap, ScVal};

use super::client_state::AnyClientState;
use super::consensus_state::AnyConsensusState;
use crate::conversion::{
    scval_as_map, scval_bytes, scval_from_xdr, scval_height, scval_map_as_map, scval_map_bytes,
    scval_map_string, scval_map_u32, scval_map_u64, scval_string, scval_struct, scval_to_xdr,
};

fn sc_get_height(map: &ScMap, name: &str) -> Result<RawHeight> {
    let h = scval_map_as_map(map, name)?;
    Ok(RawHeight {
        revision_number: scval_map_u64(h, "revision_number")?,
        revision_height: scval_map_u64(h, "revision_height")?,
    })
}

impl AnyClientState {
    pub fn to_soroban_xdr(&self) -> Result<Vec<u8>> {
        let AnyClientState::Tendermint(cs) = self;
        let cs = cs.inner();

        let trust_level = scval_struct(vec![
            ("numerator", ScVal::U32(cs.trust_level.numerator() as u32)),
            (
                "denominator",
                ScVal::U32(cs.trust_level.denominator() as u32),
            ),
        ])?;

        let (frozen_rn, frozen_rh) = cs
            .frozen_height
            .as_ref()
            .map(|h| (h.revision_number(), h.revision_height()))
            .unwrap_or((0, 0));

        let state = scval_struct(vec![
            ("chain_id", scval_string(cs.chain_id.as_str())?),
            ("trust_level", trust_level),
            (
                "trusting_period_secs",
                ScVal::U64(cs.trusting_period.as_secs()),
            ),
            (
                "unbonding_period_secs",
                ScVal::U64(cs.unbonding_period.as_secs()),
            ),
            (
                "max_clock_drift_secs",
                ScVal::U64(cs.max_clock_drift.as_secs()),
            ),
            (
                "latest_height",
                scval_height(
                    cs.latest_height.revision_number(),
                    cs.latest_height.revision_height(),
                )?,
            ),
            ("is_frozen", ScVal::Bool(cs.frozen_height.is_some())),
            ("frozen_height", scval_height(frozen_rn, frozen_rh)?),
            ("proof_specs", scval_bytes(&[])?),
        ])?;

        scval_to_xdr(&state)
    }

    #[allow(deprecated)]
    pub fn from_soroban_xdr(bytes: &[u8]) -> Result<Self> {
        let val = scval_from_xdr(bytes)?;
        let map = scval_as_map(&val).ok_or_else(|| anyhow!("client_state is not a map"))?;

        let trust = scval_map_as_map(map, "trust_level")?;
        let frozen_height = Some(sc_get_height(map, "frozen_height")?);

        let raw = RawTmClientState {
            chain_id: scval_map_string(map, "chain_id")?,
            trust_level: Some(Fraction {
                numerator: scval_map_u32(trust, "numerator")? as u64,
                denominator: scval_map_u32(trust, "denominator")? as u64,
            }),
            trusting_period: Some(Duration {
                seconds: scval_map_u64(map, "trusting_period_secs")? as i64,
                nanos: 0,
            }),
            unbonding_period: Some(Duration {
                seconds: scval_map_u64(map, "unbonding_period_secs")? as i64,
                nanos: 0,
            }),
            max_clock_drift: Some(Duration {
                seconds: scval_map_u64(map, "max_clock_drift_secs")? as i64,
                nanos: 0,
            }),
            frozen_height,
            latest_height: Some(sc_get_height(map, "latest_height")?),
            proof_specs: ProofSpecs::cosmos().into(),
            upgrade_path: vec!["upgrade".to_string(), "upgradedIBCState".to_string()],
            allow_update_after_expiry: false,
            allow_update_after_misbehaviour: false,
        };

        let cs = TmClientState::try_from(raw)
            .map_err(|e| anyhow!("tendermint client state from raw: {e}"))?;

        Ok(AnyClientState::Tendermint(cs))
    }
}

pub fn tendermint_header_to_soroban_xdr(header_bytes: &[u8]) -> Result<Vec<u8>> {
    let header =
        RawTmHeader::decode(header_bytes).map_err(|e| anyhow!("decode tendermint header: {e}"))?;

    let signed_header = header
        .signed_header
        .ok_or_else(|| anyhow!("tendermint header missing signed_header"))?;
    let inner = signed_header
        .header
        .as_ref()
        .ok_or_else(|| anyhow!("signed_header missing inner header"))?;
    let trusted_height = header
        .trusted_height
        .ok_or_else(|| anyhow!("tendermint header missing trusted_height"))?;

    let target_revision_height =
        u64::try_from(inner.height).map_err(|_| anyhow!("negative target height"))?;
    let timestamp_secs = inner
        .time
        .as_ref()
        .map(|t| t.seconds.max(0) as u64)
        .unwrap_or(0);
    let next_validators_hash = inner.next_validators_hash.clone();
    let app_hash = inner.app_hash.clone();

    if next_validators_hash.len() != 32 {
        return Err(anyhow!(
            "next_validators_hash is {} bytes, expected 32",
            next_validators_hash.len()
        ));
    }
    if app_hash.len() != 32 {
        return Err(anyhow!("app_hash is {} bytes, expected 32", app_hash.len()));
    }

    let validator_set_bytes = header
        .validator_set
        .as_ref()
        .map(|v| v.encode_to_vec())
        .unwrap_or_default();
    let signed_header_bytes = signed_header.encode_to_vec();

    let state = scval_struct(vec![
        (
            "trusted_height",
            scval_height(
                trusted_height.revision_number,
                trusted_height.revision_height,
            )?,
        ),
        (
            "target_height",
            scval_height(trusted_height.revision_number, target_revision_height)?,
        ),
        ("timestamp_secs", ScVal::U64(timestamp_secs)),
        ("next_validators_hash", scval_bytes(&next_validators_hash)?),
        ("app_hash", scval_bytes(&app_hash)?),
        ("signed_header_bytes", scval_bytes(&signed_header_bytes)?),
        ("validator_set_bytes", scval_bytes(&validator_set_bytes)?),
    ])?;

    scval_to_xdr(&state)
}

impl AnyConsensusState {
    pub fn to_soroban_xdr(&self) -> Result<Vec<u8>> {
        let AnyConsensusState::Tendermint(cons) = self;
        let cons = cons.inner();

        let timestamp_secs = cons.timestamp.unix_timestamp().max(0) as u64;
        let next_validators_hash = cons.next_validators_hash.as_bytes().to_vec();
        let root = cons.root.as_bytes().to_vec();

        let state = scval_struct(vec![
            ("timestamp_secs", ScVal::U64(timestamp_secs)),
            ("next_validators_hash", scval_bytes(&next_validators_hash)?),
            ("root", scval_bytes(&root)?),
        ])?;

        scval_to_xdr(&state)
    }

    pub fn from_soroban_xdr(bytes: &[u8]) -> Result<Self> {
        let val = scval_from_xdr(bytes)?;
        let map = scval_as_map(&val).ok_or_else(|| anyhow!("consensus_state is not a map"))?;

        let timestamp_secs = scval_map_u64(map, "timestamp_secs")?;
        let next_validators_hash = scval_map_bytes(map, "next_validators_hash")?;
        let root = scval_map_bytes(map, "root")?;

        let raw = RawTmConsensusState {
            timestamp: Some(Timestamp {
                seconds: timestamp_secs as i64,
                nanos: 0,
            }),
            root: Some(MerkleRoot { hash: root }),
            next_validators_hash,
        };

        let cons = TmConsensusState::try_from(raw)
            .map_err(|e| anyhow!("tendermint consensus state from raw: {e}"))?;

        Ok(AnyConsensusState::Tendermint(cons))
    }
}
