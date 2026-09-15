use soroban_client::xdr::{Limits, ScVal, WriteXdr};

use crate::{
    conversion::string_field,
    types::{EventCursor, EventRecord, EventsPage, LedgerData, SubmittedTx},
};

#[derive(Clone)]
pub struct ApiClient {
    base_url: String,
    http: reqwest::Client,
}

impl ApiClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            http: reqwest::Client::new(),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    async fn get_json(&self, path: &str) -> anyhow::Result<serde_json::Value> {
        let resp = self
            .http
            .get(self.url(path))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("GET {path} failed: {e}"))?;
        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("GET {path} response parse failed: {e}"))?;
        if !status.is_success() {
            return Err(anyhow::anyhow!("GET {path} returned {status}: {body}"));
        }
        Ok(body)
    }

    async fn post_json(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let resp = self
            .http
            .post(self.url(path))
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("POST {path} failed: {e}"))?;
        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("POST {path} response parse failed: {e}"))?;
        if !status.is_success() {
            return Err(anyhow::anyhow!("POST {path} returned {status}: {body}"));
        }
        Ok(body)
    }

    pub async fn get_latest_ledger(&self) -> anyhow::Result<u32> {
        let body = self.get_json("/ledger/latest").await?;
        body.get("sequence")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .ok_or_else(|| anyhow::anyhow!("missing 'sequence' in /ledger/latest response"))
    }

    pub async fn get_archive_latest_ledger(&self) -> anyhow::Result<u32> {
        let body = self.get_json("/archive/latest").await?;
        body.get("ledger")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .ok_or_else(|| anyhow::anyhow!("missing 'ledger' in /archive/latest response"))
    }

    pub async fn get_transfer_balance(
        &self,
        contract_id: &str,
        source_account: &str,
        denom: &str,
        address_hex: &str,
    ) -> anyhow::Result<i128> {
        let body = self
            .get_json(&format!(
                "/stellar/transfer/balance/{denom}/{address_hex}?contract_id={contract_id}&source_account={source_account}"
            ))
            .await?;
        body.get("balance")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<i128>().ok())
            .ok_or_else(|| {
                anyhow::anyhow!("missing/invalid 'balance' in transfer balance response")
            })
    }

    pub async fn list_client_ids(&self, contract_id: &str) -> anyhow::Result<Vec<String>> {
        let body = self
            .get_json(&format!("/stellar/clients?contract_id={contract_id}"))
            .await?;
        let mut ids = Vec::new();
        if let Some(groups) = body.get("clients").and_then(|c| c.as_array()) {
            for group in groups {
                if let Some(arr) = group.get("client_ids").and_then(|v| v.as_array()) {
                    ids.extend(arr.iter().filter_map(|v| v.as_str().map(str::to_string)));
                }
            }
        }
        Ok(ids)
    }

    pub async fn get_client_state_xdr(
        &self,
        contract_id: &str,
        source_account: &str,
        client_id: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let body = self
            .get_json(&format!(
                "/stellar/clients/{client_id}/state?contract_id={contract_id}&source_account={source_account}"
            ))
            .await?;
        let hex = body
            .get("client_state_xdr")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing 'client_state_xdr' in response"))?;
        hex::decode(hex).map_err(|e| anyhow::anyhow!("client_state_xdr hex decode: {e}"))
    }

    pub async fn get_consensus_state_xdr(
        &self,
        contract_id: &str,
        source_account: &str,
        client_id: &str,
        height: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let body = self
            .get_json(&format!(
                "/stellar/clients/{client_id}/consensus/{height}?contract_id={contract_id}&source_account={source_account}"
            ))
            .await?;
        let hex = body
            .get("consensus_state_xdr")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing 'consensus_state_xdr' in response"))?;
        hex::decode(hex).map_err(|e| anyhow::anyhow!("consensus_state_xdr hex decode: {e}"))
    }

    pub async fn get_ledger(&self, sequence: u32) -> anyhow::Result<LedgerData> {
        let body = self.get_json(&format!("/ledger/{sequence}")).await?;

        let header_hex = body
            .get("header_xdr")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing 'header_xdr' for ledger {sequence}"))?;
        let header_xdr =
            hex::decode(header_hex).map_err(|e| anyhow::anyhow!("header_xdr hex decode: {e}"))?;

        let metadata_xdr = match body.get("metadata_xdr").and_then(|v| v.as_str()) {
            Some(meta_hex) => Some(
                hex::decode(meta_hex)
                    .map_err(|e| anyhow::anyhow!("metadata_xdr hex decode: {e}"))?,
            ),
            _ => None,
        };

        Ok(LedgerData {
            sequence,
            header_xdr,
            metadata_xdr,
        })
    }

    pub async fn get_archive_scp(&self, ledger: u32) -> anyhow::Result<ScpMaterial> {
        let body = self.get_json(&format!("/archive/scp/{ledger}")).await?;

        Ok(ScpMaterial {
            quorum_sets_xdr: hex_array(&body, "quorum_sets_xdr")?,
            envelopes_xdr: hex_array(&body, "envelopes_xdr")?,
        })
    }

    pub async fn get_archive_ledger_header(
        &self,
        ledger: u32,
    ) -> anyhow::Result<ArchivedLedgerHeader> {
        let body = self
            .get_json(&format!("/archive/ledger-header/{ledger}"))
            .await?;

        let hash: [u8; 32] = hex_field(&body, "hash")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("archive ledger hash is not 32 bytes"))?;

        Ok(ArchivedLedgerHeader {
            header_xdr: hex_field(&body, "header_xdr")?,
            recorded_hash: hash,
        })
    }

    pub async fn get_archive_tx_set(&self, ledger: u32) -> anyhow::Result<Vec<u8>> {
        let body = self.get_json(&format!("/archive/tx-set/{ledger}")).await?;
        hex_field(&body, "generalized_tx_set_xdr")
    }

    pub async fn get_events(
        &self,
        contract_id: &str,
        cursor: EventCursor,
        limit: Option<u32>,
    ) -> anyhow::Result<EventsPage> {
        let mut path = format!("/events?contract_id={contract_id}");
        match cursor {
            EventCursor::Cursor(c) => path.push_str(&format!("&cursor={c}")),
            EventCursor::StartLedger(s) => path.push_str(&format!("&start_ledger={s}")),
        }
        if let Some(limit) = limit {
            path.push_str(&format!("&limit={limit}"));
        }

        let body = self.get_json(&path).await?;

        let latest_ledger = body
            .get("latest_ledger")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .ok_or_else(|| anyhow::anyhow!("missing 'latest_ledger' in /events response"))?;
        let cursor = body
            .get("cursor")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned();

        let raw_events = body
            .get("events")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow::anyhow!("missing 'events' array in /events response"))?;

        let mut events = Vec::with_capacity(raw_events.len());
        for ev in raw_events {
            let topics_xdr = ev
                .get("topics_xdr")
                .and_then(|v| v.as_array())
                .map(|topics| {
                    topics
                        .iter()
                        .filter_map(|t| t.as_str())
                        .map(hex::decode)
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()
                .map_err(|e| anyhow::anyhow!("topics_xdr hex decode: {e}"))?
                .unwrap_or_default();

            let value_xdr = ev
                .get("value_xdr")
                .and_then(|v| v.as_str())
                .map(hex::decode)
                .transpose()
                .map_err(|e| anyhow::anyhow!("value_xdr hex decode: {e}"))?
                .unwrap_or_default();

            events.push(EventRecord {
                id: string_field(ev, "id"),
                ledger: ev.get("ledger").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                ledger_closed_at: string_field(ev, "ledger_closed_at"),
                contract_id: string_field(ev, "contract_id"),
                tx_hash: string_field(ev, "tx_hash"),
                topics_xdr,
                value_xdr,
            });
        }

        Ok(EventsPage {
            latest_ledger,
            cursor,
            events,
        })
    }

    pub async fn build_unsigned_tx(
        &self,
        contract_id: &str,
        signer: &str,
        method: &str,
        args: Vec<ScVal>,
    ) -> anyhow::Result<Vec<u8>> {
        let args_xdr = args
            .iter()
            .map(|arg| {
                arg.to_xdr(Limits::none())
                    .map(hex::encode)
                    .map_err(|e| anyhow::anyhow!("ScVal XDR encode: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let body = serde_json::json!({
            "contract_id": contract_id,
            "signer": signer,
            "method": method,
            "args_xdr": args_xdr,
        });
        let resp = self.post_json("/tx/prepare", body).await?;

        let tx_hex = resp
            .get("tx_xdr")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing 'tx_xdr' in /tx/prepare response"))?;

        hex::decode(tx_hex).map_err(|e| anyhow::anyhow!("tx_xdr hex decode: {e}"))
    }

    pub async fn submit_and_wait(&self, tx_xdr: &[u8]) -> anyhow::Result<SubmittedTx> {
        let body = serde_json::json!({ "tx_xdr": hex::encode(tx_xdr) });
        let resp = self.post_json("/tx/submit", body).await?;
        let hash = resp
            .get("hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing 'hash' in /tx/submit response"))?
            .to_owned();
        let return_value = match resp.get("return_value_xdr").and_then(|v| v.as_str()) {
            Some(value_hex) => {
                let bytes = hex::decode(value_hex)
                    .map_err(|e| anyhow::anyhow!("return_value_xdr hex decode: {e}"))?;
                Some(crate::conversion::scval_from_xdr(&bytes)?)
            }
            _ => None,
        };

        Ok(SubmittedTx { hash, return_value })
    }
}

#[derive(Clone, Debug)]
pub struct ScpMaterial {
    pub quorum_sets_xdr: Vec<Vec<u8>>,
    pub envelopes_xdr: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct ArchivedLedgerHeader {
    pub header_xdr: Vec<u8>,
    pub recorded_hash: [u8; 32],
}

fn hex_field(body: &serde_json::Value, key: &str) -> anyhow::Result<Vec<u8>> {
    let raw = body
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing '{key}' in archive response"))?;
    hex::decode(raw).map_err(|e| anyhow::anyhow!("{key} hex decode: {e}"))
}

fn hex_array(body: &serde_json::Value, key: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    body.get(key)
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("missing '{key}' in archive response"))?
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let raw = v
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("{key}[{i}] is not a string"))?;
            hex::decode(raw).map_err(|e| anyhow::anyhow!("{key}[{i}] hex decode: {e}"))
        })
        .collect()
}

#[derive(Clone, Debug)]
pub struct CosmosPacketEvent {
    pub kind: String,
    pub height: u64,
    pub packet: crate::ibc::v2_msgs::Packet,
    pub acknowledgements: Vec<Vec<u8>>,
}

impl ApiClient {
    pub async fn get_cosmos_latest_height(&self) -> anyhow::Result<u64> {
        let body = self.get_json("/cosmos/latest").await?;
        body.get("height")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("/cosmos/latest carries no height"))
    }

    pub async fn get_cosmos_packet_events(
        &self,
        tx_hash: &str,
    ) -> anyhow::Result<Vec<CosmosPacketEvent>> {
        let body = self
            .get_json(&format!("/cosmos/tx/{tx_hash}/packets"))
            .await?;

        let events = body
            .get("events")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow::anyhow!("/cosmos/tx/{tx_hash}/packets carries no events"))?;

        let mut out = Vec::with_capacity(events.len());
        for event in events {
            let kind = event
                .get("kind")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("a cosmos packet event carries no kind"))?
                .to_string();
            let height = event
                .get("height")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow::anyhow!("a cosmos packet event carries no height"))?;
            let packet_proto = hex::decode(
                event
                    .get("packet_proto")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("a cosmos packet event carries no packet"))?,
            )?;
            let acknowledgements = event
                .get("acknowledgements")
                .and_then(|v| v.as_array())
                .map(|acks| {
                    acks.iter()
                        .filter_map(|a| a.as_str())
                        .map(hex::decode)
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?
                .unwrap_or_default();

            out.push(CosmosPacketEvent {
                kind,
                height,
                packet: crate::ibc::msg::decode_packet(&packet_proto)?,
                acknowledgements,
            });
        }

        Ok(out)
    }

    pub async fn get_cosmos_header(
        &self,
        height: u64,
        trusted_height: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let body = self
            .get_json(&format!(
                "/cosmos/header/{height}?trusted_height={trusted_height}"
            ))
            .await?;

        hex_field(&body, "header")
    }

    pub async fn get_cosmos_proof(
        &self,
        key: &[u8],
        height: u64,
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let body = self
            .get_json(&format!(
                "/cosmos/proof?key={}&height={height}",
                hex::encode(key)
            ))
            .await?;

        Ok((hex_field(&body, "value")?, hex_field(&body, "proof")?))
    }
}
