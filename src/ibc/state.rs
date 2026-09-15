use std::collections::HashMap;

use sha2::{Digest, Sha256};
use soroban_client::xdr::{
    ContractEvent, ContractEventBody, LedgerCloseMeta, LedgerEntryChange, LedgerEntryData,
    LedgerKey, Limits, ReadXdr, ScAddress, ScVal, TransactionMeta,
};

use crate::{
    api_client::ApiClient,
    conversion::{scval_as_bytes, scval_to_v2_path},
    proof::{serialize_membership_proof_with_index, serialize_non_membership_proof_with_index},
    smt::Smt,
    types::EventCursor,
};
pub enum PathLookup {
    Found {
        value_hash: [u8; 32],
        proof_bytes: Vec<u8>,
    },
    Absent {
        proof_bytes: Vec<u8>,
    },
}

fn cursor_ledger(cursor: &str) -> Option<u32> {
    let toid: u64 = cursor.split('-').next()?.parse().ok()?;
    u32::try_from(toid >> 32).ok()
}

fn key_index(key: &[u8]) -> u64 {
    let h: [u8; 32] = Sha256::digest(key).into();
    u64::from_be_bytes(h[..8].try_into().expect("sha256 has 32 bytes"))
}

pub struct State {
    api: ApiClient,
    roots: HashMap<u32, [u8; 32]>,
    ibc_contract_id: Option<[u8; 32]>,
    router_address: Option<String>,
    smt: Smt,
    last_processed: Option<u32>,
    genesis_ledger: Option<u32>,
    published: HashMap<u32, [u8; 32]>,
}

impl State {
    pub fn new(
        api: ApiClient,
        ibc_contract_id: Option<[u8; 32]>,
        router_address: Option<String>,
    ) -> Self {
        Self {
            api,
            roots: HashMap::new(),
            ibc_contract_id,
            router_address,
            smt: Smt::new(),
            last_processed: None,
            genesis_ledger: None,
            published: HashMap::new(),
        }
    }

    pub fn with_genesis_ledger(mut self, genesis: Option<u32>) -> Self {
        self.genesis_ledger = genesis;
        self
    }

    pub fn genesis_ledger(&self) -> Option<u32> {
        self.genesis_ledger
    }

    pub async fn root_at(&mut self, seq: u32) -> anyhow::Result<[u8; 32]> {
        if let Some(&root) = self.roots.get(&seq) {
            return Ok(root);
        }
        self.process_through(seq).await
    }

    pub async fn proof_for_path(&mut self, seq: u32, key: &[u8]) -> anyhow::Result<PathLookup> {
        self.root_at(seq).await?;
        self.check_published_root(seq)?;
        let index = key_index(key);
        match self.smt.generate_membership_proof(key) {
            Some(proof) => {
                let value_hash = proof.value_hash;
                let bytes = serialize_membership_proof_with_index(
                    &proof,
                    key,
                    value_hash.as_slice(),
                    index,
                );
                Ok(PathLookup::Found {
                    value_hash,
                    proof_bytes: bytes,
                })
            }
            _ => {
                let proof = self
                    .smt
                    .generate_non_membership_proof(key)
                    .ok_or_else(|| anyhow::anyhow!("non-membership proof unavailable for key"))?;
                let bytes = serialize_non_membership_proof_with_index(&proof, key, index);
                Ok(PathLookup::Absent { proof_bytes: bytes })
            }
        }
    }

    async fn process_through(&mut self, seq: u32) -> anyhow::Result<[u8; 32]> {
        let start = match self.last_processed {
            Some(last) if last >= seq => {
                let root = self.smt.root();
                self.roots.insert(seq, root);
                return Ok(root);
            }
            Some(last) => last + 1,
            None => self.cold_start(seq)?,
        };

        if start < seq {
            tracing::info!(
                from = start,
                to = seq,
                "replaying ledger range into smt (cumulative)"
            );
        }

        if start == seq {
            self.apply_ledger(seq).await?;
            self.last_processed = Some(seq);
            let root = self.smt.root();
            self.roots.insert(seq, root);
            return Ok(root);
        }

        match self.ledgers_with_router_activity(start, seq).await {
            Some(ledgers) => {
                tracing::info!(
                    from = start,
                    to = seq,
                    scanned = ledgers.len(),
                    skipped = (seq - start + 1) as usize - ledgers.len(),
                    "replaying only ledgers with router activity"
                );
                for ledger_seq in ledgers {
                    self.apply_ledger(ledger_seq).await?;
                }
            }
            None => {
                for ledger_seq in start..=seq {
                    self.apply_ledger(ledger_seq).await?;
                }
            }
        }

        self.last_processed = Some(seq);
        let root = self.smt.root();
        self.roots.insert(seq, root);
        Ok(root)
    }

    fn cold_start(&self, seq: u32) -> anyhow::Result<u32> {
        match self.genesis_ledger {
            Some(genesis) if genesis <= seq => Ok(genesis),
            Some(genesis) => anyhow::bail!(
                "the router genesis ledger {genesis} is after the requested ledger {seq}; \
                 ROUTER_GENESIS_LEDGER does not belong to this router"
            ),
            None => {
                tracing::warn!(
                    ledger = seq,
                    "no ROUTER_GENESIS_LEDGER — replaying this ledger alone, which only matches \
                     the chain if the router first wrote here; the published-root check decides"
                );

                Ok(seq)
            }
        }
    }

    async fn ledgers_with_router_activity(&self, start: u32, end: u32) -> Option<Vec<u32>> {
        const PAGE_LIMIT: u32 = 200;
        const MAX_PAGES: usize = 512;

        let address = self.router_address.as_deref()?;
        if start > end {
            return Some(Vec::new());
        }

        let mut cursor = EventCursor::StartLedger(start);
        let mut ledgers = Vec::new();

        for _ in 0..MAX_PAGES {
            let page = match self.api.get_events(address, cursor, Some(PAGE_LIMIT)).await {
                Ok(page) => page,
                Err(error) => {
                    tracing::warn!(
                        %error,
                        start,
                        end,
                        "router event index unavailable — replaying every ledger"
                    );
                    return None;
                }
            };

            let mut past_end = false;
            for event in &page.events {
                if event.ledger > end {
                    past_end = true;
                } else if event.ledger >= start {
                    ledgers.push(event.ledger);
                }
            }

            let scanned_through = cursor_ledger(&page.cursor);
            let exhausted = page.cursor.is_empty();
            let swept_past_end = scanned_through.is_some_and(|l| l >= end);

            if past_end || exhausted || swept_past_end {
                ledgers.sort_unstable();
                ledgers.dedup();
                return Some(ledgers);
            }

            cursor = EventCursor::Cursor(page.cursor);
        }

        tracing::warn!(
            start,
            end,
            "router event index did not terminate — replaying every ledger"
        );
        None
    }

    async fn apply_ledger(&mut self, seq: u32) -> anyhow::Result<()> {
        let ledger = self.api.get_ledger(seq).await?;

        let meta = match ledger.metadata_xdr {
            Some(meta_xdr) => Some(
                LedgerCloseMeta::from_xdr(&meta_xdr, Limits::none())
                    .map_err(|e| anyhow::anyhow!("LedgerCloseMeta XDR decode: {e}"))?,
            ),
            None => None,
        };

        let mut changes_applied = 0usize;
        if let Some(meta) = &meta {
            for change in ledger_changes(meta) {
                if self.apply(change) {
                    changes_applied += 1;
                }
            }
        }

        if changes_applied > 0 {
            tracing::info!(
                ledger = seq,
                ibc_writes = changes_applied,
                root = %hex::encode(self.smt.root()),
                "[gateway] SMT updated — committed IBC state change(s)"
            );
        } else {
            tracing::debug!(sequence = seq, "ledger processed into smt (no ibc changes)");
        }

        if let Some(root) = meta.as_ref().and_then(published_root) {
            self.published.insert(seq, root);
        }

        Ok(())
    }

    fn check_published_root(&self, seq: u32) -> anyhow::Result<()> {
        let Some(published) = self.published.get(&seq).copied() else {
            return Ok(());
        };

        let computed = self.smt.root();

        if computed == published {
            tracing::debug!(ledger = seq, "replayed root matches the published one");

            return Ok(());
        }

        anyhow::bail!(
            "the replayed state root at ledger {seq} is {} but the router published {}; the \
             replay is missing writes, so this proof would carry a root the chain never had. \
             Check ROUTER_GENESIS_LEDGER covers the router's first write",
            hex::encode(computed),
            hex::encode(published)
        )
    }

    fn apply(&mut self, change: LedgerEntryChange) -> bool {
        match change {
            LedgerEntryChange::Created(e) => self.apply_contract_data_write(e.data, false),
            LedgerEntryChange::Updated(e) => self.apply_contract_data_write(e.data, true),
            LedgerEntryChange::Removed(LedgerKey::ContractData(key)) => {
                if !self.matches(&key.contract) {
                    return false;
                }
                let Some(path) = scval_to_v2_path(&key.key) else {
                    return false;
                };
                self.smt.remove(&path);
                true
            }
            _ => false,
        }
    }

    fn apply_contract_data_write(&mut self, data: LedgerEntryData, is_update: bool) -> bool {
        let LedgerEntryData::ContractData(d) = data else {
            return false;
        };
        if !self.matches(&d.contract) {
            return false;
        }
        let Some(path) = scval_to_v2_path(&d.key) else {
            return false;
        };
        let Some(value) = scval_as_bytes(&d.val) else {
            return false;
        };
        if is_update {
            self.smt.update(&path, &value);
        } else {
            self.smt.insert(&path, &value);
        }
        true
    }

    fn matches(&self, addr: &ScAddress) -> bool {
        let ScAddress::Contract(hash) = addr else {
            return false;
        };
        match &self.ibc_contract_id {
            None => true,
            Some(id) => hash.0 == soroban_client::xdr::Hash(*id),
        }
    }
}

pub const ROOT_EVENT_TOPIC: &[u8] = b"ibc_root";

fn published_root(meta: &LedgerCloseMeta) -> Option<[u8; 32]> {
    let mut latest = None;

    for event in ledger_events(meta) {
        let ContractEventBody::V0(body) = &event.body;

        let is_root = body.topics.first().is_some_and(
            |topic| matches!(topic, ScVal::Symbol(s) if s.0.as_slice() == ROOT_EVENT_TOPIC),
        );

        if !is_root {
            continue;
        }

        if let Some(bytes) = scval_as_bytes(&body.data) {
            if let Ok(root) = <[u8; 32]>::try_from(bytes.as_slice()) {
                latest = Some(root);
            }
        }
    }

    latest
}

fn ledger_events(meta: &LedgerCloseMeta) -> Vec<ContractEvent> {
    let mut out = vec![];

    match meta {
        LedgerCloseMeta::V0(v) => {
            for tx in v.tx_processing.iter() {
                collect_tx_events(&tx.tx_apply_processing, &mut out);
            }
        }
        LedgerCloseMeta::V1(v) => {
            for tx in v.tx_processing.iter() {
                collect_tx_events(&tx.tx_apply_processing, &mut out);
            }
        }
        LedgerCloseMeta::V2(v) => {
            for tx in v.tx_processing.iter() {
                collect_tx_events(&tx.tx_apply_processing, &mut out);
            }
        }
    }

    out
}

fn collect_tx_events(meta: &TransactionMeta, out: &mut Vec<ContractEvent>) {
    match meta {
        TransactionMeta::V3(v) => {
            if let Some(soroban) = &v.soroban_meta {
                out.extend(soroban.events.iter().cloned());
            }
        }
        TransactionMeta::V4(v) => {
            for op in v.operations.iter() {
                out.extend(op.events.iter().cloned());
            }
        }
        _ => {}
    }
}

fn ledger_changes(meta: &LedgerCloseMeta) -> Vec<LedgerEntryChange> {
    let mut out = vec![];
    match meta {
        LedgerCloseMeta::V0(v) => {
            for tx in v.tx_processing.iter() {
                collect_tx_changes(&tx.tx_apply_processing, &mut out);
            }
        }
        LedgerCloseMeta::V1(v) => {
            for tx in v.tx_processing.iter() {
                collect_tx_changes(&tx.tx_apply_processing, &mut out);
            }
        }
        LedgerCloseMeta::V2(v) => {
            for tx in v.tx_processing.iter() {
                collect_tx_changes(&tx.tx_apply_processing, &mut out);
            }
        }
    }
    out
}

fn collect_tx_changes(meta: &TransactionMeta, out: &mut Vec<LedgerEntryChange>) {
    match meta {
        TransactionMeta::V0(operations) => {
            for op in operations.iter() {
                out.extend(op.changes.iter().cloned());
            }
        }
        TransactionMeta::V1(v) => {
            out.extend(v.tx_changes.iter().cloned());
            for op in v.operations.iter() {
                out.extend(op.changes.iter().cloned());
            }
        }
        TransactionMeta::V2(v) => {
            out.extend(v.tx_changes_before.iter().cloned());
            for op in v.operations.iter() {
                out.extend(op.changes.iter().cloned());
            }
            out.extend(v.tx_changes_after.iter().cloned());
        }
        TransactionMeta::V3(v) => {
            out.extend(v.tx_changes_before.iter().cloned());
            for op in v.operations.iter() {
                out.extend(op.changes.iter().cloned());
            }
            out.extend(v.tx_changes_after.iter().cloned());
        }
        TransactionMeta::V4(v) => {
            out.extend(v.tx_changes_before.iter().cloned());
            for op in v.operations.iter() {
                out.extend(op.changes.iter().cloned());
            }
            out.extend(v.tx_changes_after.iter().cloned());
        }
        #[allow(unreachable_patterns)]
        _ => {}
    }
}
