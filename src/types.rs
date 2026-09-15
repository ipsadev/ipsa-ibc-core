use soroban_client::xdr::ScVal;

#[derive(Debug, Clone)]
pub struct LedgerData {
    pub sequence: u32,
    pub header_xdr: Vec<u8>,
    pub metadata_xdr: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct SubmittedTx {
    pub hash: String,
    pub return_value: Option<ScVal>,
}

pub struct EventRecord {
    pub id: String,
    pub ledger: u32,
    pub ledger_closed_at: String,
    pub contract_id: String,
    pub tx_hash: String,
    pub topics_xdr: Vec<Vec<u8>>,
    pub value_xdr: Vec<u8>,
}

pub struct EventsPage {
    pub latest_ledger: u32,
    pub cursor: String,
    pub events: Vec<EventRecord>,
}

pub enum EventCursor {
    Cursor(String),
    StartLedger(u32),
}
