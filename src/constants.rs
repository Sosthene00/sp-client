use serde::{Serialize, Deserialize};
use bitcoin::{secp256k1::PublicKey, OutPoint, Script, Txid};

pub const PSBT_SP_PREFIX: &str = "sp";
pub const PSBT_SP_SUBTYPE: u8 = 0;
pub const PSBT_SP_TWEAK_KEY: &str = "tweak";
pub const PSBT_SP_ADDRESS_KEY: &str = "address";

pub const NUMS_KEY: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

pub struct LogEntry {
    // pub time_millis: i64,
    // pub level: i32,
    // pub tag: String,
    pub msg: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ScanStatus {
    pub birthday: u32,
    pub scan_height: u32,
    pub block_tip: u32,
}

pub struct ScanProgress {
    pub start: u32,
    pub current: u32,
    pub end: u32,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub(crate) enum Status {
    Unspent,
    Spent(Txid)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OwnedOutput {
    pub txoutpoint: OutPoint, 
    pub tweak_data: PublicKey,
    pub index: u32,
    pub tweak: String,
    pub blockheight: u64,
    pub amount: u64,
    pub script: Script,
    pub status: Status,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct SpendDestination {
    pub address: String, // Can be either sp or regular address
    pub value: u64
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SpendMessage {
    pub inputs: Vec<OwnedOutput>,
    pub outputs: Vec<SpendDestination>,
}
