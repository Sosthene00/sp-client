use serde::{Serialize, Deserialize};
use bitcoin::{secp256k1::PublicKey, OutPoint, Script, Txid};

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
