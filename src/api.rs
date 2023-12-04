use std::str::FromStr;

use bip39::Mnemonic;
use bitcoin::{secp256k1::{Scalar, Secp256k1}, util::bip32::{DerivationPath, ExtendedPrivKey}, Network};
use flutter_rust_bridge::StreamSink;

use crate::{
    constants::{LogEntry, ScanProgress, ScanStatus, Status},
    wallet::{self, WalletMessage},
    electrumclient::create_electrum_client,
    nakamotoclient,
    stream::{self, loginfo},
};

pub fn create_log_stream(s: StreamSink<LogEntry>) {
    stream::create_log_stream(s);
}
pub fn create_amount_stream(s: StreamSink<u64>) {
    stream::create_amount_stream(s);
}
pub fn create_scan_progress_stream(s: StreamSink<ScanProgress>) {
    stream::create_scan_progress_stream(s);
}

pub fn setup(label: String, network: String, seed_words: Option<String>) -> String {
    let wallet_data = wallet::setup(label.clone(), network, seed_words).unwrap();
    loginfo("wallet has been setup");

    nakamotoclient::setup(label).unwrap();
    loginfo("nakamoto config has been setup");

    wallet_data
}

pub fn start_nakamoto() -> Result<(), String> {
    nakamotoclient::start_nakamoto_client()
        .map_err(|e| e.to_string())
}

pub fn stop_nakamoto() -> Result<(), String> {
    nakamotoclient::stop_nakamoto_client()
        .map_err(|e| e.to_string())
}

pub fn restart_nakamoto() -> Result<(), String> {
    nakamotoclient::restart_nakamoto_client()
        .map_err(|e| e.to_string())
}

pub fn get_peer_count() -> Result<u32, String> {
    nakamotoclient::get_peer_count()
        .map_err(|e| e.to_string())
}

pub fn get_tip() -> Result<u32, String> {
    nakamotoclient::get_tip()
        .map_err(|e| e.to_string())
}

pub fn scan_next_n_blocks(blob: String, n: u32) -> Result<String, String> {
    let mut wallet_msg = WalletMessage::from_json(blob)
        .map_err(|e| e.to_string())?; 
    let sp_receiver = &wallet_msg.wallet.sp_wallet;

    let scan_key_path = DerivationPath::from_str(
        &format!("m/352'/{}/0'/1'/0", 
        if sp_receiver.is_testnet { 
            "1'" 
        } else { 
            "0'" 
        }))
        .map_err(|e| e.to_string())?;

    let secp = Secp256k1::new();
    let network = if sp_receiver.is_testnet { Network::Signet } else { Network::Bitcoin };
    let seed = Mnemonic::from_str(&wallet_msg.mnemonic)
        .map_err(|e| e.to_string())?
        .to_seed("");
    let scan_sk = ExtendedPrivKey::new_master(network, &seed)
        .map_err(|e| e.to_string())?
        .derive_priv(&secp, &scan_key_path)
        .map_err(|e| e.to_string())?
        .private_key;

    let electrum_client = create_electrum_client()
        .map_err(|e| e.to_string())?;

    let scan_key_scalar: Scalar = scan_sk.into();

    nakamotoclient::scan_blocks(n, &mut wallet_msg.wallet, electrum_client, scan_key_scalar)
        .map_err(|e| e.to_string())?;

    Ok(wallet_msg.to_json().map_err(|e| e.to_string())?)
}

pub fn scan_to_tip(blob: String) -> Result<String, String> {
    // 0 means scan to tip
    scan_next_n_blocks(blob, 170000)
}

pub fn get_wallet_info(blob: String) -> Result<ScanStatus, String> {
    let wallet_msg = WalletMessage::from_json(blob)
        .map_err(|e| e.to_string())?; 

    let scan_status = wallet_msg.wallet.scan_status;

    let scan_height = scan_status.scan_height;
    let tip_height = nakamotoclient::get_tip()
        .map_err(|e| e.to_string())?;

    Ok(ScanStatus {
        scan_height,
        block_tip: tip_height,
    })
}

pub fn get_wallet_balance(blob: String) -> u64 {
    let wallet_msg = WalletMessage::from_json(blob).unwrap(); 

    let wallet = wallet_msg.wallet;
    wallet.total_amt
}

pub fn get_receiving_address(blob: String) -> String {
    let wallet_msg = WalletMessage::from_json(blob).unwrap(); 

    let sp_receiver = &wallet_msg.wallet.sp_wallet;

    sp_receiver.get_receiving_address()
}
