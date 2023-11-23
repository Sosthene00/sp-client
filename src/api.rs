use std::str::FromStr;

use bip39::Mnemonic;
use bitcoin::{secp256k1::{Scalar, Secp256k1}, util::bip32::{DerivationPath, ExtendedPrivKey}, Network};
use flutter_rust_bridge::StreamSink;

use crate::{
    constants::{LogEntry, ScanProgress, ScanStatus},
    wallet::{self, WalletMessage},
    electrumclient::create_electrum_client,
    nakamotoclient,
    // spclient::{self, get_sp_client},
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

pub fn setup(label: String, mnemonic: Option<String>, birthday: u32, network: String) -> String {
    let wallet_data = wallet::setup(label.clone(), mnemonic, birthday, network).unwrap();
    loginfo("wallet has been setup");

    nakamotoclient::setup(label).unwrap();
    loginfo("nakamoto config has been setup");

    wallet_data
}


// pub fn reset_wallet() {
//     let birthday = spclient::get_birthday().unwrap();
//     wallet::reset_scan_height(birthday).unwrap();
//     wallet::drop_owned_outpoints().unwrap();
// }

pub fn start_nakamoto() {
    nakamotoclient::start_nakamoto_client().unwrap();
}

pub fn restart_nakamoto() {
    nakamotoclient::restart_nakamoto_client().unwrap();
}

pub fn get_peer_count() -> u32 {
    nakamotoclient::get_peer_count().unwrap()
}

pub fn scan_next_n_blocks(blob: String, n: u32) {
    let mut wallet_msg: WalletMessage = serde_json::from_str(&blob).unwrap();
    let sp_receiver = &wallet_msg.wallet.sp_wallet;

    let scan_key_path = DerivationPath::from_str(&format!("m/352'/{}/0'/1'/0", if sp_receiver.is_testnet { "1'" } else { "0'" })).unwrap();

    let secp = Secp256k1::new();
    let network = if sp_receiver.is_testnet { Network::Signet } else { Network::Bitcoin };
    let seed = Mnemonic::from_str(&wallet_msg.mnemonic).unwrap().to_seed("");
    let scan_sk = ExtendedPrivKey::new_master(network, &seed).unwrap().derive_priv(&secp, &scan_key_path).unwrap().private_key;

    let electrum_client = create_electrum_client().unwrap();

    let scan_key_scalar: Scalar = scan_sk.into();

    nakamotoclient::scan_blocks(n, &mut wallet_msg.wallet, electrum_client, scan_key_scalar).unwrap();
}

pub fn scan_to_tip(blob: String) {
    // 0 means scan to tip
    scan_next_n_blocks(blob, 0);
}

pub fn get_wallet_info(blob: String) -> ScanStatus {
    let wallet_msg: WalletMessage = serde_json::from_str(&blob).unwrap();

    let scan_status = wallet_msg.wallet.scan_status;

    let scan_height = scan_status.scan_height;
    let tip_height = nakamotoclient::get_tip().unwrap();

    ScanStatus {
        scan_height,
        block_tip: tip_height,
    }
}

pub fn get_birthday(blob: String) -> u32 {
    let wallet_msg: WalletMessage = serde_json::from_str(&blob).unwrap();

    let wallet = wallet_msg.wallet;
    wallet.birthday
}

pub fn get_wallet_balance(blob: String) -> u64 {
    let wallet_msg: WalletMessage = serde_json::from_str(&blob).unwrap();

    let wallet = wallet_msg.wallet;
    wallet.total_amt
}

pub fn get_receiving_address(blob: String) -> String {
    let wallet_msg: WalletMessage = serde_json::from_str(&blob).unwrap();

    let sp_receiver = &wallet_msg.wallet.sp_wallet;

    sp_receiver.get_receiving_address()
}
