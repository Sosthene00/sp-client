use std::str::FromStr;

use bip39::Mnemonic;
use bitcoin::{secp256k1::{Scalar, Secp256k1}, util::bip32::{DerivationPath, ExtendedPrivKey}, Network, TxOut, Address, Script, psbt::{Psbt, Input, raw}, Transaction, PackedLockTime, TxIn, Witness, Sequence, consensus::encode};
use bitcoin::hashes::hex::FromHex;
use flutter_rust_bridge::StreamSink;

use crate::{
    constants::{LogEntry, ScanProgress, Status, SpendMessage},
    wallet::{self, WalletMessage, sign_psbt},
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

pub fn setup(label: String, network: String, seed_words: Option<String>) -> Result<String, String> {
    let wallet_data = wallet::setup(label.clone(), network, seed_words)
        .map_err(|e| e.to_string())?;
    loginfo("wallet has been setup");

    nakamotoclient::setup(label)
        .map_err(|e| e.to_string())?;
    loginfo("nakamoto config has been setup");

    Ok(wallet_data)
}

pub fn start_nakamoto() -> Result<(), String> {
    nakamotoclient::start_nakamoto_client()
}

pub fn stop_nakamoto() -> Result<(), String> {
    nakamotoclient::stop_nakamoto_client()
}

pub fn restart_nakamoto() -> Result<(), String> {
    nakamotoclient::restart_nakamoto_client()
}

pub fn get_peer_count() -> Result<u32, String> {
    nakamotoclient::get_peer_count()
}

pub fn get_tip() -> Result<u32, String> {
    nakamotoclient::get_tip()
        .map_err(|e| e.to_string())
}

pub fn scan_from(blob: String, height: u32) -> Result<String, String> {
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

    let tip = get_tip()?;

    // for now we just scan to the tip
    let to_scan = tip - height;

    let new_scan_height = nakamotoclient::scan_blocks(height, to_scan, &mut wallet_msg.wallet, electrum_client, scan_key_scalar)?;

    wallet_msg.scan_status.scan_height = new_scan_height;

    loginfo(&format!("{:?}", wallet_msg.wallet.list_outpoints()));

    Ok(wallet_msg.to_json().map_err(|e| e.to_string())?)
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

pub fn set_wallet_birthday(blob: String, new_birthday: u32) -> Result<String, String> {
    let mut wallet_msg = WalletMessage::from_json(blob)
        .map_err(|e| e.to_string())?;

    // Update block tip
    let current_tip = nakamotoclient::get_tip()?;
    if wallet_msg.scan_status.block_tip < current_tip {
        wallet_msg.scan_status.block_tip = current_tip;
    }

    // Update birthday in wallet
    wallet_msg.scan_status.birthday = new_birthday;

    // We also drop all the outpoints and reset scan_height to birthday
    wallet_msg.wallet.reset_scan();

    Ok(wallet_msg.to_json().map_err(|e| e.to_string())?)
}

pub fn get_spendable_outputs(blob: String) -> Result<Vec<String>, String> {
    let wallet_msg = WalletMessage::from_json(blob)
        .map_err(|e| e.to_string())?;

    Ok(wallet_msg.wallet.list_outpoints().iter()
        .filter(|o| {
            o.status == Status::Unspent
        })
        .map(|o| {
            let str = serde_json::to_string(o).unwrap();
            loginfo(&format!("{}", str));
            str
        })
        .collect()
    )
}

pub fn sign_psbt_at(blob: String, psbt: String, input_index: u32) -> Result<String, String> {
    let wallet_msg = WalletMessage::from_json(blob)
        .map_err(|e| e.to_string())?;

    let mut psbt: Psbt = serde_json::from_str(&psbt)
        .map_err(|e| e.to_string())?;

    let is_testnet = wallet_msg.wallet.sp_wallet.is_testnet;

    sign_psbt(&mut psbt, input_index as usize, wallet_msg.mnemonic, is_testnet)
        .map_err(|e| e.to_string())?;

    serde_json::to_string(&psbt).map_err(|e| e.to_string())
}

pub fn finalize_psbt(psbt: String) -> Result<String, String> {
    let mut psbt: Psbt = serde_json::from_str(&psbt)
        .map_err(|e| e.to_string())?;

    wallet::finalize_psbt(&mut psbt).map_err(|e| e.to_string())?;

    let final_tx = psbt.extract_tx();

    let hex = encode::serialize_hex(&final_tx);

    Ok(hex)
}

pub fn mark_spent_from_transaction(blob: String, tx_hex: String) -> Result<String, String> {
    let mut wallet_msg = WalletMessage::from_json(blob)
        .map_err(|e| e.to_string())?;

    let tx: Transaction = deserialize(&Vec::from_hex(&tx_hex)
        .map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string()
    )?;

    let txid = tx.txid();

    for input in tx.input {
        let res = wallet_msg.wallet.mark_outpoint_spent(input.previous_output, txid);
        if res.is_err() {
            loginfo(res.unwrap_err().to_string().as_str());
        }
    }

    wallet_msg.to_json().map_err(|e| e.to_string())
}

pub fn broadcast_raw_transaction(tx_hex: String) -> Result<String, String> {
    let tx: Transaction = deserialize(&Vec::from_hex(&tx_hex)
        .map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string()
    )?;

    let txid = tx.txid().to_string();

    nakamotoclient::broadcast_raw_transaction(tx)?;

    Ok(txid)
}

pub fn spend_to(spending_request: String) -> Result<String, String> {
    loginfo(&format!("{:?}", &spending_request));
    let spend_info: SpendMessage = serde_json::from_str(&spending_request)
        .map_err(|e| e.to_string())?;

    loginfo(&format!("Received SpendMessage: {:?}", spend_info));

    let mut inputs: Vec<TxIn> = vec![];
    let mut inputs_data: Vec<(Script, u64, Scalar)> = vec![];

    for input in spend_info.inputs {
        inputs.push(TxIn { 
            previous_output: input.txoutpoint,
            script_sig: Script::new(), 
            sequence: Sequence::MAX, 
            witness: Witness::new()
        });

        let scalar = Scalar::from_be_bytes(FromHex::from_hex(&input.tweak).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;

        inputs_data.push((input.script, input.amount, scalar));
    }

    // Since we don't have access to private materials for now we use a NUMS key as a placeholder 
    let placeholder_key = XOnlyPublicKey::from_str(NUMS_KEY)
        .map_err(|e| format!("Error for key {:?}: {}", NUMS_KEY, e.to_string()))?.dangerous_assume_tweaked();

    let _outputs: Result<Vec<TxOut>, String> = spend_info.outputs.iter()
        .map(|o| {
            let address: Address;

            match SilentPaymentAddress::try_from(o.address.as_str()) {
                Ok(sp_address) => {
                    let network = if sp_address.is_testnet() { Network::Testnet } else { Network::Bitcoin };

                    address = Address::from_script(&Script::new_v1_p2tr_tweaked(placeholder_key), network).unwrap();
                },
                Err(_) => {
                    address = Address::from_str(&o.address).map_err(|e| e.to_string())?;
                },
            }

            Ok(TxOut {
                value: o.value,
                script_pubkey: address.script_pubkey()
            })
        })
        .collect();

    let outputs = _outputs?;

    let tx = Transaction {
        version: 2,
        lock_time: PackedLockTime::ZERO,
        input: inputs,
        output: outputs
    };

    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

    // Add the witness utxo to the input in psbt
    for (i, input_data) in inputs_data.iter().enumerate() {
        let (script_pubkey, value, tweak) = input_data;
        let witness_txout = TxOut {
            value: *value,
            script_pubkey: script_pubkey.clone()
        };
        let mut psbt_input = Input { witness_utxo: Some(witness_txout), ..Default::default() };
        psbt_input.proprietary.insert(raw::ProprietaryKey {
            prefix: PSBT_SP_PREFIX.as_bytes().to_vec(),
            subtype: PSBT_SP_SUBTYPE,
            key: PSBT_SP_TWEAK_KEY.as_bytes().to_vec()
        }, tweak.to_be_bytes().to_vec());
        psbt.inputs[i] = psbt_input;
    }
    
    for (i, output) in spend_info.outputs.iter().enumerate() {
        if let Ok(sp_address) = SilentPaymentAddress::try_from(output.address.as_str()) {
            // Add silentpayment address to the output
            let mut psbt_output = Output { ..Default::default() };
            psbt_output.proprietary.insert(raw::ProprietaryKey {
                prefix: PSBT_SP_PREFIX.as_bytes().to_vec(),
                subtype: PSBT_SP_SUBTYPE,
                key: PSBT_SP_ADDRESS_KEY.as_bytes().to_vec()
            }, serialize(&sp_address.to_string()));
            psbt.outputs[i] = psbt_output;
        } else {
            // Regular address, we don't need to add more data
            continue;
        }
    }

    serde_json::to_string(&psbt).map_err(|e| e.to_string())
}
