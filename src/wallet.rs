use std::{str::FromStr, ops::Deref, collections::BTreeMap, borrow::BorrowMut};

use anyhow::{Error, Result};
use bip39::Mnemonic;
use bitcoin::{secp256k1::{Secp256k1, Message, SecretKey, SignOnly, Scalar, constants::SCHNORRSIG_SIGNATURE_SIZE}, OutPoint, Txid, util::{bip32::{ExtendedPrivKey, DerivationPath}, sighash::SighashCache, taproot::TapLeafHash}, Network, psbt::{Psbt, Input, PsbtSighashType, Prevouts, raw::ProprietaryKey}, Transaction, TxOut, SchnorrSighashType, KeyPair, SchnorrSig, Witness, blockdata::script};
use serde::{Serialize, Deserialize};
use silentpayments::receiving::Receiver;
use chrono::{DateTime, Utc};

use crate::constants::{OwnedOutput, ScanStatus, Status};

#[derive(Serialize, Deserialize)]
pub(crate) struct WalletMessage {
    pub label: String,
    pub timestamp: String, // when this state of the wallet was returned
    pub scan_status: ScanStatus,
    // below this is encrypted stuff
    pub mnemonic: String,
    pub wallet: Wallet,
}

impl WalletMessage {
    pub(crate) fn new(label: String, mnemonic: String, wallet: Wallet) -> Self {
        let current_time: DateTime<Utc> = Utc::now();
        
        WalletMessage { 
            label, 
            timestamp: format!("{}", current_time.format("%Y/%m/%d %H:%M")),
            scan_status: ScanStatus::default(),
            mnemonic,
            wallet
        }
    }

    pub(crate) fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    pub(crate) fn from_json(blob: String) -> Result<WalletMessage> {
        Ok(serde_json::from_str(&blob)?)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Wallet {
    pub sp_wallet: Receiver,
    pub total_amt: u64,
    pub outputs: Vec<OwnedOutput>
}

impl Wallet {
    pub fn reset_scan(&mut self) {
        // drop all outpoints
        self.outputs = vec![];
        // reset amount to 0
        self.total_amt = 0;
    }

    pub fn update_amt_owned(&mut self) {
        self.total_amt = self.outputs.iter()
            .fold(0, |acc, x| acc + x.amount);
    }

    pub fn insert_outpoint(&mut self, owned: OwnedOutput) {
        self.outputs.push(owned);
    }

    pub fn list_outpoints(&self) -> Vec<OwnedOutput> {
        self.outputs.clone()
    }

    pub fn mark_outpoint_spent(&mut self, txoutpoint: OutPoint, txid: Txid) -> Result<()> {
        let output = self.outputs.iter_mut()
            .find(|o| o.txoutpoint == txoutpoint);

        if let Some(to_spend) = output {
            if to_spend.status != Status::Unspent {
                return Err(Error::msg(format!("outpoint {} is already spent", txoutpoint)));
            } else {
                to_spend.status = Status::Spent(txid);
            }
        } else {
            return Err(Error::msg("Unknown outpoint"));
        }

        Ok(())
    }
}

pub fn derive_sp_keys(seed: &[u8;64], network: Network, secp: &Secp256k1<SignOnly>) -> Result<(SecretKey, SecretKey)> {
    let master_key = ExtendedPrivKey::new_master(network, seed).unwrap();
    let coin_type_derivation = if network == Network::Bitcoin { "0'" } else { "1'" };

    let scan_key_path = DerivationPath::from_str(&format!("m/352'/{}/0'/1'/0", coin_type_derivation))?;
    let spend_key_path = DerivationPath::from_str(&format!("m/352'/{}/0'/0'/0", coin_type_derivation))?;

    let scan_privkey = master_key.derive_priv(&secp, &scan_key_path)?.private_key;
    let spend_privkey = master_key.derive_priv(&secp, &spend_key_path)?.private_key;

    Ok((scan_privkey, spend_privkey))
}

pub fn setup(label: String, network: String, seed_words: Option<String>) -> Result<String> {
    let network = Network::from_str(&network)?;

    let mnemonic = if let Some(words) = seed_words { Mnemonic::from_str(&words).unwrap() }
    else { Mnemonic::generate(12).unwrap() }; 
    let seed = &mnemonic.to_seed("");

    let secp = Secp256k1::signing_only();
    let (scan_privkey, spend_privkey) = derive_sp_keys(seed, network, &secp)?;

    let receiver = Receiver::new(0, scan_privkey.public_key(&secp), spend_privkey.public_key(&secp), network != Network::Bitcoin)?;

    let wallet = Wallet {
        sp_wallet: receiver,
        total_amt: u64::default(),
        outputs: vec![]
    };

    Ok(WalletMessage::new(label, mnemonic.to_string(), wallet).to_json()?)
}

fn taproot_sighash<T: Deref<Target = Transaction>>(
        input: &Input,
        prevouts: Vec<&TxOut>,
        input_index: usize,
        cache: &mut SighashCache<T>,
        tapleaf_hash: Option<TapLeafHash>
    ) -> Result<(Message, PsbtSighashType), bitcoin::util::sighash::Error> {
        let prevouts = Prevouts::All(&prevouts);

        let hash_ty = input
            .sighash_type
            .map(|ty| ty.schnorr_hash_ty())
            .unwrap_or(Ok(SchnorrSighashType::Default))?;

        let sighash = match tapleaf_hash {
            Some(leaf_hash) => cache.taproot_script_spend_signature_hash(
                input_index,
                &prevouts,
                leaf_hash,
                hash_ty,
            )?,
            None => cache.taproot_key_spend_signature_hash(input_index, &prevouts, hash_ty)?,
        };
        let msg = Message::from_slice(&sighash).expect("sighashes are 32 bytes");
        Ok((msg, hash_ty.into()))
    }

pub fn sign_psbt(
        psbt: &mut Psbt,
        input_index: usize,
        mnemonic: String,
        is_testnet: bool
    ) -> Result<()> {
        let mut cache = SighashCache::new(&psbt.unsigned_tx);

        let input: &Input = &psbt.inputs[input_index];

        let mut prevouts: Vec<&TxOut> = vec![];

        for input in &psbt.inputs {
            if let Some(witness_utxo) = &input.witness_utxo {
                prevouts.push(witness_utxo);
            }
        }
        
        let tap_leaf_hash: Option<TapLeafHash> = None;

        let (msg, sighash_ty) = taproot_sighash(&input, prevouts, input_index, &mut cache, tap_leaf_hash)?;

        // Construct the signing key
        let secp = Secp256k1::signing_only();
        let seed = match Mnemonic::from_str(&mnemonic) {
            Ok(m) => m.to_seed(""),
            Err(_) => [0u8;64], // spoof signature for fee estimation
        };
        let network = if is_testnet { Network::Testnet } else { Network::Bitcoin };
        let (_, spend_privkey) = derive_sp_keys(&seed, network, &secp)?;

        let tweak = input.proprietary.get(&ProprietaryKey {
            prefix: b"sp".to_vec(),
            subtype: 0u8,
            key: b"tweak".to_vec()
        });

        if tweak.is_none() { panic!("Missing tweak") };

        let tweak = SecretKey::from_slice(tweak.unwrap().as_slice()).unwrap();

        let sk = spend_privkey.add_tweak(&tweak.into()).unwrap();

        let sig = secp.sign_schnorr(&msg, &KeyPair::from_secret_key(&secp, &sk));

        psbt.inputs[input_index].tap_key_sig = Some(SchnorrSig { sig, hash_ty: sighash_ty.schnorr_hash_ty().unwrap() });

        Ok(())
    }

pub(crate) fn finalize_psbt(psbt: &mut Psbt) -> Result<()> {
        psbt.inputs.iter_mut()
            .for_each(|i| {
                if let Some(sig) = i.tap_key_sig {
                    let mut script_witness = Witness::new();
                    script_witness.push(sig.to_vec());
                    i.final_script_witness = Some(script_witness);
                    i.tap_key_sig = None;
                } else {
                    panic!("Missing signature");
                }
            });

        // Clear all the data fields as per the spec.
        psbt.inputs[0].partial_sigs = BTreeMap::new();
        psbt.inputs[0].sighash_type = None;
        psbt.inputs[0].redeem_script = None;
        psbt.inputs[0].witness_script = None;
        psbt.inputs[0].bip32_derivation = BTreeMap::new();

        Ok(())
    }
