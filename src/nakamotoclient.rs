use std::{collections::HashMap, net, path::PathBuf, str::FromStr, sync::{Mutex, Arc}, thread};

use anyhow::{Error, Result};
use bitcoin::{
    secp256k1::{PublicKey, Scalar, Secp256k1},
    util::bip158::BlockFilter,
    Block, BlockHash, Script, Transaction, TxOut, XOnlyPublicKey, OutPoint,
};
use electrum_client::ElectrumApi;
use lazy_static::lazy_static;
use nakamoto::{
    client::{self, traits::Handle, Client, Config},
    common::network::Services,
    net::poll::Waker,
};
use once_cell::sync::OnceCell;
use silentpayments::receiving::Receiver;

use crate::{
    constants::{ScanProgress, OwnedOutput},
    wallet::Wallet,
    stream::{loginfo, send_amount_update, send_scan_progress},
};

lazy_static! {
    static ref JOIN_HANDLE: Arc<Mutex<Option<thread::JoinHandle<()>>>> = Arc::new(Mutex::new(None));
    static ref HANDLE: Arc<Mutex<Option<nakamoto::client::Handle<nakamoto::net::poll::Waker>>>> =
        Arc::new(Mutex::new(None));
    static ref NAKAMOTO_CONFIG: OnceCell<Config> = OnceCell::new();
}

pub fn setup(path: String) -> anyhow::Result<()> {
    let mut cfg = Config::new(client::Network::Signet);

    cfg.root = PathBuf::from(format!("{}/db", path));
    loginfo(format!("cfg.root = {:?}", cfg.root).as_str());

    let _ = NAKAMOTO_CONFIG.set(cfg);
    Ok(())
}

fn set_thread_handle(handle: thread::JoinHandle<()>) {
    let mut global_handle = JOIN_HANDLE.lock().unwrap();
    *global_handle = Some(handle);
}

fn stop_thread() -> Result<(), String> {
    let mut global_handle = JOIN_HANDLE.lock()
        .map_err(|_| "Mutex Error".to_owned())?;
    if let Some(h) = global_handle.take() {
        h.join().unwrap();
        Ok(())
    } else {
        Err("No thread to stop".to_owned())
    }
}
fn set_global_handle(handle: nakamoto::client::Handle<Waker>) {
    let mut global_handle = HANDLE.lock().unwrap();
    *global_handle = Some(handle);
}

fn get_global_handle() -> Result<nakamoto::client::Handle<Waker>, String> {
    let global_handle = HANDLE.lock()
        .map_err(|_| "Mutex Error".to_owned())?.clone();
    match global_handle.is_some() {
        true => Ok(global_handle.unwrap()),
        false => Err("No handle in the lock".to_owned())
    }
}

pub fn get_tip() -> Result<u32, String> {
    let handle = get_global_handle()?;

    let res = handle.get_tip()
        .map_err(|e| e.to_string())?;

    Ok(res.0 as u32)
}

pub fn get_peer_count() -> Result<u32, String> {
    let handle = get_global_handle()?;

    let res = handle.get_peers(Services::default())
        .map_err(|e| e.to_string())?;

    Ok(res.len() as u32)
}

pub fn scan_blocks(
    mut n_blocks_to_scan: u32,
    wallet: &mut Wallet,
    electrum_client: electrum_client::Client,
    scan_key_scalar: Scalar,
) -> anyhow::Result<(), String> {
    let handle = get_global_handle()?;

    let sp_receiver = wallet.sp_wallet.clone();

    loginfo("scanning blocks");

    let secp = Secp256k1::new();
    let filterchannel = handle.filters();
    let blkchannel = handle.blocks();

    let scan_height = wallet.scan_status.scan_height;
    let tip_height = handle.get_tip()
        .map_err(|e| e.to_string())?.0 as u32;

    // 0 means scan to tip
    if n_blocks_to_scan == 0 {
        n_blocks_to_scan = tip_height - scan_height;
    }

    loginfo(format!("scan_height: {:?}", scan_height).as_str());

    let start = scan_height + 1;
    let end = if scan_height + n_blocks_to_scan <= tip_height {
        scan_height + n_blocks_to_scan
    } else {
        tip_height
    };

    if start > end {
        return Err("Start height can't be higher than end".to_owned());
    }

    loginfo(format!("start: {} end: {}", start, end).as_str());
    handle.request_filters(start as u64..=end as u64)
        .map_err(|e| e.to_string())?;

    let mut tweak_data_map = electrum_client.sp_tweaks(start as usize)
        .map_err(|e| e.to_string())?;

    for n in start..=end {
        if n % 10 == 0 || n == end {
            send_scan_progress(ScanProgress {
                start,
                current: n,
                end,
            });
        }

        let (blkfilter, blkhash, blkheight) = filterchannel.recv()
            .map_err(|e| e.to_string())?;

        let tweak_data_vec = tweak_data_map.remove(&(blkheight as u32));
        if let Some(tweak_data_vec) = tweak_data_vec {
            let tweak_data_vec: Result<Vec<PublicKey>> = tweak_data_vec
                .into_iter()
                .map(|x| PublicKey::from_str(&x).map_err(|x| Error::new(x)))
                .collect();
            let shared_secret_vec: Result<Vec<PublicKey>> = tweak_data_vec
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|x| {
                    x.mul_tweak(&secp, &scan_key_scalar)
                        .map_err(|x| Error::new(x))
                })
                .collect();
            let map = calculate_script_pubkeys(
                shared_secret_vec
                .map_err(|e| e.to_string())?, 
                &sp_receiver
            );

            let found =
                search_filter_for_script_pubkeys(map.keys().cloned().collect(), blkfilter, blkhash);
            if found {
                handle.request_block(&blkhash)
                    .map_err(|e| e.to_string())?;
                let (blk, _) = blkchannel.recv().unwrap();
                let res = scan_block(&sp_receiver, blk, blkheight, map);

                loginfo(format!("outputs found:{:?}", res).as_str());

                for r in res {
                    wallet.insert_outpoint(r)
                }
                let amount = wallet.get_sum_owned();
                send_amount_update(amount);
                send_scan_progress(ScanProgress {
                    start,
                    current: n,
                    end,
                });
            } else {
                // println!("no payments found");
            }
        } else {
            // println!("no tweak data for this block");
        }
    }
    wallet.update_scan_height(end);
    Ok(())
}

pub fn start_nakamoto_client() -> anyhow::Result<(), String> {
    let cfg = NAKAMOTO_CONFIG.wait().clone();

    // Create a client using the above network reactor.
    type Reactor = nakamoto::net::poll::Reactor<net::TcpStream>;
    let client = Client::<Reactor>::new()
        .map_err(|e| format!("Failed to create nakamoto client: {}", e.to_string()))?;
    let handle = client.handle();

    set_global_handle(handle);

    let t = thread::spawn(|| {
        let res = client.run(cfg)
            .map_err(|e| format!("Nakamoto client failed with error: {}", e.to_string()));
        match res {
            Ok(()) => return,
            Err(e) => loginfo(&e),
        }
    });

    set_thread_handle(t);

    Ok(())
}

pub fn stop_nakamoto_client() -> Result<(), String> {
    let handle = get_global_handle();

    match handle {
        Ok(_) => loginfo("Got handle"),
        Err(_) => {
            return Err("Failed to get a handle".to_owned());
        }
    }

    let shutdown = handle.unwrap().shutdown();
    match shutdown {
        Ok(_) => loginfo("Successfully shutdown"),
        Err(e) => {
            return Err(format!("Failed to shutdown with error {}", e.to_string())); 
        }
    }

    stop_thread()?;
    Ok(())
}

pub fn restart_nakamoto_client() -> Result<(), String> {
    stop_nakamoto_client()?;
    loginfo("Succesfully shutdown Nakamoto, starting again...");
    start_nakamoto_client()
}

// possible block has been found, scan the block
fn scan_block(
    sp_receiver: &Receiver,
    block: Block,
    blockheight: u64,
    mut map: HashMap<Script, PublicKey>,
) -> Vec<OwnedOutput> {
    let mut res: Vec<OwnedOutput> = vec![];

    for (_, tx) in block.txdata.into_iter().enumerate() {
        if !is_eligible_sp_transaction(&tx) {
            // println!("not a valid tx");
            continue;
        }
        // collect all taproot outputs from transaction
        // todo improve
        let mut outputs_map = get_tx_with_outpoints(&tx.output);

        if let (Some(tweak_data), scripts) =
            get_tx_taproot_scripts_and_tweak_data(&tx.output, &mut map)
        {
            let xonlypubkeys = get_xonly_pubkeys_from_scripts(scripts);
            let outputs = sp_receiver
                .scan_transaction(&tweak_data, xonlypubkeys)
                .unwrap();
            for (output, scalar) in outputs {
                let (txout, index) = outputs_map.remove(&output).unwrap();

                res.push(OwnedOutput {
                    txoutpoint: OutPoint::new(tx.txid(), index),
                    tweak_data,
                    index: 0, // how do we get this?
                    tweak: scalar.to_be_bytes(),
                    blockheight,
                    amount: txout.value,
                    script: txout.script_pubkey,
                    status: crate::constants::Status::Unspent
                });
            }
        }
    }

    res
}

fn is_eligible_sp_transaction(tx: &Transaction) -> bool {
    // we check if the output has a taproot output
    tx.output.iter().any(|x| x.script_pubkey.is_v1_p2tr())
}

fn get_xonly_pubkeys_from_scripts(scripts: Vec<Script>) -> Vec<XOnlyPublicKey> {
    scripts
        .into_iter()
        .map(|x| {
            if !x.is_v1_p2tr() {
                panic!("Only taproot allowed");
            }
            let output = x.into_bytes();
            XOnlyPublicKey::from_slice(&output[2..]).unwrap()
        })
        .collect()
}

fn get_tx_taproot_scripts_and_tweak_data(
    txout: &Vec<TxOut>,
    map: &mut HashMap<Script, PublicKey>,
) -> (Option<PublicKey>, Vec<Script>) {
    let mut tweak_data = None;
    let outputs: Vec<Script> = txout
        .iter()
        .filter_map(|x| {
            let script = &x.script_pubkey;

            if let Some(found_tweak_data) = map.remove(script) {
                // this indicates we have found a tx with tweak data that we are looking for
                // in the minimal case, this output belongs to us, but there may be more
                tweak_data = Some(found_tweak_data);
                Some(script.to_owned())
            } else if script.is_v1_p2tr() {
                Some(script.to_owned())
            } else {
                None
            }
        })
        .collect();

    (tweak_data, outputs)
}

fn calculate_script_pubkeys(
    tweak_data_vec: Vec<PublicKey>,
    sp_receiver: &Receiver,
) -> HashMap<Script, PublicKey> {
    let mut res = HashMap::new();

    for tweak_data in tweak_data_vec {
        // using sp lib to get taproot output
        // we only need to look for the case n=0, we can look for the others if this matches
        let script_bytes = sp_receiver
            .get_script_bytes_from_shared_secret(&tweak_data)
            .unwrap();

        let script = Script::from(script_bytes.to_vec());
        res.insert(script, tweak_data);
    }
    res
}

fn get_tx_with_outpoints(txout: &Vec<TxOut>) -> HashMap<XOnlyPublicKey, (TxOut, u32)> {
    let mut res = HashMap::new();

    for (i, o) in txout.iter().enumerate() {
        if o.script_pubkey.is_v1_p2tr() {
            let pk = XOnlyPublicKey::from_slice(&o.script_pubkey.as_bytes()[2..]).unwrap();
            res.insert(pk, (o.clone(), i as u32));
        }
    }
    res
}

fn search_filter_for_script_pubkeys(
    scriptpubkeys: Vec<Script>,
    blkfilter: BlockFilter,
    blkhash: BlockHash,
) -> bool {
    if scriptpubkeys.len() == 0 {
        return false;
    }

    // get bytes of every script
    let script_bytes: Vec<Vec<u8>> = scriptpubkeys.into_iter().map(|x| x.to_bytes()).collect();

    // the query for nakamoto filters is a iterator over the script byte slices
    let mut query = script_bytes.iter().map(|x| x.as_slice());

    // match our query against the block filter
    let found = blkfilter.match_any(&blkhash, &mut query).unwrap();

    found
}
