#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::{self, File};
use std::path::Path;
use pqcrypto_sphincsplus::sphincssha2128fsimple::{
	keypair, detached_sign, verify_detached_signature,
	PublicKey, SecretKey,
};
use pqcrypto_traits::sign::{PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait, DetachedSignature};
use blake3;
use serde::{Deserialize, Serialize};
use tauri::command;
use std::process::Command;
use std::path::PathBuf;
use hex::encode;
use hex::decode;
use std::sync::Mutex;
use lazy_static::lazy_static;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::Manager;

use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use rand::RngCore;
use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha256;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Wallet {
    public_key: String,
    secret_key: String,
    address: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct PoolData {
    id: String,
    coinid: String,
    height: String,
    diff: String,
    reward: String,
    rewardusdt: String,
    ts: String,
    name: String,
    symbol: String,
    blocktime: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Output {
    txid: String,
    vout: String,
    amount: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct INTXO {
    txid: String,
    vout: u32,
    extrasize: String,
    extra: String,
    sequence: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RawTransaction {
    inputcount: String,
    inputs: Vec<INTXO>,
    outputcount: String,
    outputs: Vec<(String, u64)>,
    fee: u64,
    sigpub: String,
    signature: String,
}

lazy_static! {
    static ref STORED_OUTPUTS: Mutex<Vec<Output>> = Mutex::new(Vec::new());
    static ref LAST_FETCH_TS: Mutex<u64> = Mutex::new(0);
	static ref ACTIVE_WALLET: Mutex<Option<Wallet>> = Mutex::new(None);
}

#[derive(Serialize, Deserialize, Debug)]
struct MinerWorker {
    name: String,
    hashrate: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct MiningPendingPaid {
    xpara: f64,
    usdt: f64,
}

#[derive(Serialize, Deserialize, Debug)]
struct MinerData {
    active: u8,
    hashrate: u64,
    totalhashes: u64,
    workers: Vec<MinerWorker>,
    pending: MiningPendingPaid,
    paid: MiningPendingPaid,
}

#[derive(Clone, serde::Deserialize)]
struct StakingData {
    staked: u64,
    pending: u64,
}

#[derive(Deserialize)]
struct PolygonData {
    user_id: String,
    xp_address: String,
    address: String,
}

#[command]
async fn get_miner_data() -> Result<String, String> {
    let wallet = get_active_wallet()?;

    let url = format!("https://xpara.site/miner.php?address={}", wallet.address);

    let client = reqwest::Client::new();
    let response = client.get(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let text = response.text().await.map_err(|e| e.to_string())?;
    Ok(text)
}

fn set_outputs(outputs: Vec<Output>) {
    let mut stored = STORED_OUTPUTS.lock().unwrap();
    *stored = outputs;
}

fn get_outputs() -> Vec<Output> {
    STORED_OUTPUTS.lock().unwrap().clone()
}

fn set_last_fetch_ts(ts: u64) {
    let mut last = LAST_FETCH_TS.lock().unwrap();
    *last = ts;
}

fn get_last_fetch_ts() -> u64 {
    *LAST_FETCH_TS.lock().unwrap()
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn get_active_wallet() -> Result<Wallet, String> {
    ACTIVE_WALLET
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "No wallet selected".to_string())
}

fn derive_key(password: &str, salt: &[u8]) -> Key<Aes256Gcm> {
    let mut key_bytes = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, 100_000, &mut key_bytes);
    Key::<Aes256Gcm>::from_slice(&key_bytes).clone()
}

#[command]
async fn fetch_outputs_and_balance() -> Result<u64, String> {
    let wallet = get_active_wallet()?;

    let current_ts = now_ts();
    let last_ts = get_last_fetch_ts();
    if current_ts - last_ts < 60 {
        let total: u64 = get_outputs()
            .iter()
            .filter_map(|o| o.amount.parse::<u64>().ok())
            .sum();
        return Ok(total);
    }
    let url = format!("https://xpara.site/outputs.php?address={}", wallet.address);
    let client = reqwest::Client::new();

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let outputs: Vec<Output> = response.json().await.map_err(|e| e.to_string())?;
    set_outputs(outputs.clone());
    set_last_fetch_ts(current_ts);
    let total: u64 = outputs
        .iter()
        .filter_map(|o| o.amount.parse::<u64>().ok())
        .sum();
    Ok(total)
}

#[command]
async fn fetch_staking() -> Result<(u64, u64), String> {
    let wallet = get_active_wallet()?;

    let url = format!("https://xpara.site/staking.php?address={}", wallet.address);
    let client = reqwest::Client::new();

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    
    let staking_data: StakingData = response.json().await.map_err(|e| e.to_string())?;
    Ok((staking_data.staked, staking_data.pending))
}

#[command]
async fn fetch_polygon() -> Result<String, String> {
    let wallet = get_active_wallet()?;

    let url = format!("https://xpara.site/polygon.php?address={}", wallet.address);
    let client = reqwest::Client::new();

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let polygon_data: PolygonData = response.json().await.map_err(|e| e.to_string())?;
    Ok(polygon_data.address)
}

#[command]
fn get_stored_outputs() -> Result<Vec<Output>, String> {
    Ok(get_outputs())
}

#[tauri::command]
async fn run_miner() -> Result<String, String> {
    let wallet = get_active_wallet()?;

    let exe_path = "./xmrig/xmrig.exe";
    let args = [
        exe_path,
        "-o", "xpara.site:4444",
        "-u", &wallet.address
    ];
    match Command::new("cmd")
        .args(&["/C", "start"])
        .args(&args)
        .spawn()
    {
        Ok(_) => Ok("XMRig started on new terminal.".to_string()),
        Err(e) => Err(format!("Error starting XMRig: {}", e)),
    }
}

#[command]
async fn get_pool_data() -> Result<String, String> {
    let client = reqwest::Client::new();
    let response = client.get("https://xpara.site/pools.php")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let pools_data: Vec<PoolData> = response.json().await.map_err(|e| e.to_string())?;
    serde_json::to_string(&pools_data).map_err(|e| e.to_string())
}

fn load_wallet_from_file(filename: &str, password: &str) -> Option<Wallet> {
    let data = fs::read(filename).ok()?;
    if password.is_empty() {
        serde_json::from_slice(&data).ok()
    } else {
        if data.len() < 28 {
            return None;
        }
        let salt = &data[0..16];
        let nonce_bytes = &data[16..28];
        let ciphertext = &data[28..];

        let key = derive_key(password, salt);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext).ok()?;
        serde_json::from_slice(&plaintext).ok()
    }
}

#[tauri::command]
fn export_wallet_with_new_password(new_password: String) -> Result<String, String> {
    let wallet = get_active_wallet()?;
    let filename = format!("{}_encrypted.json", wallet.address);
    save_wallet_to_file(&wallet, &filename, &new_password)?;
    Ok(filename)
}


fn save_wallet_to_file(wallet: &Wallet, filename: &str, password: &str) -> Result<(), String> {
    if password.is_empty() {
        let file = File::create(filename)
            .map_err(|e| format!("Unable to create {}: {}", filename, e))?;
        serde_json::to_writer_pretty(file, &wallet)
            .map_err(|e| format!("Unable to write {}: {}", filename, e))?;
        return Ok(());
    }

    let mut salt = [0u8; 16];
	rand::thread_rng().fill_bytes(&mut salt);
	let mut nonce_bytes = [0u8; 12];
	rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let wallet_json = serde_json::to_vec(wallet).map_err(|e| e.to_string())?;
    let ciphertext = cipher.encrypt(nonce, wallet_json.as_ref())
        .map_err(|e: aes_gcm::Error| e.to_string())?;

    let mut file_data = vec![];
    file_data.extend_from_slice(&salt);
    file_data.extend_from_slice(&nonce_bytes);
    file_data.extend_from_slice(&ciphertext);

    fs::write(filename, file_data).map_err(|e| e.to_string())
}

#[tauri::command]
fn list_wallets() -> Result<Vec<String>, String> {
    let paths = fs::read_dir(".").map_err(|e| e.to_string())?;
    let mut wallets = vec![];
    for entry in paths {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "json" {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        wallets.push(name.to_string());
                    }
                }
            }
        }
    }
    Ok(wallets)
}

#[tauri::command]
fn select_wallet(filename: String, password: String) -> Result<Wallet, String> {
    let wallet = load_wallet_from_file(&filename, &password)
        .ok_or("Unable to load wallet or incorrect password")?;
    let mut active = ACTIVE_WALLET.lock().unwrap();
    *active = Some(wallet.clone());
    set_last_fetch_ts(now_ts() - 120);
    Ok(wallet)
}

#[tauri::command]
fn get_wallet() -> Option<Wallet> {
    ACTIVE_WALLET.lock().unwrap().clone()
}

fn generate_wallet() -> Wallet {
    let (pk, sk) = keypair();
    let public_key = encode(pk.as_bytes());
    let secret_key = encode(sk.as_bytes());
    let mut address = encode(blake3::hash(pk.as_bytes()).as_bytes());
	address.replace_range(0..2, "xP");
    
    Wallet {
        public_key,
        secret_key,
        address,
    }
}

/*fn save_wallet(wallet: &Wallet) -> Result<(), String> {
    let file = File::create("wallet.json")
        .map_err(|e| format!("Unable to create wallet.json: {}", e))?;
    serde_json::to_writer_pretty(file, &wallet)
        .map_err(|e| format!("Unable to write wallet.json: {}", e))?;
    Ok(())
}*/

/*fn load_wallet() -> Option<Wallet> {
    if Path::new("wallet.json").exists() {
        let data = fs::read_to_string("wallet.json").ok()?;
        serde_json::from_str(&data).ok()
    } else {
        None
    }
}*/

#[tauri::command]
fn create_wallet(name: String, password: String) -> Result<Wallet, String> {
    let filename = format!("{}.json", name);
    if Path::new(&filename).exists() {
        return Err(format!("Wallet {} ya existe", filename));
    }
    let wallet = generate_wallet();
    save_wallet_to_file(&wallet, &filename, &password)?;
    Ok(wallet)
}


/*#[command]
fn get_wallet() -> Result<Wallet, String> {
    if let Some(wallet) = load_wallet() {
        Ok(wallet)
    } else {
        let wallet = generate_wallet();
        save_wallet(&wallet)?;
        Ok(wallet)
    }
}*/

#[command]
fn delete_wallet_file() -> Result<(), String> {
    if Path::new("wallet.json").exists() {
        fs::remove_file("wallet.json")
            .map_err(|e| format!("Failed to delete wallet file: {}", e))?;
    }
    Ok(())
}

#[command]
async fn get_mining_data() -> Result<String, String> {
    let client = reqwest::Client::new();
    let response = client.get("https://xpara.site/mining.php")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    response.text().await.map_err(|e| e.to_string())
}

fn select_utxos(utxos: &[Output], amount_needed: u64, fee_per_input: u64) -> (Vec<(String, u64, u64)>, u64) {
    let mut selected = Vec::new();
    let mut total = 0u64;
    for utxo in utxos {
        let vout_num = utxo.vout.parse::<u64>().unwrap_or(0);
        let amt = utxo.amount.parse::<u64>().unwrap_or(0);
        selected.push((utxo.txid.clone(), vout_num, amt));
        total += amt;
        if total >= amount_needed + fee_per_input {
            break;
        }
    }
    (selected, total)
}

#[command]
async fn send_transaction(dest_address: String, amount: f64, extradata: String) -> Result<String, String> {
    let wallet = get_active_wallet()?;

    let pk_bytes = decode(&wallet.public_key).map_err(|e| e.to_string())?;
    let sk_bytes = decode(&wallet.secret_key).map_err(|e| e.to_string())?;

    let utxos = get_outputs();
    if utxos.is_empty() {
        return Err("No UTXOs in memory".to_string());
    }

    let amount_u64 = (amount * 100000000.0) as u64;
    let fee_per_input = 5000;
    let fee_per_output = 2000;
    let output_count = 2;

    let (selected_utxos, total_inputs) = select_utxos(&utxos, amount_u64, fee_per_input);
    if selected_utxos.is_empty() {
        return Err("Not enough funds".to_string());
    }

    let exact_fee = (selected_utxos.len() as u64 * fee_per_input) + (output_count as u64 * fee_per_output);
    if total_inputs < amount_u64 + exact_fee {
        return Err("Not enough funds including fees".to_string());
    }

    let mut outputs = vec![(dest_address.clone(), amount_u64)];
    let change = total_inputs - amount_u64 - exact_fee;
    if change > 0 {
        outputs.push((wallet.address.clone(), change));
    }

    let inputs: Vec<INTXO> = selected_utxos.iter().map(|(txid, vout, _)| {
        INTXO {
            txid: txid.clone(),
            vout: *vout as u32,
            extrasize: "00".to_string(),
            extra: extradata.clone(),
            sequence: 0xFFFFFFFF,
        }
    }).collect();

    let mut raw_tx = RawTransaction {
        inputcount: format!("{:02x}", inputs.len()),
        inputs,
        outputcount: format!("{:02x}", outputs.len()),
        outputs: outputs.clone(),
        fee: exact_fee,
        sigpub: wallet.public_key.clone(),
        signature: "".to_string(),
    };
	
    let tx_binary = bincode::serialize(&raw_tx).map_err(|e| e.to_string())?;
    let tx_hash = blake3::hash(&tx_binary);

    let sk = SecretKey::from_bytes(&sk_bytes).map_err(|_| "Invalid secret key")?;
    let signature = detached_sign(tx_hash.as_bytes(), &sk);
    raw_tx.signature = encode(signature.as_bytes());

    let signed_tx_binary = bincode::serialize(&raw_tx).map_err(|e| e.to_string())?;
    let signed_tx_hex = encode(&signed_tx_binary);

    let client = reqwest::Client::new();
    let send_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "xp_wallet",
        "method": "xp_sendRawTransaction",
        "params": [signed_tx_hex]
    });

        let resp_text = client
			.post("https://xpara.site/rpc")
			.header("Content-Type", "application/json")
			.json(&send_request)
			.send()
			.await
			.map_err(|e| e.to_string())?
			.text()
			.await
			.map_err(|e| e.to_string())?;

		let parsed: serde_json::Value = serde_json::from_str(&resp_text)
			.map_err(|e| format!("Invalid JSON response: {}, raw: {}", e, resp_text))?;

		let mut success = false;
		if let Some(result_val) = parsed.get("result") {
			if let Some(s) = result_val.as_str() {
				if !s.is_empty() {
					success = true;
				}
			}
		}

		if success {
			let mut stored = STORED_OUTPUTS.lock().unwrap();
			stored.retain(|o| {
				!selected_utxos.iter().any(|(txid, vout, _)| {
					o.txid == *txid && o.vout.parse::<u64>().unwrap_or(0) == *vout
				})
			});
			let current_ts = now_ts();
			set_last_fetch_ts(current_ts);
		}

		Ok(format!("{}", resp_text))

}

#[tauri::command]
fn sign_message(message: String) -> Result<serde_json::Value, String> {
    let wallet = get_active_wallet()?;
    let sk_bytes = decode(&wallet.secret_key).map_err(|e| format!("Invalid secret key hex: {}", e))?;
    let sk = SecretKey::from_bytes(&sk_bytes).map_err(|_| "Failed to load secret key")?;
    let signature = detached_sign(message.as_bytes(), &sk);
    Ok(serde_json::json!({
        "pubkey": wallet.public_key,
        "sign": encode(signature.as_bytes())
    }))
}


fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_wallet, 
            delete_wallet_file, 
            get_mining_data, 
            get_pool_data, 
            run_miner,
            fetch_outputs_and_balance,
            get_stored_outputs,
			send_transaction,
			get_miner_data,
			fetch_staking,
			fetch_polygon,
			list_wallets,
			select_wallet,
			create_wallet,
			export_wallet_with_new_password,
			sign_message
        ])
		.setup(|app| {
            let window = app.get_webview_window("main").unwrap();
            window.maximize().unwrap();
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri app");
}