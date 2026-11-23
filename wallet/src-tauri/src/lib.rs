use riyalcoin::embed::{self, Embedded};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Manager, RunEvent, State};

/// Methods the UI may call. Mining, `generate`, `stop`, `addnode` etc. are deliberately not reachable from the UI.
const ALLOWED: &[&str] = &[
    "getinfo",
    "getbalance",
    "getnewaddress",
    "listaddresses",
    "sendtoaddress",
    "listtransactions",
    "listunspent",
    "getwalletinfo",
    "encryptwallet",
    "walletpassphrase",
    "walletlock",
    "getpeerinfo",
];

#[derive(Serialize, Deserialize, Clone)]
struct Config {
    net: String,
    seeds: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config { net: "mainnet".into(), seeds: vec![] }
    }
}

enum NodeState {
    Starting,
    Running(Embedded),
    Failed(String),
}

struct AppState {
    node: Arc<Mutex<NodeState>>,
    dir: PathBuf,
}

fn cfg_path(dir: &PathBuf) -> PathBuf {
    dir.join("wallet-config.json")
}

fn load_config(dir: &PathBuf) -> Config {
    std::fs::read_to_string(cfg_path(dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

#[tauri::command]
fn get_config(state: State<'_, AppState>) -> Config {
    load_config(&state.dir)
}

/// Saves the network/seeds; they take effect after the app restarts.
#[tauri::command]
fn set_config(state: State<'_, AppState>, net: String, seeds: Vec<String>) -> Result<(), String> {
    if riyalcoin::params::by_name(&net).is_none() {
        return Err(format!("unknown network: {}", net));
    }
    let seeds: Vec<String> = seeds.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let json = serde_json::to_string_pretty(&Config { net, seeds }).map_err(|e| e.to_string())?;
    std::fs::write(cfg_path(&state.dir), json).map_err(|e| e.to_string())
}

/// "starting", "running" or an error message.
#[tauri::command]
fn node_status(state: State<'_, AppState>) -> String {
    match &*state.node.lock().unwrap() {
        NodeState::Starting => "starting".into(),
        NodeState::Running(_) => "running".into(),
        NodeState::Failed(e) => format!("error: {}", e),
    }
}

/// Calls one whitelisted node RPC and returns its JSON result.
#[tauri::command]
async fn rpc(state: State<'_, AppState>, method: String, params: Vec<String>) -> Result<serde_json::Value, String> {
    if !ALLOWED.contains(&method.as_str()) {
        return Err("method not allowed".into());
    }
    let node = state.node.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let raw = {
            let g = node.lock().unwrap();
            match &*g {
                NodeState::Running(e) => e.call(&method, &params)?,
                NodeState::Starting => return Err("node is starting".to_string()),
                NodeState::Failed(e) => return Err(e.clone()),
            }
        };
        let v: serde_json::Value = serde_json::from_str(&raw).map_err(|e| format!("bad node reply: {}", e))?;
        match v.get("error") {
            Some(serde_json::Value::Null) | None => Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null)),
            Some(serde_json::Value::String(s)) => Err(s.clone()),
            Some(other) => Err(other.to_string()),
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Copies wallet.dat to a backup file; returns {path, hex} (hex = file contents).
#[tauri::command]
async fn backup_wallet(app: AppHandle, state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let dir = app.path().document_dir().unwrap_or_else(|_| state.dir.clone()).join("RiyalCoin-backups");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let path = dir.join(format!("wallet-{}.dat", ts));
    let p = path.to_string_lossy().to_string();
    let node = state.node.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let g = node.lock().unwrap();
        match &*g {
            NodeState::Running(e) => {
                let raw = e.call("backupwallet", &[p.clone()])?;
                let v: serde_json::Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
                match v.get("error") {
                    Some(serde_json::Value::String(s)) => Err(s.clone()),
                    _ => {
                        // Also return the file as hex so the UI can show/copy it (the folder is not reachable on Android).
                        let bytes = std::fs::read(&p).map_err(|e| e.to_string())?;
                        Ok(serde_json::json!({ "path": p, "hex": riyalcoin::hex::encode(&bytes) }))
                    }
                }
            }
            _ => Err("node is not running".to_string()),
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Replaces wallet.dat with a backup (hex text from `backup_wallet`). The current wallet is kept as wallet.dat.bak-<time>,
/// never deleted. The node is stopped afterwards; the UI then restarts the app.
#[tauri::command]
async fn restore_wallet(state: State<'_, AppState>, backup_hex: String) -> Result<(), String> {
    let clean: String = backup_hex.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("backup text is not valid hex".into());
    }
    let bytes = riyalcoin::hex::decode(&clean).ok_or("backup text is not valid hex")?;
    let cfg = load_config(&state.dir);
    let datadir = state.dir.join("chain").join(&cfg.net);
    let node = state.node.clone();
    tauri::async_runtime::spawn_blocking(move || {
        std::fs::create_dir_all(&datadir).map_err(|e| e.to_string())?;
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        // validate with the node's own parser before touching the live wallet
        let tmp = datadir.join(format!("wallet.restore-{}.tmp", ts));
        std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
        let ok = match riyalcoin::wallet::Wallet::load(tmp.clone()) {
            Ok(w) if !w.keys.is_empty() => Ok(()),
            Ok(_) => Err("backup contains no keys".to_string()),
            Err(e) => Err(format!("invalid backup: {}", e)),
        };
        if let Err(e) = ok {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        // stop the running node first so it cannot overwrite the restored file
        {
            let mut g = node.lock().unwrap();
            if let NodeState::Running(e) = &*g {
                e.shutdown();
            }
            *g = NodeState::Failed("restart required".into());
        }
        let live = datadir.join("wallet.dat");
        if live.exists() {
            std::fs::rename(&live, datadir.join(format!("wallet.dat.bak-{}", ts))).map_err(|e| e.to_string())?;
        }
        std::fs::rename(&tmp, &live).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Restarts the app on desktop; on Android the user reopens it (the process is closed).
#[tauri::command]
fn restart_app(app: AppHandle) {
    #[cfg(desktop)]
    app.restart();
    #[cfg(mobile)]
    app.exit(0);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();
    // Camera QR scanning is provided natively on Android/iOS only.
    #[cfg(mobile)]
    let builder = builder.plugin(tauri_plugin_barcode_scanner::init());
    let app = builder
        .setup(|app| {
            let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let cfg = load_config(&dir);
            let node = Arc::new(Mutex::new(NodeState::Starting));
            app.manage(AppState { node: node.clone(), dir: dir.clone() });
            // Opening the chain can take a moment: do it off the UI thread.
            std::thread::spawn(move || {
                let datadir = dir.join("chain").join(&cfg.net);
                // A wallet never needs inbound connections: P2P listens on loopback only.
                let r = embed::start(&cfg.net, datadir, cfg.seeds.clone(), "127.0.0.1");
                *node.lock().unwrap() = match r {
                    Ok(e) => NodeState::Running(e),
                    Err(e) => NodeState::Failed(e),
                };
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![get_config, set_config, node_status, rpc, backup_wallet, restore_wallet, restart_app])
        .build(tauri::generate_context!())
        .expect("error while building RiyalCoin Wallet");

    app.run(|handle, event| {
        if let RunEvent::Exit = event {
            if let Some(st) = handle.try_state::<AppState>() {
                if let NodeState::Running(e) = &*st.node.lock().unwrap() {
                    e.shutdown();
                }
            }
        }
    });
}
