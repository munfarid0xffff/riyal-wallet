//! Starts a full node inside another process (the GUI wallet) and talks to it over the local RPC.
//! Mirrors `run_node` in main.rs but returns errors instead of exiting the process.
use crate::{ecdsa, hex, node, params, rpc, wallet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub struct Embedded {
    pub shared: node::Shared,
    pub rpc_port: u16,
    pub token: String,
    pub net: &'static params::Network,
    pub datadir: PathBuf,
}

/// Opens the chain + wallet in `datadir`, starts P2P (bound to `listen`), RPC (127.0.0.1) and peer discovery.
pub fn start(net_name: &str, datadir: PathBuf, seeds: Vec<String>, listen: &str) -> Result<Embedded, String> {
    let net = params::by_name(net_name).ok_or_else(|| format!("unknown network: {}", net_name))?;
    std::fs::create_dir_all(&datadir).map_err(|e| format!("cannot create {}: {}", datadir.display(), e))?;
    let node = node::Node::open(net, datadir.clone())?;
    let shared: node::Shared = Arc::new(Mutex::new(node));

    let token = {
        let sk = ecdsa::random_secret().ok_or("no randomness source")?;
        hex::encode(&sk[..16])
    };
    wallet::write_private(&datadir.join(".cookie"), &token).map_err(|e| e.to_string())?;

    shared.lock().unwrap().allow_local = net.name == "regtest";
    node::start_p2p(shared.clone(), listen, net.p2p_port)?;
    rpc::start_rpc(shared.clone(), net.rpc_port, token.clone())?;
    node::connect_anchors(&shared);

    let mut seed_list = seeds;
    if let Ok(s) = std::fs::read_to_string(datadir.join("seeds.txt")) {
        for line in s.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                seed_list.push(line.to_string());
            }
        }
    }
    for s in &seed_list {
        let _ = node::add_seed(&shared, s); // an unreachable seed must not stop the wallet from opening
    }
    if net.name != "regtest" {
        node::start_outbound_manager(shared.clone());
    }
    Ok(Embedded { shared, rpc_port: net.rpc_port, token, net, datadir })
}

impl Embedded {
    /// One JSON-RPC call; returns the raw JSON `result` text, or the node's error message.
    pub fn call(&self, method: &str, params: &[String]) -> Result<String, String> {
        rpc::client(self.rpc_port, &self.token, method, params)
    }

    /// Stops background loops and persists the peer book.
    pub fn shutdown(&self) {
        let n = {
            let mut g = self.shared.lock().unwrap();
            g.stop = true;
            g
        };
        n.addrs.save(&n.datadir.join("peers.dat"));
        n.save_anchors();
    }
}
