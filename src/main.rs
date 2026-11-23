mod addrman;
mod address;
mod bech32;
mod block;
mod chain;
mod ecdsa;
mod hex;
mod node;
mod params;
mod rpc;
mod sha256;
mod wallet;

use chain::Chain;
use params::*;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

struct Opts {
    net: &'static Network,
    datadir: PathBuf,
    connect: Vec<String>,
    listen: String,
    mine: bool,
    seeds: Vec<String>,
    allow_local: bool,
    discover: bool,
    nodiscovery: bool,
    threads: usize,
    p2p_port: Option<u16>,
    rpc_port: Option<u16>,
    rest: Vec<String>,
}

fn parse_opts(args: &[String]) -> Opts {
    let mut net: &'static Network = &MAINNET;
    let mut datadir: Option<PathBuf> = None;
    let mut connect = vec![];
    let mut listen = "0.0.0.0".to_string();
    let mut mine = false;
    let mut seeds: Vec<String> = vec![];
    let mut allow_local = false;
    let mut discover = false;
    let mut nodiscovery = false;
    let mut threads: usize = 1;
    let mut p2p_port: Option<u16> = None;
    let mut rpc_port: Option<u16> = None;
    let mut rest = vec![];
    for a in args {
        if let Some(v) = a.strip_prefix("--net=") {
            net = by_name(v).unwrap_or_else(|| {
                eprintln!("unknown network: {}", v);
                std::process::exit(1)
            });
        } else if let Some(v) = a.strip_prefix("--datadir=") {
            datadir = Some(PathBuf::from(v));
        } else if let Some(v) = a.strip_prefix("--connect=") {
            connect.push(v.to_string());
        } else if let Some(v) = a.strip_prefix("--listen=") {
            listen = v.to_string();
        } else if let Some(v) = a.strip_prefix("--p2pport=") {
            p2p_port = Some(v.parse().unwrap_or_else(|_| die("bad --p2pport")));
        } else if let Some(v) = a.strip_prefix("--rpcport=") {
            rpc_port = Some(v.parse().unwrap_or_else(|_| die("bad --rpcport")));
        } else if let Some(v) = a.strip_prefix("--threads=") {
            threads = v.parse().unwrap_or_else(|_| die("bad --threads"));
            if threads == 0 || threads > 256 {
                die("--threads must be between 1 and 256");
            }
        } else if let Some(v) = a.strip_prefix("--seed=") {
            seeds.push(v.to_string());
        } else if a == "--allowlocal" {
            allow_local = true;
        } else if a == "--discover" {
            discover = true;
        } else if a == "--nodiscovery" {
            nodiscovery = true;
        } else if a == "--mine" {
            mine = true;
        } else {
            rest.push(a.clone());
        }
    }
    let datadir = datadir.unwrap_or_else(|| {
        let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".riyalcoin").join(net.name)
    });
    Opts { net, datadir, connect, listen, mine, seeds, allow_local, discover, nodiscovery, threads, p2p_port, rpc_port, rest }
}

fn prompt(msg: &str) -> String {
    use std::io::Write;
    eprint!("{}", msg);
    let _ = std::io::stderr().flush();
    let _ = std::process::Command::new("stty").arg("-echo").status();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    let _ = std::process::Command::new("stty").arg("echo").status();
    eprintln!();
    s.trim_end_matches(|c: char| c == '\n' || c == '\r').to_string()
}

fn die(msg: &str) -> ! {
    eprintln!("error: {}", msg);
    std::process::exit(1)
}

fn run_node(o: Opts) {
    node::MINING_THREADS.store(o.threads, std::sync::atomic::Ordering::Relaxed);
    let p2p = o.p2p_port.unwrap_or(o.net.p2p_port);
    let rpcp = o.rpc_port.unwrap_or(o.net.rpc_port);
    let node = node::Node::open(o.net, o.datadir.clone()).unwrap_or_else(|e| die(&e));
    let shared: node::Shared = Arc::new(Mutex::new(node));
    let token = {
        let mut b = [0u8; 16];
        let sk = ecdsa::random_secret().unwrap_or_else(|| die("no randomness source"));
        b.copy_from_slice(&sk[..16]);
        hex::encode(&b)
    };
    wallet::write_private(&o.datadir.join(".cookie"), &token).unwrap_or_else(|e| die(&e.to_string()));
    shared.lock().unwrap().allow_local = o.allow_local || o.net.name == "regtest";
    node::start_p2p(shared.clone(), &o.listen, p2p).unwrap_or_else(|e| die(&e));
    rpc::start_rpc(shared.clone(), rpcp, token).unwrap_or_else(|e| die(&e));
    // anchors first: the two longest-lived outbound peers of the previous run
    let anchored = node::connect_anchors(&shared);
    if anchored > 0 {
        println!("anchors: {} connected", anchored);
    }
    // seeds: --seed=host:port (a DNS name may return many addresses) and an optional <datadir>/seeds.txt
    let mut seed_list = o.seeds.clone();
    if let Ok(s) = std::fs::read_to_string(o.datadir.join("seeds.txt")) {
        for line in s.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                seed_list.push(line.to_string());
            }
        }
    }
    for s in &seed_list {
        match node::add_seed(&shared, s) {
            Ok(k) => println!("seed {}: {} new addresses", s, k),
            Err(e) => eprintln!("{}", e),
        }
    }
    let discover = !o.nodiscovery && (o.discover || o.net.name != "regtest");
    if discover {
        node::start_outbound_manager(shared.clone());
    }
    for c in &o.connect {
        if let Err(e) = node::connect(shared.clone(), c) {
            eprintln!("connect failed: {}", e);
        }
    }
    {
        let n = shared.lock().unwrap();
        println!("riyalcoin {} | height {} | P2P {} RPC {} | datadir {}", o.net.name, n.chain.height(), p2p, rpcp, o.datadir.display());
    }
    if o.mine {
        let pkh = {
            let mut n = shared.lock().unwrap();
            let first = n.wallet.keys.first().map(|k| k.pkh);
            match first {
                Some(p) => p,
                None => n.wallet.new_key().unwrap_or_else(|e| die(&e)),
            }
        };
        let sh = shared.clone();
        std::thread::spawn(move || loop {
            if sh.lock().unwrap().stop {
                break;
            }
            let wait = sh.lock().unwrap().chain.mining_opens_in();
            if let Some(s) = wait {
                println!("mining paused: this network accepts its next block in {} s (about {:.1} h)", s, s as f64 / 3600.0);
                for _ in 0..60 {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    if sh.lock().unwrap().stop {
                        return;
                    }
                }
                continue;
            }
            let stop = || !sh.lock().unwrap().stop;
            if let Some(h) = node::mine_one(&sh, pkh, &stop) {
                println!("mined {}", h);
            } else {
                break;
            }
        });
    }
    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if shared.lock().unwrap().stop {
            break;
        }
    }
    {
        let n = shared.lock().unwrap();
        let path = n.datadir.join("peers.dat");
        n.addrs.save(&path);
        n.save_anchors();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");
    let o = parse_opts(&args[args.len().min(2)..]);
    match cmd {
        "node" => run_node(o),
        "cli" => {
            let method = o.rest.first().cloned().unwrap_or_else(|| die("usage: cli [--net=..] <method> [params]"));
            let token = std::fs::read_to_string(o.datadir.join(".cookie")).unwrap_or_else(|_| die("cannot read .cookie (is the node running?)"));
            let mut params: Vec<String> = o.rest[1..].to_vec();
            // passphrases are typed at a hidden prompt, not passed on the command line (shell history, `ps`)
            match method.as_str() {
                "encryptwallet" if params.is_empty() => {
                    let a = prompt("New passphrase (min 8 chars): ");
                    let b = prompt("Repeat passphrase: ");
                    if a != b {
                        die("passphrases do not match");
                    }
                    params = vec![a];
                }
                "walletpassphrase" if params.len() == 1 => {
                    let a = prompt("Passphrase: ");
                    params.insert(0, a);
                }
                _ => {}
            }
            match rpc::client(o.rpc_port.unwrap_or(o.net.rpc_port), token.trim(), &method, &params) {
                Ok(r) => println!("{}", r),
                Err(e) => die(&e),
            }
        }
        "params" => {
            let n = o.net;
            println!("{}: P2P {} RPC {} magic {} hrp \"{}\"", n.name, n.p2p_port, n.rpc_port, hex::encode(&n.magic), n.bech32_hrp);
            println!("genesis {} bits {:#010x} nonce {}", n.genesis.hash, n.genesis.bits, n.genesis.nonce);
        }
        "verify-genesis" => {
            for n in ALL.iter() {
                let c = Chain::new(n);
                let ok = c.tip().header.hash_hex() == n.genesis.hash && c.tip().header.check_pow();
                println!("{:<9} {} {}", n.name, if ok { "OK  " } else { "FAIL" }, c.tip().header.hash_hex());
            }
        }
        "supply" => {
            let mut total: u128 = 0;
            for era in 0..45u32 {
                let s = block_subsidy(era * HALVING_INTERVAL);
                if s == 0 {
                    break;
                }
                total += s as u128 * HALVING_INTERVAL as u128;
                println!("era {:>2}: reward {} -> total {}", era, fmt_coins(s), fmt_coins(total as u64));
            }
            println!("cap: {}", fmt_coins(MAX_MONEY));
        }
        _ => {
            println!("riyalcoin node [--net=regtest] [--datadir=DIR] [--connect=HOST:PORT] [--listen=ADDR] [--p2pport=N] [--rpcport=N] [--mine] [--threads=N] [--seed=HOST:PORT] [--allowlocal] [--discover|--nodiscovery]");
            println!("riyalcoin cli [--net=NET] [--datadir=DIR] [--rpcport=N] <getinfo|getnewaddress|getbalance|sendtoaddress ADDR AMOUNT|generate N|getblock H|addnode H:P|getpeerinfo|getaddrmaninfo|getnodeaddresses|getmininginfo|listunspent|listtransactions [N]|sendmany ADDR AMT ...|backupwallet PATH|getnewaddress [bech32]|getwalletinfo|encryptwallet|walletpassphrase SECS|walletlock|stop>");
            println!("riyalcoin params|verify-genesis|supply");
        }
    }
}
