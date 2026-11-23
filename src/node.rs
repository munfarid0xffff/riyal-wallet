use crate::addrman::{decode_addrs, encode_addrs, group, now_secs, AddrBook};
use crate::block::*;
use crate::chain::{check_tx, sigs_ok, Accept, Chain, OutPoint};
use crate::params::*;
use crate::sha256::double_sha256;
use crate::wallet::Wallet;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use k256::elliptic_curve::rand_core::{OsRng, RngCore};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Arc, Mutex, Once};
use std::thread;
use std::time::{Duration, Instant};

// ---- DoS limits -------------------------------------------------------------------------------
const MAX_PEERS: usize = 32;
const MAX_INBOUND: usize = 24; // the rest is reserved for outbound connections
const MAX_PER_IP: usize = 2; // loopback is exempt (local testing)
const BAN_SCORE: u32 = 100;
const BAN_SECS: u64 = 86_400;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_secs(1200);
const WINDOW: Duration = Duration::from_secs(10);
const MAX_TX_PER_WINDOW: u32 = 30; // each tx costs a signature check
const MAX_REQ_PER_WINDOW: u32 = 2000; // getblock / getblk requests
const MAX_MSG_PER_WINDOW: u32 = 5000;
const TARGET_OUTBOUND: usize = 8;
const OUT_QUEUE: usize = 16; // frames queued per peer; a peer that cannot keep up is dropped

pub struct Peer {
    pub id: u64,
    pub ip: IpAddr,
    pub inbound: bool,
    pub score: u32,
    pub since: Instant,
    pub addr: Option<SocketAddr>, // where this peer listens (outbound: dialed address; inbound: from its version)
    asked_addr: bool,
    served_addr: bool,
    out: SyncSender<Vec<u8>>,
    stream: TcpStream, // only used to shut the socket down
}

pub struct Node {
    pub chain: Chain,
    pub mempool: Vec<Tx>,
    pub wallet: Wallet,
    pub datadir: PathBuf,
    pub peers: Vec<Peer>,
    pub next_peer: u64,
    pub stop: bool,
    pub orphans: HashMap<[u8; 32], Vec<Block>>, // keyed by missing parent hash
    pub banned: HashMap<IpAddr, Instant>,
    pub addrs: AddrBook,
    pub allow_local: bool,
    pub listen_port: u16,
    pub nonce: u64,
}

pub type Shared = Arc<Mutex<Node>>;

pub fn frame_bytes(magic: [u8; 4], cmd: &str, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(24 + payload.len());
    f.extend_from_slice(&magic);
    let mut c = [0u8; 12];
    let n = cmd.len().min(12);
    c[..n].copy_from_slice(&cmd.as_bytes()[..n]);
    f.extend_from_slice(&c);
    f.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    f.extend_from_slice(&double_sha256(payload)[..4]);
    f.extend_from_slice(payload);
    f
}

pub fn read_frame(s: &mut TcpStream, magic: [u8; 4]) -> std::io::Result<(String, Vec<u8>)> {
    let bad = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());
    let mut h = [0u8; 24];
    s.read_exact(&mut h)?;
    if h[..4] != magic {
        return Err(bad("wrong magic"));
    }
    let cmd: String = h[4..16].iter().take_while(|&&b| b != 0).map(|&b| b as char).collect();
    let len = u32::from_le_bytes([h[16], h[17], h[18], h[19]]) as usize;
    if len > 2_000_000 {
        return Err(bad("payload too large"));
    }
    let mut p = vec![0u8; len];
    s.read_exact(&mut p)?;
    if double_sha256(&p)[..4] != h[20..24] {
        return Err(bad("bad checksum"));
    }
    Ok((cmd, p))
}

impl Node {
    pub fn open(net: &'static Network, datadir: PathBuf) -> Result<Node, String> {
        std::fs::create_dir_all(&datadir).map_err(|e| e.to_string())?;
        let wallet = Wallet::load(datadir.join("wallet.dat"))?;
        let mut chain = Chain::new(net);
        if let Ok(data) = std::fs::read(datadir.join("blocks.dat")) {
            let mut pos = 0usize;
            while pos + 4 <= data.len() {
                let len = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
                pos += 4;
                if pos + len > data.len() {
                    break; // truncated tail from an interrupted write
                }
                let b = Block::deserialize(&data[pos..pos + len])
                    .ok_or_else(|| format!("corrupt blocks.dat in {} - move it away or use another --datadir", datadir.display()))?;
                let h = chain.height() + 1;
                let _ = chain.accept_block(b).map_err(|e| format!("blocks.dat invalid at height {}: {}", h, e))?;
                pos += len;
            }
        }
        let peers_path = datadir.join("peers.dat");
        Ok(Node {
            chain,
            mempool: vec![],
            wallet,
            datadir,
            peers: vec![],
            next_peer: 1,
            stop: false,
            orphans: HashMap::new(),
            banned: HashMap::new(),
            addrs: AddrBook::load(&peers_path),
            allow_local: false,
            listen_port: 0,
            nonce: OsRng.next_u64(),
        })
    }

    fn append_block(&self, b: &Block) {
        let d = b.serialize();
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(self.datadir.join("blocks.dat")) {
            let mut out = (d.len() as u32).to_le_bytes().to_vec();
            out.extend_from_slice(&d);
            let _ = f.write_all(&out);
        }
    }

    /// Remember the two longest-lived outbound peers; they are redialed first after a restart, so an attacker
    /// who floods the address book still cannot replace every connection of a running node.
    pub fn save_anchors(&self) {
        let mut out: Vec<&Peer> = self.peers.iter().filter(|p| !p.inbound && p.addr.is_some()).collect();
        out.sort_by_key(|p| p.since);
        let lines: String = out.iter().take(2).filter_map(|p| p.addr).map(|a| format!("{}\n", a)).collect();
        if lines.is_empty() {
            return; // keep the previous anchors if we are currently offline
        }
        let path = self.datadir.join("anchors.dat");
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, lines).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }

    fn peer_mut(&mut self, id: u64) -> Option<&mut Peer> {
        self.peers.iter_mut().find(|p| p.id == id)
    }

    fn version_payload(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(14);
        v.extend_from_slice(&self.chain.height().to_le_bytes());
        v.extend_from_slice(&self.listen_port.to_le_bytes());
        v.extend_from_slice(&self.nonce.to_le_bytes());
        v
    }

    fn drop_peer(&mut self, id: u64) {
        self.peers.retain(|p| {
            if p.id == id {
                let _ = p.stream.shutdown(Shutdown::Both);
                false
            } else {
                true
            }
        });
    }

    /// Queue a frame for a peer. Never blocks (no network I/O under the node lock).
    fn send_frame(&mut self, id: u64, f: Vec<u8>) {
        let mut dead = false;
        if let Some(p) = self.peers.iter().find(|p| p.id == id) {
            dead = p.out.try_send(f).is_err();
        }
        if dead {
            self.drop_peer(id);
        }
    }

    pub fn send_to(&mut self, id: u64, cmd: &str, payload: &[u8]) {
        let f = frame_bytes(self.chain.net.magic, cmd, payload);
        self.send_frame(id, f);
    }

    pub fn broadcast(&mut self, cmd: &str, payload: &[u8], except: Option<u64>) {
        let f = frame_bytes(self.chain.net.magic, cmd, payload);
        let mut dead = Vec::new();
        for p in &self.peers {
            if Some(p.id) == except {
                continue;
            }
            if p.out.try_send(f.clone()).is_err() {
                dead.push(p.id);
            }
        }
        for id in dead {
            self.drop_peer(id);
        }
    }

    /// Add misbehaviour points; at BAN_SCORE the peer is disconnected and its IP banned for 24h
    /// (loopback is only disconnected, never banned).
    pub fn misbehave(&mut self, id: u64, points: u32, why: &str) {
        let mut ip = None;
        if let Some(p) = self.peers.iter_mut().find(|p| p.id == id) {
            p.score = p.score.saturating_add(points);
            if p.score >= BAN_SCORE {
                ip = Some(p.ip);
            }
        }
        if let Some(ip) = ip {
            eprintln!("peer {} ({}) dropped: {}", id, ip, why);
            if !ip.is_loopback() {
                self.banned.insert(ip, Instant::now() + Duration::from_secs(BAN_SECS));
                self.peers.retain(|p| {
                    if p.ip == ip {
                        let _ = p.stream.shutdown(Shutdown::Both);
                        false
                    } else {
                        true
                    }
                });
            } else {
                self.drop_peer(id);
            }
        }
    }

    /// Rewrite blocks.dat with the active chain (needed after a reorg).
    fn rewrite_blocks(&self) {
        let mut out = Vec::new();
        for b in self.chain.blocks.iter().skip(1) {
            let d = b.serialize();
            out.extend_from_slice(&(d.len() as u32).to_le_bytes());
            out.extend_from_slice(&d);
        }
        let tmp = self.datadir.join("blocks.dat.tmp");
        if std::fs::write(&tmp, &out).is_ok() {
            let _ = std::fs::rename(&tmp, self.datadir.join("blocks.dat"));
        }
    }

    fn refresh_mempool(&mut self) {
        let h = self.chain.spend_height();
        let mat = self.chain.net.coinbase_maturity();
        let utxo = &self.chain.utxo;
        self.mempool.retain(|t| check_tx(utxo, t, h, mat).is_ok());
    }

    fn after_accept(&mut self, b: &Block, acc: Accept, from: Option<u64>) {
        match acc {
            Accept::Extended => {
                self.append_block(b);
                self.broadcast("block", &b.serialize(), from);
            }
            Accept::Reorg { disconnected } => {
                self.rewrite_blocks();
                self.broadcast("block", &b.serialize(), from);
                self.refresh_mempool();
                // transactions of the abandoned blocks go back to the mempool if still valid
                for blk in disconnected.iter().rev() {
                    for t in blk.txs.iter().skip(1) {
                        let _ = self.submit_tx(t.clone(), None);
                    }
                }
            }
            Accept::Stored => {}
        }
        self.refresh_mempool();
    }

    fn process_orphans(&mut self, start: [u8; 32], from: Option<u64>) {
        let mut work = vec![start];
        while let Some(h) = work.pop() {
            if let Some(children) = self.orphans.remove(&h) {
                for c in children {
                    let ch = c.header.hash();
                    if let Ok(acc) = self.chain.accept_block(c.clone()) {
                        self.after_accept(&c, acc, from);
                        work.push(ch);
                    }
                }
            }
        }
    }

    fn keep_orphan(&mut self, b: Block) {
        let total: usize = self.orphans.values().map(|v| v.len()).sum();
        if total >= 64 {
            // evict one parent's entries instead of wiping the whole pool
            if let Some(k) = self.orphans.keys().next().cloned() {
                self.orphans.remove(&k);
            }
        }
        let list = self.orphans.entry(b.header.prev).or_default();
        if list.len() < 4 {
            list.push(b);
        }
    }

    /// Err("orphan") means the parent is unknown (the block is kept; ask peers for the parent).
    pub fn submit_block(&mut self, b: Block, from: Option<u64>) -> Result<(), String> {
        let hash = b.header.hash();
        match self.chain.accept_block(b.clone()) {
            Ok(acc) => {
                self.after_accept(&b, acc, from);
                self.process_orphans(hash, from);
                Ok(())
            }
            Err(e) => {
                if e == "orphan" {
                    self.keep_orphan(b);
                }
                Err(e)
            }
        }
    }

    pub fn mempool_spent(&self) -> HashSet<OutPoint> {
        self.mempool.iter().flat_map(|t| t.inputs.iter().map(|i| (i.prev, i.index))).collect()
    }

    pub fn submit_tx(&mut self, tx: Tx, from: Option<u64>) -> Result<[u8; 32], String> {
        let id = tx.txid();
        if self.mempool.iter().any(|t| t.txid() == id) {
            return Err("already in mempool".into());
        }
        let spent = self.mempool_spent();
        if tx.inputs.iter().any(|i| spent.contains(&(i.prev, i.index))) {
            return Err("conflicts with a mempool transaction".into());
        }
        let fee = check_tx(&self.chain.utxo, &tx, self.chain.spend_height(), self.chain.net.coinbase_maturity())?;
        let ser = tx.serialize();
        if fee < (ser.len() as u64) * MIN_RELAY_FEE_PER_BYTE {
            return Err("fee too low".into());
        }
        let bytes: usize = self.mempool.iter().map(|t| t.serialize().len()).sum();
        if self.mempool.len() >= MAX_MEMPOOL_TXS || bytes + ser.len() > MAX_MEMPOOL_BYTES {
            return Err("mempool full".into());
        }
        self.mempool.push(tx);
        self.broadcast("tx", &ser, from);
        Ok(id)
    }
}

const BENIGN_BLOCK_ERRORS: [&str; 11] = [
    "orphan",
    "already known",
    "too many side blocks",
    "side branch pool full",
    "timestamp too far in the future",
    "timestamp not after previous block",
    "wrong difficulty bits",
    "prev hash mismatch",
    "input missing or already spent",
    "coinbase not mature",
    "not extending the tip",
];
const BENIGN_TX_ERRORS: [&str; 6] = [
    "already in mempool",
    "conflicts with a mempool transaction",
    "input missing or already spent",
    "coinbase not mature",
    "mempool full",
    "fee too low",
];

fn handle(node: &mut Node, id: u64, cmd: &str, payload: &[u8], tx: Option<Tx>, block: Option<Block>) {
    match cmd {
        "version" => {
            let len = payload.len();
            if len != 4 && len != 6 && len != 14 {
                node.misbehave(id, 20, "bad version message");
                return;
            }
            let ph = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
            let port = if len >= 6 { u16::from_le_bytes([payload[4], payload[5]]) } else { 0 };
            if len == 14 {
                let mut nb = [0u8; 8];
                nb.copy_from_slice(&payload[6..14]);
                if u64::from_le_bytes(nb) == node.nonce {
                    node.drop_peer(id); // we dialed ourselves
                    return;
                }
            }
            let allow_local = node.allow_local;
            let mut ask = false;
            let mut learn: Option<SocketAddr> = None;
            if let Some(p) = node.peer_mut(id) {
                if p.inbound && port != 0 {
                    let a = SocketAddr::new(p.ip, port);
                    p.addr = Some(a);
                    learn = Some(a);
                }
                if !p.inbound && !p.asked_addr {
                    p.asked_addr = true;
                    ask = true;
                }
            }
            if let Some(a) = learn {
                node.addrs.add(a, a.ip(), now_secs(), allow_local);
            }
            if ask {
                node.send_to(id, "getaddr", &[]);
            }
            let next = node.chain.height() + 1;
            if ph > node.chain.height() {
                node.send_to(id, "getblock", &next.to_le_bytes());
            }
        }
        "getaddr" => {
            let first = match node.peer_mut(id) {
                Some(p) if !p.served_addr => {
                    p.served_addr = true;
                    true
                }
                _ => false,
            };
            if first {
                let list = node.addrs.sample(100);
                let payload = encode_addrs(&list);
                node.send_to(id, "addr", &payload);
            }
        }
        "addr" => {
            // only answers to our own getaddr are accepted: unsolicited address floods cannot poison the book
            let (asked, src) = match node.peer_mut(id) {
                Some(p) => {
                    let a = p.asked_addr;
                    p.asked_addr = false;
                    (a, Some(p.ip))
                }
                None => (false, None),
            };
            let src = match src {
                Some(s) if asked => s,
                _ => {
                    node.misbehave(id, 10, "unsolicited addr");
                    return;
                }
            };
            match decode_addrs(payload) {
                Some(list) => {
                    let allow_local = node.allow_local;
                    for (a, ts) in list {
                        node.addrs.add(a, src, ts, allow_local);
                    }
                }
                None => node.misbehave(id, 20, "malformed addr"),
            }
        }
        "ping" => {}
        "getblock" => {
            if payload.len() == 4 {
                let idx = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
                let data = node.chain.blocks.get(idx).map(|b| b.serialize());
                if let Some(d) = data {
                    node.send_to(id, "block", &d);
                }
            }
        }
        "getblk" => {
            if payload.len() == 32 {
                let mut h = [0u8; 32];
                h.copy_from_slice(payload);
                let data = node.chain.block_by_hash(&h).map(|b| b.serialize());
                if let Some(d) = data {
                    node.send_to(id, "block", &d);
                }
            }
        }
        "block" => {
            if let Some(b) = block {
                let prev = b.header.prev;
                match node.submit_block(b, Some(id)) {
                    Ok(()) => {
                        let next = node.chain.height() + 1;
                        node.send_to(id, "getblock", &next.to_le_bytes());
                    }
                    Err(e) => {
                        if e == "orphan" {
                            node.send_to(id, "getblk", &prev);
                        } else if !BENIGN_BLOCK_ERRORS.contains(&e.as_str()) {
                            node.misbehave(id, 100, &format!("invalid block: {}", e));
                        }
                    }
                }
            }
        }
        "tx" => {
            if let Some(t) = tx {
                if let Err(e) = node.submit_tx(t, Some(id)) {
                    if !BENIGN_TX_ERRORS.contains(&e.as_str()) {
                        node.misbehave(id, 10, &format!("invalid tx: {}", e));
                    }
                }
            }
        }
        _ => node.misbehave(id, 5, "unknown command"),
    }
}

pub fn spawn_peer(shared: Shared, stream: TcpStream, inbound: bool, target: Option<SocketAddr>) {
    let ip = match stream.peer_addr() {
        Ok(a) => a.ip(),
        Err(_) => return,
    };
    let mut ws = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let sd = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = ws.set_write_timeout(Some(Duration::from_secs(10)));
    let (otx, orx) = sync_channel::<Vec<u8>>(OUT_QUEUE);
    let (id, magic) = {
        let mut n = shared.lock().unwrap();
        let now = Instant::now();
        n.banned.retain(|_, t| *t > now);
        if !ip.is_loopback() && n.banned.contains_key(&ip) {
            return;
        }
        if n.peers.len() >= MAX_PEERS {
            return;
        }
        if inbound && n.peers.iter().filter(|p| p.inbound).count() >= MAX_INBOUND {
            return;
        }
        if !ip.is_loopback() && n.peers.iter().filter(|p| p.ip == ip).count() >= MAX_PER_IP {
            return;
        }
        let id = n.next_peer;
        n.next_peer += 1;
        n.peers.push(Peer { id, ip, inbound, score: 0, since: Instant::now(), addr: target, asked_addr: false, served_addr: false, out: otx, stream: sd });
        let vp = n.version_payload();
        n.send_to(id, "version", &vp);
        (id, n.chain.net.magic)
    };
    // writer thread: all socket writes happen here, never under the node lock
    thread::spawn(move || {
        for f in orx {
            if ws.write_all(&f).is_err() {
                break;
            }
        }
        let _ = ws.shutdown(Shutdown::Both);
    });
    let mut rs = stream;
    thread::spawn(move || {
        let _ = rs.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
        let mut shaken = false;
        let mut win_start = Instant::now();
        let (mut msgs, mut txs, mut reqs) = (0u32, 0u32, 0u32);
        loop {
            let (cmd, p) = match read_frame(&mut rs, magic) {
                Ok(x) => x,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::InvalidData {
                        shared.lock().unwrap().misbehave(id, BAN_SCORE, "protocol violation");
                    }
                    break;
                }
            };
            if !shaken {
                if cmd != "version" {
                    shared.lock().unwrap().misbehave(id, 50, "no handshake");
                    break;
                }
                shaken = true;
                let _ = rs.set_read_timeout(Some(IDLE_TIMEOUT));
            }
            // per-peer rate limits, kept thread-local so they cost no lock
            if win_start.elapsed() > WINDOW {
                win_start = Instant::now();
                msgs = 0;
                txs = 0;
                reqs = 0;
            }
            msgs += 1;
            let mut over = msgs > MAX_MSG_PER_WINDOW;
            if cmd == "tx" {
                txs += 1;
                over |= txs > MAX_TX_PER_WINDOW;
            }
            if cmd == "getblock" || cmd == "getblk" {
                reqs += 1;
                over |= reqs > MAX_REQ_PER_WINDOW;
            }
            if over {
                shared.lock().unwrap().misbehave(id, 20, "rate limit exceeded");
                continue;
            }
            // expensive stateless validation happens here, OUTSIDE the node lock
            let mut bad = 0u32;
            let mut ptx = None;
            let mut pblock = None;
            match cmd.as_str() {
                "tx" => match Tx::from_bytes(&p) {
                    Some(t) => {
                        if t.is_coinbase() || !sigs_ok(&t) {
                            bad = 20;
                        } else {
                            ptx = Some(t);
                        }
                    }
                    None => bad = 20,
                },
                "block" => match Block::deserialize(&p) {
                    Some(b) => {
                        if !b.header.check_pow() || b.txs.iter().skip(1).any(|t| t.is_coinbase() || !sigs_ok(t)) {
                            bad = 100;
                        } else {
                            pblock = Some(b);
                        }
                    }
                    None => bad = 50,
                },
                _ => {}
            }
            let mut n = shared.lock().unwrap();
            if bad > 0 {
                n.misbehave(id, bad, "invalid message");
            } else {
                handle(&mut n, id, &cmd, &p, ptx, pblock);
            }
            if !n.peers.iter().any(|q| q.id == id) {
                break; // dropped or banned by handle()
            }
        }
        let mut n = shared.lock().unwrap();
        n.peers.retain(|q| q.id != id);
    });
}

pub fn start_p2p(shared: Shared, bind: &str, port: u16) -> Result<(), String> {
    let l = TcpListener::bind((bind, port)).map_err(|e| format!("p2p bind {}:{}: {}", bind, port, e))?;
    shared.lock().unwrap().listen_port = port;
    let sh = shared.clone();
    thread::spawn(move || {
        for s in l.incoming().flatten() {
            spawn_peer(sh.clone(), s, true, None);
        }
    });
    // keepalive + ban expiry
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(120));
        let mut n = shared.lock().unwrap();
        let now = Instant::now();
        n.banned.retain(|_, t| *t > now);
        n.broadcast("ping", &[], None);
        let path = n.datadir.join("peers.dat");
        n.addrs.save(&path);
        n.save_anchors();
    });
    Ok(())
}

/// Dial a specific address (5 s timeout) and start a peer session.
pub fn connect_addr(shared: Shared, addr: SocketAddr) -> Result<(), String> {
    let s = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).map_err(|e| format!("{}: {}", addr, e))?;
    spawn_peer(shared, s, false, Some(addr));
    Ok(())
}

/// Manual connection (`--connect`, `addnode`); the address is also remembered for later.
pub fn connect(shared: Shared, addr: &str) -> Result<(), String> {
    use std::net::ToSocketAddrs;
    let a = addr
        .to_socket_addrs()
        .map_err(|e| format!("{}: {}", addr, e))?
        .next()
        .ok_or("address did not resolve")?;
    connect_addr(shared.clone(), a)?;
    let mut n = shared.lock().unwrap();
    n.addrs.add(a, a.ip(), now_secs(), true);
    n.addrs.mark_good(a, now_secs());
    Ok(())
}

/// Resolve `host:port` (a DNS seed may return many addresses) and add them to the address book.
pub fn add_seed(shared: &Shared, seed: &str) -> Result<usize, String> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<SocketAddr> = seed.to_socket_addrs().map_err(|e| format!("seed {}: {}", seed, e))?.collect();
    let mut n = shared.lock().unwrap();
    let allow = n.allow_local;
    let mut added = 0;
    for a in addrs {
        if n.addrs.add(a, a.ip(), now_secs(), allow) {
            added += 1;
        }
    }
    Ok(added)
}

/// Keeps TARGET_OUTBOUND outbound connections open using the address book (one per network group when possible).
pub fn start_outbound_manager(shared: Shared) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(10));
        let cand = {
            let mut n = shared.lock().unwrap();
            if n.stop {
                return;
            }
            let outbound = n.peers.iter().filter(|p| !p.inbound).count();
            if outbound >= TARGET_OUTBOUND || n.peers.len() >= MAX_PEERS {
                None
            } else {
                let connected: HashSet<SocketAddr> = n.peers.iter().filter_map(|p| p.addr).collect();
                let groups: Vec<Vec<u8>> = n.peers.iter().filter(|p| !p.inbound).map(|p| group(&p.ip)).collect();
                let now = now_secs();
                let c = n.addrs.pick(&connected, &groups, now);
                if let Some(a) = c {
                    n.addrs.mark_attempt(a, now);
                }
                c
            }
        };
        if let Some(addr) = cand {
            if connect_addr(shared.clone(), addr).is_ok() {
                let mut n = shared.lock().unwrap();
                n.addrs.mark_good(addr, now_secs());
            }
        }
    });
}

/// Read and delete anchors.dat (a crash must not pin a bad anchor forever); at most 2 addresses.
pub fn take_anchors(datadir: &std::path::Path) -> Vec<SocketAddr> {
    let path = datadir.join("anchors.dat");
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    text.lines().filter_map(|l| l.trim().parse::<SocketAddr>().ok()).take(2).collect()
}

/// Redial the saved anchors. Returns how many connected.
pub fn connect_anchors(shared: &Shared) -> usize {
    let dir = shared.lock().unwrap().datadir.clone();
    let mut ok = 0;
    for a in take_anchors(&dir) {
        if connect_addr(shared.clone(), a).is_ok() {
            ok += 1;
            let mut n = shared.lock().unwrap();
            n.addrs.add(a, a.ip(), now_secs(), true);
            n.addrs.mark_good(a, now_secs());
        }
    }
    ok
}

/// Total hashes tried (approximate) and hashes/second averaged over the last 5 s.
pub static HASHES: AtomicU64 = AtomicU64::new(0);
pub static RATE: AtomicU64 = AtomicU64::new(0);
pub static MINING_THREADS: AtomicUsize = AtomicUsize::new(1);
static SAMPLER: Once = Once::new();

fn start_sampler() {
    SAMPLER.call_once(|| {
        thread::spawn(|| {
            let mut last = HASHES.load(Ordering::Relaxed);
            loop {
                thread::sleep(Duration::from_secs(5));
                let now = HASHES.load(Ordering::Relaxed);
                RATE.store(now.saturating_sub(last) / 5, Ordering::Relaxed);
                last = now;
            }
        });
    });
}

fn worker(mut h: Header, start: u32, stop: &AtomicBool, found: &Mutex<Option<Header>>) {
    h.nonce = start;
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let mut done = false;
        for _ in 0..20_000 {
            if h.check_pow() {
                done = true;
                break;
            }
            let (n, overflow) = h.nonce.overflowing_add(1);
            h.nonce = n;
            if overflow {
                h.time += 1;
            }
        }
        HASHES.fetch_add(20_000, Ordering::Relaxed);
        if done {
            let mut f = found.lock().unwrap();
            if f.is_none() {
                *f = Some(h.clone());
            }
            stop.store(true, Ordering::Relaxed);
            return;
        }
    }
}

/// Mine one block to `pkh` with MINING_THREADS worker threads, without holding the node lock while hashing.
/// Returns the block hash, or None if `keep_going` says stop.
pub fn mine_one(shared: &Shared, pkh: [u8; 20], keep_going: &dyn Fn() -> bool) -> Option<String> {
    start_sampler();
    loop {
        let tpl = {
            let n = shared.lock().unwrap();
            let txs = n.mempool.clone();
            let r = n.chain.build_template(pkh.to_vec(), txs).or_else(|_| n.chain.build_template(pkh.to_vec(), vec![])).ok();
            r
        };
        let block = tpl?;
        let threads = MINING_THREADS.load(Ordering::Relaxed).max(1);
        let stop = AtomicBool::new(false);
        let found: Mutex<Option<Header>> = Mutex::new(None);
        let mut quit = false;
        let prev = block.header.prev;
        thread::scope(|sc| {
            for t in 0..threads {
                let h = block.header.clone();
                let stop_ref = &stop;
                let found_ref = &found;
                let start = (((u32::MAX as u64) / (threads as u64)) * (t as u64)) as u32;
                sc.spawn(move || worker(h, start, stop_ref, found_ref));
            }
            let mut i = 0u32;
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
                i += 1;
                if i % 100 == 0 {
                    let moved = shared.lock().unwrap().chain.tip().header.hash() != prev;
                    if moved {
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                    if !keep_going() {
                        quit = true;
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
        });
        let hdr = found.into_inner().unwrap();
        if let Some(hdr) = hdr {
            let mut b = block;
            b.header = hdr;
            let h = b.header.hash_hex();
            let hh = b.header.hash();
            let mut n = shared.lock().unwrap();
            if n.submit_block(b, None).is_ok() && n.chain.tip().header.hash() == hh {
                return Some(h);
            }
            continue; // tip moved or block not on the active chain; rebuild
        }
        if quit {
            return None;
        }
    }
}
