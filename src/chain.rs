use crate::address::hash160;
use crate::block::*;
use crate::ecdsa;
use crate::params::*;
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

pub type OutPoint = ([u8; 32], u32);

#[derive(Clone, Debug)]
pub struct Utxo {
    pub value: u64,
    pub pkh: Vec<u8>,
    pub height: u32,
    pub coinbase: bool,
}

#[derive(Default, Clone)]
struct Undo {
    spent: Vec<(OutPoint, Utxo)>,
    created: Vec<OutPoint>,
    minted: u64,
}

struct Side {
    size: usize,
    block: Block,
    height: u32,
    work: u128,
}

#[derive(Debug)]
pub enum Accept {
    /// Block extended the active chain.
    Extended,
    /// Block stored on a side branch with less or equal work.
    Stored,
    /// Active chain switched to a heavier branch; the old blocks (tip first) are returned.
    Reorg { disconnected: Vec<Block> },
}

const MAX_SIDE_BLOCKS: usize = 10_000;
const MAX_SIDE_BYTES: usize = 64_000_000;

pub struct Chain {
    pub net: &'static Network,
    pub blocks: Vec<Block>,
    /// Coins created by block rewards so far (never exceeds MAX_MONEY).
    pub issued: u64,
    pub utxo: HashMap<OutPoint, Utxo>,
    work: Vec<u128>,                // cumulative work, parallel to blocks
    undos: Vec<Undo>,               // parallel to blocks
    active: HashMap<[u8; 32], u32>, // hash -> height for active blocks
    side: HashMap<[u8; 32], Side>,
}

/// Validate a non-coinbase transaction against `utxo`; returns its fee.
static SIG_CACHE: OnceLock<Mutex<HashSet<[u8; 32]>>> = OnceLock::new();

/// Verify every input signature of `tx`. This depends only on the transaction itself, so callers can do the
/// expensive work OUTSIDE the node lock; results are cached by the hash of the full serialization.
pub fn sigs_ok(tx: &Tx) -> bool {
    let key = crate::sha256::double_sha256(&tx.serialize());
    let cache = SIG_CACHE.get_or_init(|| Mutex::new(HashSet::new()));
    let known = cache.lock().unwrap().contains(&key);
    if known {
        return true;
    }
    let msg = tx.sighash();
    for i in &tx.inputs {
        if !ecdsa::verify(&i.pubkey, &msg, &i.sig) {
            return false;
        }
    }
    let mut c = cache.lock().unwrap();
    if c.len() >= 50_000 {
        c.clear();
    }
    c.insert(key);
    true
}

pub fn check_tx(utxo: &HashMap<OutPoint, Utxo>, tx: &Tx, spend_height: u32, maturity: u32) -> Result<u64, String> {
    if tx.is_coinbase() {
        return Err("unexpected coinbase".into());
    }
    if tx.inputs.is_empty() || tx.outputs.is_empty() {
        return Err("empty inputs or outputs".into());
    }
    let mut seen: Vec<OutPoint> = Vec::new();
    let mut total_in: u64 = 0;
    for i in &tx.inputs {
        let key = (i.prev, i.index);
        if seen.contains(&key) {
            return Err("duplicate input".into());
        }
        seen.push(key);
        let u = utxo.get(&key).ok_or("input missing or already spent")?;
        if u.coinbase && spend_height < u.height + maturity {
            return Err("coinbase not mature".into());
        }
        if i.pubkey.len() != 64 || hash160(&i.pubkey)[..] != u.pkh[..] {
            return Err("pubkey does not match output".into());
        }
        total_in = total_in.checked_add(u.value).ok_or("overflow")?;
    }
    if !sigs_ok(tx) {
        return Err("bad signature".into());
    }
    let mut total_out: u64 = 0;
    for o in &tx.outputs {
        if o.value == 0 || o.value > MAX_MONEY || o.script.len() != 20 {
            return Err("bad output".into());
        }
        total_out = total_out.checked_add(o.value).ok_or("overflow")?;
    }
    if total_out > total_in {
        return Err("outputs exceed inputs".into());
    }
    Ok(total_in - total_out)
}

impl Chain {
    pub fn new(net: &'static Network) -> Chain {
        let g = &net.genesis;
        let header = header_from_display(None, g.merkle, g.time, g.bits, g.nonce);
        let mut active = HashMap::new();
        active.insert(header.hash(), 0u32);
        let w = bits_work(header.bits);
        Chain {
            net,
            blocks: vec![Block { header, txs: vec![] }],
            issued: 0,
            utxo: HashMap::new(),
            work: vec![w],
            undos: vec![Undo::default()],
            active,
            side: HashMap::new(),
        }
    }

    pub fn height(&self) -> u32 {
        self.blocks.len() as u32 - 1
    }

    pub fn tip(&self) -> &Block {
        self.blocks.last().unwrap()
    }

    fn pow_limit(&self) -> [u8; 32] {
        bits_to_target(self.net.genesis.bits).unwrap()
    }

    /// Bits required for the next block (retarget every RETARGET_INTERVAL blocks).
    pub fn next_bits(&self) -> u32 {
        let height = self.height() + 1;
        let prev = &self.tip().header;
        if !self.net.retargets() || height % RETARGET_INTERVAL != 0 {
            return prev.bits;
        }
        let first = &self.blocks[(height - RETARGET_INTERVAL) as usize].header;
        let expected = (RETARGET_INTERVAL as u64) * (TARGET_SPACING as u64);
        let mut actual = prev.time as i64 - first.time as i64;
        actual = actual.max((expected / 4) as i64).min((expected * 4) as i64);
        let limit = self.pow_limit();
        let old = bits_to_target(prev.bits).unwrap_or(limit);
        let q = div_small(&mul_small(&old, actual as u64), expected);
        let mut t = [0u8; 32];
        if q[..8].iter().any(|&b| b != 0) {
            t = limit;
        } else {
            t.copy_from_slice(&q[8..]);
        }
        if t > limit {
            t = limit;
        }
        target_to_bits(&t)
    }

    /// Latest acceptable block timestamp on public networks: the wall clock plus 2 hours (the standard rule).
    /// Because genesis lies in the future before launch, honest software cannot mine or accept blocks early.
    fn max_future_time(&self) -> u32 {
        crate::addrman::now_secs().saturating_add(7200)
    }

    /// Seconds until this node will accept the next block, or None if it is open now (public networks only).
    pub fn mining_opens_in(&self) -> Option<u64> {
        if !self.net.retargets() {
            return None;
        }
        let earliest = (self.tip().header.time as u64) + 1;
        let allowed = self.max_future_time() as u64;
        if earliest > allowed {
            Some(earliest - allowed)
        } else {
            None
        }
    }

    pub fn spend_height(&self) -> u32 {
        self.height() + 1
    }

    /// Build a block paying `payout` (20-byte hash). `txs` must be independent of each other.
    pub fn build_template(&self, payout: Vec<u8>, txs: Vec<Tx>) -> Result<Block, String> {
        let height = self.spend_height();
        let mut fees: u64 = 0;
        for t in &txs {
            fees = fees
                .checked_add(check_tx(&self.utxo, t, height, self.net.coinbase_maturity())?)
                .ok_or("overflow")?;
        }
        if let Some(s) = self.mining_opens_in() {
            return Err(format!("network not open yet: the next block would be dated more than 2 hours in the future (opens in {} s)", s));
        }
        let time = crate::addrman::now_secs().max(self.tip().header.time + 1);
        let mut all = vec![Tx::coinbase(height, block_subsidy(height) + fees, payout)];
        all.extend(txs);
        let mut block = Block {
            header: Header { version: 1, prev: self.tip().header.hash(), merkle: [0u8; 32], time, bits: self.next_bits(), nonce: 0 },
            txs: all,
        };
        block.header.merkle = block.compute_merkle();
        Ok(block)
    }

    fn revert(&mut self, undo: Undo) {
        for (k, u) in undo.spent.into_iter().rev() {
            self.utxo.insert(k, u);
        }
        for k in undo.created {
            self.utxo.remove(&k);
        }
    }

    /// Apply all transactions; returns newly created coins. Caller reverts on Err.
    fn apply_block(&mut self, block: &Block, height: u32, undo: &mut Undo) -> Result<u64, String> {
        let maturity = self.net.coinbase_maturity();
        let mut fees: u64 = 0;
        for tx in block.txs.iter().skip(1) {
            let fee = check_tx(&self.utxo, tx, height, maturity)?;
            fees = fees.checked_add(fee).ok_or("overflow")?;
            let id = tx.txid();
            for i in &tx.inputs {
                let k = (i.prev, i.index);
                let u = self.utxo.remove(&k).ok_or("input vanished")?;
                undo.spent.push((k, u));
            }
            for (n, o) in tx.outputs.iter().enumerate() {
                let k = (id, n as u32);
                if self.utxo.contains_key(&k) {
                    return Err("duplicate outpoint".into());
                }
                self.utxo.insert(k, Utxo { value: o.value, pkh: o.script.clone(), height, coinbase: false });
                undo.created.push(k);
            }
        }
        let cb = &block.txs[0];
        // The coinbase must commit to its height (makes every coinbase txid unique) and carry no signature data.
        if cb.data != height.to_le_bytes() || !cb.inputs[0].pubkey.is_empty() || !cb.inputs[0].sig.is_empty() {
            return Err("coinbase must commit to block height".into());
        }
        let mut cb_value: u64 = 0;
        for o in &cb.outputs {
            if o.value == 0 || o.value > MAX_MONEY || o.script.len() != 20 {
                return Err("bad coinbase output".into());
            }
            cb_value = cb_value.checked_add(o.value).ok_or("overflow")?;
        }
        let allowed = block_subsidy(height).checked_add(fees).ok_or("overflow")?;
        if cb_value > allowed {
            return Err("coinbase exceeds subsidy + fees".into());
        }
        let minted = cb_value.saturating_sub(fees);
        let new_issued = self.issued.checked_add(minted).ok_or("overflow")?;
        if new_issued > MAX_MONEY {
            return Err("MAX_MONEY (12,000,000) exceeded".into());
        }
        let id = cb.txid();
        for (n, o) in cb.outputs.iter().enumerate() {
            let k = (id, n as u32);
            if self.utxo.contains_key(&k) {
                return Err("duplicate outpoint".into());
            }
            self.utxo.insert(k, Utxo { value: o.value, pkh: o.script.clone(), height, coinbase: true });
            undo.created.push(k);
        }
        Ok(minted)
    }

    fn tip_work(&self) -> u128 {
        *self.work.last().unwrap()
    }

    pub fn block_by_hash(&self, h: &[u8; 32]) -> Option<&Block> {
        if let Some(&ht) = self.active.get(h) {
            return self.blocks.get(ht as usize);
        }
        self.side.get(h).map(|s| &s.block)
    }

    fn check_standalone(&self, block: &Block) -> Result<(), String> {
        // reject blocks whose target is easier than the network limit (cheap spam otherwise)
        match bits_to_target(block.header.bits) {
            Some(t) if t <= self.pow_limit() => {}
            _ => return Err("difficulty target above network limit".into()),
        }
        if !block.header.check_pow() {
            return Err("proof of work failed".into());
        }
        if block.txs.is_empty() || !block.txs[0].is_coinbase() {
            return Err("first tx must be coinbase".into());
        }
        if block.txs.iter().skip(1).any(|t| t.is_coinbase()) {
            return Err("multiple coinbase txs".into());
        }
        if block.serialize().len() > MAX_BLOCK_SIZE {
            return Err("block too large".into());
        }
        if block.compute_merkle() != block.header.merkle {
            return Err("bad merkle root".into());
        }
        Ok(())
    }

    /// Fully validate `block` on top of the current tip and connect it.
    fn connect(&mut self, block: Block) -> Result<(), String> {
        let height = self.spend_height();
        if block.header.prev != self.tip().header.hash() {
            return Err("prev hash mismatch".into());
        }
        if block.header.time <= self.tip().header.time {
            return Err("timestamp not after previous block".into());
        }
        if self.net.retargets() && block.header.time > self.max_future_time() {
            return Err("timestamp too far in the future".into());
        }
        if block.header.bits != self.next_bits() {
            return Err("wrong difficulty bits".into());
        }
        self.check_standalone(&block)?;
        let mut undo = Undo::default();
        match self.apply_block(&block, height, &mut undo) {
            Ok(minted) => {
                undo.minted = minted;
                self.issued += minted;
                let w = self.tip_work().saturating_add(bits_work(block.header.bits));
                self.work.push(w);
                self.undos.push(undo);
                self.active.insert(block.header.hash(), height);
                self.blocks.push(block);
                Ok(())
            }
            Err(e) => {
                self.revert(undo);
                Err(e)
            }
        }
    }

    fn disconnect_tip(&mut self) -> (Block, u32, u128) {
        let height = self.height();
        let block = self.blocks.pop().unwrap();
        let work = self.work.pop().unwrap();
        let undo = self.undos.pop().unwrap();
        self.active.remove(&block.header.hash());
        self.issued = self.issued.saturating_sub(undo.minted);
        self.revert(undo);
        (block, height, work)
    }

    /// Accept a block. Err("orphan") means its parent is unknown.
    pub fn accept_block(&mut self, block: Block) -> Result<Accept, String> {
        let hash = block.header.hash();
        if self.active.contains_key(&hash) || self.side.contains_key(&hash) {
            return Err("already known".into());
        }
        self.check_standalone(&block)?;
        if block.header.prev == self.tip().header.hash() {
            self.connect(block)?;
            return Ok(Accept::Extended);
        }
        let (pheight, pwork) = if let Some(&h) = self.active.get(&block.header.prev) {
            (h, self.work[h as usize])
        } else if let Some(s) = self.side.get(&block.header.prev) {
            (s.height, s.work)
        } else {
            return Err("orphan".into());
        };
        if self.side.len() >= MAX_SIDE_BLOCKS {
            return Err("too many side blocks".into());
        }
        let size = block.serialize().len();
        let side_bytes: usize = self.side.values().map(|s| s.size).sum();
        if side_bytes + size > MAX_SIDE_BYTES {
            return Err("side branch pool full".into());
        }
        let work = pwork.saturating_add(bits_work(block.header.bits));
        self.side.insert(hash, Side { size, block, height: pheight + 1, work });
        if work <= self.tip_work() {
            return Ok(Accept::Stored);
        }
        self.reorg_to(hash)
    }

    fn reorg_to(&mut self, new_tip: [u8; 32]) -> Result<Accept, String> {
        let mut branch: Vec<[u8; 32]> = Vec::new();
        let mut cur = new_tip;
        let fork_height = loop {
            if let Some(&h) = self.active.get(&cur) {
                break h;
            }
            let prev = self.side.get(&cur).ok_or("broken side branch")?.block.header.prev;
            branch.push(cur);
            cur = prev;
        };
        branch.reverse(); // oldest first
        let mut old: Vec<(Block, u32, u128)> = Vec::new();
        while self.height() > fork_height {
            old.push(self.disconnect_tip());
        }
        let mut connected = 0usize;
        let mut failure: Option<(usize, String)> = None;
        for (i, h) in branch.iter().enumerate() {
            let blk = self.side.get(h).ok_or("side block missing")?.block.clone();
            match self.connect(blk) {
                Ok(()) => connected += 1,
                Err(e) => {
                    failure = Some((i, e));
                    break;
                }
            }
        }
        if let Some((i, e)) = failure {
            for _ in 0..connected {
                self.disconnect_tip();
            }
            for h in &branch[i..] {
                self.side.remove(h); // invalid block and its descendants
            }
            for (b, _, _) in old.into_iter().rev() {
                self.connect(b).map_err(|e| format!("fatal: cannot restore old chain: {}", e))?;
            }
            return Err(format!("invalid block in heavier fork: {}", e));
        }
        for h in &branch {
            self.side.remove(h);
        }
        let mut disconnected = Vec::new();
        for (b, height, work) in old {
            disconnected.push(b.clone());
            let size = b.serialize().len();
            self.side.insert(b.header.hash(), Side { size, block: b, height, work });
        }
        Ok(Accept::Reorg { disconnected })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_genesis_hashes_match_spec() {
        for n in ALL.iter() {
            let c = Chain::new(n);
            assert_eq!(c.tip().header.hash_hex(), n.genesis.hash, "{}", n.name);
            assert!(c.tip().header.check_pow(), "{}", n.name);
        }
    }

    #[test]
    fn regtest_mining_and_cap() {
        let mut c = Chain::new(&REGTEST);
        for _ in 0..5 {
            let mut b = c.build_template(vec![0u8; 20], vec![]).unwrap();
            b.header.mine();
            c.accept_block(b).unwrap();
        }
        assert_eq!(c.height(), 5);
        assert_eq!(c.issued, 5 * INITIAL_SUBSIDY);
        let mut bad = c.build_template(vec![0u8; 20], vec![]).unwrap();
        bad.txs[0].outputs[0].value += 1;
        bad.header.merkle = bad.compute_merkle();
        bad.header.mine();
        assert!(c.accept_block(bad).is_err());
        assert_eq!(c.height(), 5);
    }

    fn test_net(genesis_time: u32) -> &'static Network {
        let g = &REGTEST.genesis;
        // name != regtest/signet, so it follows the public-network rules (retargeting + future-time cap)
        Box::leak(Box::new(Network {
            name: "testretarget",
            p2p_port: 1,
            rpc_port: 2,
            magic: REGTEST.magic,
            bech32_hrp: "rx",
            pubkey_prefix: REGTEST.pubkey_prefix,
            script_prefix: 0,
            secret_prefix: 0,
            ext_public: [0; 4],
            ext_secret: [0; 4],
            genesis: Genesis { time: genesis_time, bits: g.bits, nonce: g.nonce, merkle: g.merkle, hash: g.hash },
        }))
    }

    fn forge(c: &Chain, time: u32) -> Block {
        let h = c.spend_height();
        let mut b = Block {
            header: Header { version: 1, prev: c.tip().header.hash(), merkle: [0u8; 32], time, bits: c.next_bits(), nonce: 0 },
            txs: vec![Tx::coinbase(h, block_subsidy(h), vec![0u8; 20])],
        };
        b.header.merkle = b.compute_merkle();
        b.header.mine();
        b
    }

    #[test]
    fn early_launch_is_blocked() {
        let now = crate::addrman::now_secs();
        let mut c = Chain::new(test_net(now + 100_000)); // genesis (launch) is still in the future
        let opens = c.mining_opens_in().expect("must be closed before launch");
        assert!(opens > 90_000 && opens < 100_000);
        assert!(c.build_template(vec![0u8; 20], vec![]).is_err());
        let early = forge(&c, c.tip().header.time + 1);
        assert!(c.accept_block(early).unwrap_err().contains("future"));
        assert_eq!(c.height(), 0);
    }

    #[test]
    fn future_window_is_two_hours() {
        let now = crate::addrman::now_secs();
        let mut ok = Chain::new(test_net(now - 1000));
        assert!(ok.mining_opens_in().is_none());
        let b = ok.build_template(vec![0u8; 20], vec![]).unwrap();
        let mut b = b;
        b.header.mine();
        ok.accept_block(b).unwrap();
        let within = forge(&ok, now + 3000);
        ok.accept_block(within).unwrap();
        let mut bad = Chain::new(test_net(now - 1000));
        let beyond = forge(&bad, now + 9000);
        assert!(bad.accept_block(beyond).unwrap_err().contains("future"));
        // regtest keeps working without the wall-clock rule
        let mut r = Chain::new(&REGTEST);
        let far = forge(&r, r.tip().header.time + 1_000_000);
        r.accept_block(far).unwrap();
    }

    #[test]
    fn coinbase_must_commit_to_height() {
        let mut c = Chain::new(&REGTEST);
        let mut b = c.build_template(vec![0u8; 20], vec![]).unwrap();
        b.txs[0].data = vec![9, 9, 9, 9];
        b.header.merkle = b.compute_merkle();
        b.header.mine();
        assert!(c.accept_block(b).is_err());
        assert_eq!(c.height(), 0);
    }

    fn mine_on(c: &Chain, pkh: u8) -> Block {
        let mut b = c.build_template(vec![pkh; 20], vec![]).unwrap();
        b.header.mine();
        b
    }

    #[test]
    fn reorg_to_heavier_chain() {
        let mut a = Chain::new(&REGTEST);
        let mut b = Chain::new(&REGTEST);
        let c1 = mine_on(&a, 1);
        a.accept_block(c1.clone()).unwrap();
        b.accept_block(c1).unwrap();
        let a2 = mine_on(&a, 2);
        a.accept_block(a2).unwrap();
        let b2 = mine_on(&b, 3);
        b.accept_block(b2.clone()).unwrap();
        let b3 = mine_on(&b, 3);
        b.accept_block(b3.clone()).unwrap();
        assert_ne!(a.tip().header.hash(), b.tip().header.hash());
        // orphan: parent unknown
        assert_eq!(a.accept_block(b3.clone()).unwrap_err(), "orphan");
        assert!(matches!(a.accept_block(b2).unwrap(), Accept::Stored));
        assert!(matches!(a.accept_block(b3).unwrap(), Accept::Reorg { .. }));
        assert_eq!(a.tip().header.hash(), b.tip().header.hash());
        assert_eq!(a.issued, b.issued);
        assert_eq!(a.utxo.len(), b.utxo.len());
        assert_eq!(a.height(), 3);
    }

    #[test]
    fn invalid_heavier_fork_is_rejected_and_old_chain_restored() {
        let mut a = Chain::new(&REGTEST);
        let mut b = Chain::new(&REGTEST);
        let c1 = mine_on(&a, 1);
        a.accept_block(c1.clone()).unwrap();
        b.accept_block(c1).unwrap();
        let a2 = mine_on(&a, 2);
        a.accept_block(a2).unwrap();
        let tip_before = a.tip().header.hash();
        let issued_before = a.issued;
        let b2 = mine_on(&b, 3);
        b.accept_block(b2.clone()).unwrap();
        let mut bad = b.build_template(vec![3u8; 20], vec![]).unwrap();
        bad.txs[0].outputs[0].value += 1; // coinbase above subsidy
        bad.header.merkle = bad.compute_merkle();
        bad.header.mine();
        a.accept_block(b2).unwrap();
        assert!(a.accept_block(bad).is_err());
        assert_eq!(a.tip().header.hash(), tip_before);
        assert_eq!(a.issued, issued_before);
        assert_eq!(a.height(), 2);
    }
}
