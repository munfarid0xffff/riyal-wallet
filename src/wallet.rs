//! Wallet with optional passphrase encryption.
//! File formats:
//!  * legacy plaintext: one hex secret per line (still readable; encrypt it with `encryptwallet`)
//!  * encrypted: "RYLWAL01" | salt(16) | nonce(12) | n(u32 LE) | n * pubkey(64) | AEAD(n * secret(32)) + tag(16)
//!    Key = Argon2id(passphrase, salt); cipher = ChaCha20-Poly1305; the whole header is authenticated (AAD).
//! Public keys stay readable so addresses and balances work while the wallet is locked.
use crate::address::hash160;
use crate::block::{Tx, TxIn, TxOut};
use crate::chain::{Chain, OutPoint};
use crate::ecdsa;
use crate::hex;
use crate::params::*;
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as CKey, Nonce};
use k256::elliptic_curve::rand_core::{OsRng, RngCore};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"RYLWAL01";

pub struct Key {
    pub secret: [u8; 32], // all zero while the wallet is locked
    pub pubkey: [u8; 64],
    pub pkh: [u8; 20],
}

impl Drop for Key {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

struct Enc {
    salt: [u8; 16],
    key: Option<[u8; 32]>, // derived key, present only while unlocked
}

impl Drop for Enc {
    fn drop(&mut self) {
        if let Some(k) = self.key.as_mut() {
            k.zeroize();
        }
    }
}

pub struct Wallet {
    pub keys: Vec<Key>,
    path: Option<PathBuf>,
    enc: Option<Enc>,
    unlock_until: Option<Instant>,
}

fn key_from_secret(secret: [u8; 32]) -> Option<Key> {
    let pubkey = ecdsa::pubkey(&secret)?;
    let pkh = hash160(&pubkey);
    Some(Key { secret, pubkey, pkh })
}

/// Atomic private write: temp file (mode 0600) -> fsync -> rename over the target.
pub fn write_private_bytes(path: &PathBuf, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(&tmp)?;
    f.write_all(content)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

pub fn write_private(path: &PathBuf, content: &str) -> std::io::Result<()> {
    write_private_bytes(path, content.as_bytes())
}

struct Parsed {
    salt: [u8; 16],
    nonce: [u8; 12],
    pubs: Vec<[u8; 64]>,
    hdr_len: usize,
}

fn parse_enc(data: &[u8]) -> Result<Parsed, String> {
    if data.len() < 40 || data[..8] != MAGIC[..] {
        return Err("not an encrypted wallet".into());
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&data[8..24]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&data[24..36]);
    let n = u32::from_le_bytes([data[36], data[37], data[38], data[39]]) as usize;
    if n > 100_000 {
        return Err("corrupt wallet file".into());
    }
    let hdr_len = 40 + n * 64;
    if data.len() != hdr_len + n * 32 + 16 {
        return Err("corrupt wallet file".into());
    }
    let mut pubs = Vec::with_capacity(n);
    for i in 0..n {
        let mut p = [0u8; 64];
        p.copy_from_slice(&data[40 + 64 * i..40 + 64 * (i + 1)]);
        pubs.push(p);
    }
    Ok(Parsed { salt, nonce, pubs, hdr_len })
}

fn derive(pass: &str, salt: &[u8; 16]) -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    Argon2::default().hash_password_into(pass.as_bytes(), salt, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

impl Wallet {
    pub fn new(path: Option<PathBuf>) -> Wallet {
        Wallet { keys: vec![], path, enc: None, unlock_until: None }
    }

    /// Loads the wallet. A damaged wallet file is an ERROR (never silently replaced by an empty wallet).
    pub fn load(path: PathBuf) -> Result<Wallet, String> {
        let mut w = Wallet::new(Some(path.clone()));
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(w),
            Err(e) => return Err(format!("cannot read wallet {}: {}", path.display(), e)),
        };
        if data.starts_with(MAGIC) {
            let p = parse_enc(&data)?;
            for pk in p.pubs.iter() {
                w.keys.push(Key { secret: [0u8; 32], pubkey: *pk, pkh: hash160(pk) });
            }
            w.enc = Some(Enc { salt: p.salt, key: None });
            return Ok(w);
        }
        let s = String::from_utf8(data).map_err(|_| "wallet.dat is neither encrypted nor plain text".to_string())?;
        for line in s.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let v = hex::decode(line).ok_or("corrupt wallet line")?;
            if v.len() != 32 {
                return Err("corrupt wallet line".into());
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            let k = key_from_secret(a).ok_or("invalid key in wallet")?;
            a.zeroize();
            w.keys.push(k);
        }
        Ok(w)
    }

    pub fn is_encrypted(&self) -> bool {
        self.enc.is_some()
    }

    pub fn locked(&self) -> bool {
        match &self.enc {
            Some(e) => e.key.is_none(),
            None => false,
        }
    }

    fn expired(&self) -> bool {
        match self.unlock_until {
            Some(t) => Instant::now() >= t,
            None => false,
        }
    }

    /// Re-locks the wallet when the unlock timeout has passed.
    pub fn tick(&mut self) {
        if self.expired() {
            self.lock();
        }
    }

    pub fn lock(&mut self) {
        for k in self.keys.iter_mut() {
            k.secret.zeroize();
        }
        if let Some(e) = self.enc.as_mut() {
            if let Some(k) = e.key.as_mut() {
                k.zeroize();
            }
            e.key = None;
        }
        self.unlock_until = None;
    }

    fn seal(&self, key: &[u8; 32], salt: &[u8; 16]) -> Result<Vec<u8>, String> {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let mut hdr = Vec::new();
        hdr.extend_from_slice(MAGIC);
        hdr.extend_from_slice(salt);
        hdr.extend_from_slice(&nonce);
        hdr.extend_from_slice(&(self.keys.len() as u32).to_le_bytes());
        for k in &self.keys {
            hdr.extend_from_slice(&k.pubkey);
        }
        let mut plain = Vec::with_capacity(self.keys.len() * 32);
        for k in &self.keys {
            plain.extend_from_slice(&k.secret);
        }
        let cipher = ChaCha20Poly1305::new(CKey::from_slice(key));
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: &plain, aad: &hdr })
            .map_err(|_| "encryption failed".to_string());
        plain.zeroize();
        let mut out = hdr;
        out.extend_from_slice(&ct?);
        Ok(out)
    }

    fn save(&self) -> Result<(), String> {
        let p = match &self.path {
            Some(p) => p,
            None => return Ok(()),
        };
        match &self.enc {
            None => {
                let s: String = self.keys.iter().map(|k| format!("{}\n", hex::encode(&k.secret))).collect();
                write_private(p, &s).map_err(|e| e.to_string())
            }
            Some(e) => {
                let key = e.key.ok_or("wallet is locked")?;
                let bytes = self.seal(&key, &e.salt)?;
                write_private_bytes(p, &bytes).map_err(|e| e.to_string())
            }
        }
    }

    /// Encrypt a plaintext wallet with `pass` (min 8 chars). The wallet ends up locked.
    pub fn encrypt(&mut self, pass: &str) -> Result<(), String> {
        if self.enc.is_some() {
            return Err("wallet is already encrypted".into());
        }
        if pass.chars().count() < 8 {
            return Err("passphrase must be at least 8 characters".into());
        }
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let key = derive(pass, &salt)?;
        self.enc = Some(Enc { salt, key: Some(key) });
        if let Err(e) = self.save() {
            self.enc = None;
            return Err(e);
        }
        self.lock();
        Ok(())
    }

    /// Decrypt keys into memory for `secs` seconds (max one day).
    pub fn unlock(&mut self, pass: &str, secs: u64) -> Result<(), String> {
        let path = self.path.clone().ok_or("wallet has no file")?;
        let salt = match &self.enc {
            Some(e) => e.salt,
            None => return Err("wallet is not encrypted".into()),
        };
        let data = std::fs::read(&path).map_err(|e| e.to_string())?;
        let p = parse_enc(&data)?;
        if p.pubs.len() != self.keys.len() {
            return Err("wallet file changed on disk; restart the node".into());
        }
        let mut key = derive(pass, &salt)?;
        let cipher = ChaCha20Poly1305::new(CKey::from_slice(&key));
        let res = cipher.decrypt(
            Nonce::from_slice(&p.nonce),
            Payload { msg: &data[p.hdr_len..], aad: &data[..p.hdr_len] },
        );
        let mut plain = match res {
            Ok(v) => v,
            Err(_) => {
                key.zeroize();
                std::thread::sleep(Duration::from_secs(1)); // slows down online guessing
                return Err("wrong passphrase".into());
            }
        };
        if plain.len() != self.keys.len() * 32 {
            key.zeroize();
            plain.zeroize();
            return Err("corrupt wallet file".into());
        }
        for (i, k) in self.keys.iter_mut().enumerate() {
            k.secret.copy_from_slice(&plain[i * 32..(i + 1) * 32]);
        }
        plain.zeroize();
        self.enc = Some(Enc { salt, key: Some(key) });
        self.unlock_until = Some(Instant::now() + Duration::from_secs(secs.clamp(1, 86_400)));
        Ok(())
    }

    pub fn new_key(&mut self) -> Result<[u8; 20], String> {
        self.tick();
        if self.locked() {
            return Err("wallet is locked: unlock it with walletpassphrase".into());
        }
        let mut secret = ecdsa::random_secret().ok_or("cannot get randomness")?;
        let k = key_from_secret(secret);
        secret.zeroize();
        let k = k.ok_or("bad key")?;
        let pkh = k.pkh;
        self.keys.push(k);
        if let Err(e) = self.save() {
            self.keys.pop(); // never hand out an address whose key could not be stored
            return Err(e);
        }
        Ok(pkh)
    }

    fn key_for(&self, pkh: &[u8]) -> Option<&Key> {
        self.keys.iter().find(|k| k.pkh[..] == *pkh)
    }

    fn spendable(&self, chain: &Chain, exclude: &HashSet<OutPoint>) -> Vec<(OutPoint, u64)> {
        let sh = chain.spend_height();
        let mat = chain.net.coinbase_maturity();
        let mut v = Vec::new();
        for (op, u) in chain.utxo.iter() {
            if exclude.contains(op) {
                continue;
            }
            if u.coinbase && sh < u.height + mat {
                continue;
            }
            if self.key_for(&u.pkh).is_some() {
                v.push((*op, u.value));
            }
        }
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    }

    pub fn balance(&self, chain: &Chain) -> u64 {
        self.spendable(chain, &HashSet::new()).iter().map(|x| x.1).sum()
    }

    /// Build and sign a payment. `min_fee` is a floor; the fee grows with the number of inputs.
    pub fn create_tx(&self, chain: &Chain, to: [u8; 20], amount: u64, min_fee: u64, exclude: &HashSet<OutPoint>) -> Result<Tx, String> {
        self.create_tx_multi(chain, &[(to, amount)], min_fee, exclude)
    }

    /// Pay several recipients in one transaction (1..=100).
    pub fn create_tx_multi(&self, chain: &Chain, dests: &[([u8; 20], u64)], min_fee: u64, exclude: &HashSet<OutPoint>) -> Result<Tx, String> {
        if self.locked() || self.expired() {
            return Err("wallet is locked: unlock it with walletpassphrase".into());
        }
        if dests.is_empty() || dests.len() > 100 {
            return Err("between 1 and 100 recipients are allowed".into());
        }
        let mut amount: u64 = 0;
        for (_, a) in dests.iter() {
            if *a == 0 {
                return Err("amount must be positive".into());
            }
            amount = amount.checked_add(*a).ok_or("overflow")?;
        }
        let nout = dests.len() + 1;
        let fee_for = |n: usize| -> u64 { min_fee.max(((12 + 166 * n + 29 * nout) as u64) * FEE_RATE_PER_BYTE) };
        let mut picked: Vec<(OutPoint, u64)> = Vec::new();
        let mut sum: u64 = 0;
        let mut fee = fee_for(1);
        for (op, v) in self.spendable(chain, exclude) {
            picked.push((op, v));
            sum = sum.checked_add(v).ok_or("overflow")?;
            fee = fee_for(picked.len());
            if sum >= amount.checked_add(fee).ok_or("overflow")? {
                break;
            }
        }
        let need = amount.checked_add(fee).ok_or("overflow")?;
        if picked.is_empty() || sum < need {
            return Err("insufficient funds".into());
        }
        let first_pkh = chain.utxo.get(&picked[0].0).map(|u| u.pkh.clone()).ok_or("utxo vanished")?;
        let mut outputs: Vec<TxOut> = dests.iter().map(|(t, a)| TxOut { value: *a, script: t.to_vec() }).collect();
        if sum > need {
            outputs.push(TxOut { value: sum - need, script: first_pkh });
        }
        let mut tx = Tx {
            version: 1,
            inputs: picked.iter().map(|(op, _)| TxIn { prev: op.0, index: op.1, pubkey: vec![], sig: vec![] }).collect(),
            outputs,
            lock_time: 0,
            data: vec![],
        };
        let msg = tx.sighash();
        for (n, (op, _)) in picked.iter().enumerate() {
            let pkh = chain.utxo.get(op).map(|u| u.pkh.clone()).ok_or("utxo vanished")?;
            let key = self.key_for(&pkh).ok_or("key missing")?;
            let sig = ecdsa::sign(&key.secret, &msg).ok_or("signing failed")?;
            tx.inputs[n].pubkey = key.pubkey.to_vec();
            tx.inputs[n].sig = sig.to_vec();
        }
        Ok(tx)
    }

    /// Wallet outputs currently in the UTXO set.
    pub fn unspent(&self, chain: &Chain) -> Vec<UnspentEntry> {
        let sh = chain.spend_height();
        let mat = chain.net.coinbase_maturity();
        let mut v = Vec::new();
        for (op, u) in chain.utxo.iter() {
            if self.key_for(&u.pkh).is_none() || u.pkh.len() != 20 {
                continue;
            }
            let mut pkh = [0u8; 20];
            pkh.copy_from_slice(&u.pkh);
            let spendable = !u.coinbase || sh >= u.height + mat;
            v.push(UnspentEntry { op: *op, value: u.value, height: u.height, spendable, pkh });
        }
        v.sort_by(|a, b| a.height.cmp(&b.height).then(a.op.cmp(&b.op)));
        v
    }

    /// Transactions of the active chain that touch this wallet (oldest first).
    /// "send" amounts are what went to other addresses (negative); fees are not broken out.
    pub fn history(&self, chain: &Chain) -> Vec<HistEntry> {
        let mut v = Vec::new();
        for (h, b) in chain.blocks.iter().enumerate() {
            for tx in b.txs.iter() {
                let recv: i64 = tx.outputs.iter().filter(|o| self.key_for(&o.script[..]).is_some()).map(|o| o.value as i64).sum();
                let txid = tx.txid();
                if tx.is_coinbase() {
                    if recv > 0 {
                        v.push(HistEntry { txid, height: h as u32, category: "generate", amount: recv });
                    }
                    continue;
                }
                let spends_ours = tx.inputs.iter().any(|i| i.pubkey.len() == 64 && self.key_for(&hash160(&i.pubkey)[..]).is_some());
                if spends_ours {
                    let to_others: i64 = tx.outputs.iter().filter(|o| self.key_for(&o.script[..]).is_none()).map(|o| o.value as i64).sum();
                    v.push(HistEntry { txid, height: h as u32, category: "send", amount: -to_others });
                } else if recv > 0 {
                    v.push(HistEntry { txid, height: h as u32, category: "receive", amount: recv });
                }
            }
        }
        v
    }

    /// Copy the wallet file (encrypted if the wallet is encrypted) to a new path.
    pub fn backup(&self, dest: &str) -> Result<String, String> {
        let src = self.path.as_ref().ok_or("wallet has no file")?;
        let d = std::path::Path::new(dest);
        if d.exists() {
            return Err("destination already exists".into());
        }
        std::fs::copy(src, d).map_err(|e| e.to_string())?;
        let msg = if self.is_encrypted() {
            "encrypted backup written"
        } else {
            "WARNING: wallet is not encrypted, so this backup is plain text"
        };
        Ok(msg.to_string())
    }
}

pub struct UnspentEntry {
    pub op: OutPoint,
    pub value: u64,
    pub height: u32,
    pub spendable: bool,
    pub pkh: [u8; 20],
}

pub struct HistEntry {
    pub txid: [u8; 32],
    pub height: u32,
    pub category: &'static str,
    pub amount: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spend_flow() {
        let mut w = Wallet::new(None);
        let a = w.new_key().unwrap();
        let mut c = Chain::new(&REGTEST);
        for _ in 0..4 {
            let mut b = c.build_template(a.to_vec(), vec![]).unwrap();
            b.header.mine();
            c.accept_block(b).unwrap();
        }
        // regtest maturity 2: coinbases at heights 1..=3 are spendable for height 5
        assert_eq!(w.balance(&c), 3 * INITIAL_SUBSIDY);
        let dest = [7u8; 20];
        let tx = w.create_tx(&c, dest, 10 * COIN, DEFAULT_FEE, &HashSet::new()).unwrap();
        let mut b = c.build_template(a.to_vec(), vec![tx.clone()]).unwrap();
        b.header.mine();
        c.accept_block(b).unwrap();
        assert_eq!(c.issued, 5 * INITIAL_SUBSIDY);
        assert!(c.utxo.values().any(|u| u.pkh == dest.to_vec() && u.value == 10 * COIN));
        // double spend of the same inputs is rejected
        let mut b2 = c.build_template(a.to_vec(), vec![]).unwrap();
        b2.txs.push(tx);
        b2.header.merkle = b2.compute_merkle();
        b2.header.mine();
        assert!(c.accept_block(b2).is_err());
    }

    #[test]
    fn sendmany_history_and_unspent() {
        let mut w = Wallet::new(None);
        let a = w.new_key().unwrap();
        let mut c = Chain::new(&REGTEST);
        for _ in 0..4 {
            let mut b = c.build_template(a.to_vec(), vec![]).unwrap();
            b.header.mine();
            c.accept_block(b).unwrap();
        }
        let tx = w
            .create_tx_multi(&c, &[([7u8; 20], 3 * COIN), ([8u8; 20], 4 * COIN)], DEFAULT_FEE, &HashSet::new())
            .unwrap();
        assert!(tx.outputs.len() >= 3);
        let mut b = c.build_template(a.to_vec(), vec![tx]).unwrap();
        b.header.mine();
        c.accept_block(b).unwrap();
        assert!(c.utxo.values().any(|u| u.pkh == vec![7u8; 20] && u.value == 3 * COIN));
        assert!(c.utxo.values().any(|u| u.pkh == vec![8u8; 20] && u.value == 4 * COIN));
        let h = w.history(&c);
        assert_eq!(h.iter().filter(|e| e.category == "generate").count(), 5);
        assert!(h.iter().any(|e| e.category == "send" && e.amount == -(7 * COIN as i64)));
        assert_eq!(w.unspent(&c).len(), c.utxo.values().filter(|u| u.pkh == a.to_vec()).count());
    }

    #[test]
    fn encrypt_lock_unlock() {
        let dir = std::env::temp_dir().join(format!("rylw-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.dat");
        let mut w = Wallet::load(path.clone()).unwrap();
        let a = w.new_key().unwrap();
        let secret = w.keys[0].secret;
        w.encrypt("correct horse").unwrap();
        assert!(w.locked());
        assert_eq!(w.keys[0].secret, [0u8; 32]);
        assert!(w.new_key().is_err());
        assert!(w.encrypt("another one 1").is_err());

        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(32).any(|x| x == secret), "secret must not appear in the file");

        let mut w2 = Wallet::load(path.clone()).unwrap();
        assert!(w2.locked());
        assert_eq!(w2.keys[0].pkh, a);
        assert!(w2.unlock("wrong passphrase", 60).is_err());
        w2.unlock("correct horse", 60).unwrap();
        assert!(!w2.locked());
        assert_eq!(w2.keys[0].secret, secret);
        // adding a key while unlocked re-encrypts the file
        let b = w2.new_key().unwrap();
        w2.lock();
        let mut w3 = Wallet::load(path.clone()).unwrap();
        assert_eq!(w3.keys.len(), 2);
        assert_eq!(w3.keys[1].pkh, b);
        w3.unlock("correct horse", 60).unwrap();
        // tampering is detected
        let mut tampered = std::fs::read(&path).unwrap();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        std::fs::write(&path, &tampered).unwrap();
        let mut w4 = Wallet::load(path.clone()).unwrap();
        assert!(w4.unlock("correct horse", 60).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn damaged_wallet_is_an_error() {
        let dir = std::env::temp_dir().join(format!("rylw-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.dat");
        std::fs::write(&path, b"RYLWAL01 garbage").unwrap();
        assert!(Wallet::load(path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
