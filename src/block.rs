use crate::hex;
use crate::sha256::double_sha256;

pub fn rev(a: [u8; 32]) -> [u8; 32] {
    let mut r = a;
    r.reverse();
    r
}

/// Hash in the usual displayed (byte-reversed) hex form.
pub fn rev_hex(h: &[u8; 32]) -> String {
    hex::encode(&rev(*h))
}

fn varint(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

pub struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Reader { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.b.len() {
            return None;
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Some(s)
    }
    pub fn rd_u32(&mut self) -> Option<u32> {
        let s = self.take(4)?;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    pub fn rd_u64(&mut self) -> Option<u64> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Some(u64::from_le_bytes(a))
    }
    pub fn varint(&mut self) -> Option<u64> {
        let f = self.take(1)?[0];
        match f {
            0xfd => {
                let s = self.take(2)?;
                Some(u16::from_le_bytes([s[0], s[1]]) as u64)
            }
            0xfe => Some(self.rd_u32()? as u64),
            0xff => self.rd_u64(),
            n => Some(n as u64),
        }
    }
    pub fn bytes(&mut self, n: u64) -> Option<Vec<u8>> {
        if n > 4_000_000 {
            return None;
        }
        Some(self.take(n as usize)?.to_vec())
    }
    pub fn hash(&mut self) -> Option<[u8; 32]> {
        let s = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        Some(a)
    }
    pub fn done(&self) -> bool {
        self.pos == self.b.len()
    }
}

#[derive(Clone, Debug)]
pub struct TxIn {
    pub prev: [u8; 32],
    pub index: u32,
    pub pubkey: Vec<u8>, // raw x||y, 64 bytes
    pub sig: Vec<u8>,    // r||s, 64 bytes
}

#[derive(Clone, Debug)]
pub struct TxOut {
    pub value: u64,
    pub script: Vec<u8>, // 20-byte address hash
}

#[derive(Clone, Debug)]
pub struct Tx {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
    pub data: Vec<u8>, // coinbase data (height)
}

impl Tx {
    pub fn coinbase(height: u32, value: u64, script: Vec<u8>) -> Tx {
        Tx {
            version: 1,
            inputs: vec![TxIn { prev: [0u8; 32], index: 0xffff_ffff, pubkey: vec![], sig: vec![] }],
            outputs: vec![TxOut { value, script }],
            lock_time: 0,
            data: height.to_le_bytes().to_vec(),
        }
    }

    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].prev == [0u8; 32] && self.inputs[0].index == 0xffff_ffff
    }

    fn ser(&self, full: bool) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&self.version.to_le_bytes());
        varint(&mut o, self.inputs.len() as u64);
        for i in &self.inputs {
            o.extend_from_slice(&i.prev);
            o.extend_from_slice(&i.index.to_le_bytes());
            if full {
                varint(&mut o, i.pubkey.len() as u64);
                o.extend_from_slice(&i.pubkey);
                varint(&mut o, i.sig.len() as u64);
                o.extend_from_slice(&i.sig);
            }
        }
        varint(&mut o, self.outputs.len() as u64);
        for out in &self.outputs {
            o.extend_from_slice(&out.value.to_le_bytes());
            varint(&mut o, out.script.len() as u64);
            o.extend_from_slice(&out.script);
        }
        o.extend_from_slice(&self.lock_time.to_le_bytes());
        varint(&mut o, self.data.len() as u64);
        o.extend_from_slice(&self.data);
        o
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.ser(true)
    }

    /// Transaction id: hash of the form without pubkeys/signatures (not malleable).
    pub fn txid(&self) -> [u8; 32] {
        double_sha256(&self.ser(false))
    }

    /// Message every input signs (commits to all inputs' outpoints and all outputs).
    pub fn sighash(&self) -> [u8; 32] {
        self.txid()
    }

    pub fn read(r: &mut Reader) -> Option<Tx> {
        let version = r.rd_u32()?;
        let ni = r.varint()?;
        let mut inputs = Vec::new();
        for _ in 0..ni {
            let prev = r.hash()?;
            let index = r.rd_u32()?;
            let pl = r.varint()?;
            let pubkey = r.bytes(pl)?;
            let sl = r.varint()?;
            let sig = r.bytes(sl)?;
            inputs.push(TxIn { prev, index, pubkey, sig });
        }
        let no = r.varint()?;
        let mut outputs = Vec::new();
        for _ in 0..no {
            let value = r.rd_u64()?;
            let sl = r.varint()?;
            let script = r.bytes(sl)?;
            outputs.push(TxOut { value, script });
        }
        let lock_time = r.rd_u32()?;
        let dl = r.varint()?;
        let data = r.bytes(dl)?;
        Some(Tx { version, inputs, outputs, lock_time, data })
    }

    pub fn from_bytes(b: &[u8]) -> Option<Tx> {
        let mut r = Reader::new(b);
        let t = Tx::read(&mut r)?;
        if r.done() { Some(t) } else { None }
    }
}

pub fn merkle_root(mut level: Vec<[u8; 32]>) -> [u8; 32] {
    if level.is_empty() {
        return [0u8; 32];
    }
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().unwrap();
            level.push(last);
        }
        level = level
            .chunks(2)
            .map(|p| {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&p[0]);
                buf[32..].copy_from_slice(&p[1]);
                double_sha256(&buf)
            })
            .collect();
    }
    level[0]
}

#[derive(Clone, Debug)]
pub struct Header {
    pub version: i32,
    pub prev: [u8; 32],   // internal byte order
    pub merkle: [u8; 32], // internal byte order
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl Header {
    pub fn serialize(&self) -> [u8; 80] {
        let mut b = [0u8; 80];
        b[0..4].copy_from_slice(&self.version.to_le_bytes());
        b[4..36].copy_from_slice(&self.prev);
        b[36..68].copy_from_slice(&self.merkle);
        b[68..72].copy_from_slice(&self.time.to_le_bytes());
        b[72..76].copy_from_slice(&self.bits.to_le_bytes());
        b[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        b
    }

    pub fn read(r: &mut Reader) -> Option<Header> {
        let version = r.rd_u32()? as i32;
        let prev = r.hash()?;
        let merkle = r.hash()?;
        let time = r.rd_u32()?;
        let bits = r.rd_u32()?;
        let nonce = r.rd_u32()?;
        Some(Header { version, prev, merkle, time, bits, nonce })
    }

    pub fn hash(&self) -> [u8; 32] {
        double_sha256(&self.serialize())
    }

    pub fn hash_hex(&self) -> String {
        rev_hex(&self.hash())
    }

    pub fn check_pow(&self) -> bool {
        match bits_to_target(self.bits) {
            Some(t) => rev(self.hash()) <= t,
            None => false,
        }
    }

    /// Try `tries` nonces; true if a valid one was found.
    pub fn search(&mut self, tries: u32) -> bool {
        for _ in 0..tries {
            if self.check_pow() {
                return true;
            }
            let (n, overflow) = self.nonce.overflowing_add(1);
            self.nonce = n;
            if overflow {
                self.time += 1;
            }
        }
        self.check_pow()
    }

    pub fn mine(&mut self) {
        while !self.search(1_000_000) {}
    }
}

/// Compact "bits" -> 256-bit big-endian target.
pub fn bits_to_target(bits: u32) -> Option<[u8; 32]> {
    let exp = (bits >> 24) as usize;
    let mant = bits & 0x007f_ffff;
    if bits & 0x0080_0000 != 0 || exp > 32 || mant == 0 {
        return None;
    }
    let mut t = [0u8; 32];
    if exp <= 3 {
        let m = mant >> (8 * (3 - exp));
        t[29] = (m >> 16) as u8;
        t[30] = (m >> 8) as u8;
        t[31] = m as u8;
    } else {
        let start = 32 - exp;
        if start + 2 < 32 {
            t[start] = (mant >> 16) as u8;
            t[start + 1] = (mant >> 8) as u8;
            t[start + 2] = mant as u8;
        }
    }
    Some(t)
}

/// Deterministic work estimate for a block with these bits (~2^128 / (target_hi128 + 1)).
pub fn bits_work(bits: u32) -> u128 {
    match bits_to_target(bits) {
        Some(t) => {
            let mut hi = [0u8; 16];
            hi.copy_from_slice(&t[..16]);
            u128::MAX / u128::from_be_bytes(hi).saturating_add(1)
        }
        None => 0,
    }
}

pub fn target_to_bits(t: &[u8; 32]) -> u32 {
    let i = match t.iter().position(|&b| b != 0) {
        Some(i) => i,
        None => return 0,
    };
    let mut size = 32 - i;
    let b1 = if i + 1 < 32 { t[i + 1] as u32 } else { 0 };
    let b2 = if i + 2 < 32 { t[i + 2] as u32 } else { 0 };
    let mut mant = ((t[i] as u32) << 16) | (b1 << 8) | b2;
    if mant & 0x0080_0000 != 0 {
        mant >>= 8;
        size += 1;
    }
    ((size as u32) << 24) | mant
}

/// big-endian 256-bit * u64 -> 320-bit (40 bytes).
pub fn mul_small(t: &[u8; 32], m: u64) -> Vec<u8> {
    let mut out = vec![0u8; 40];
    let mut carry: u128 = 0;
    for i in (0..32).rev() {
        let v = (t[i] as u128) * (m as u128) + carry;
        out[i + 8] = (v & 0xff) as u8;
        carry = v >> 8;
    }
    for j in (0..8).rev() {
        out[j] = (carry & 0xff) as u8;
        carry >>= 8;
    }
    out
}

pub fn div_small(v: &[u8], d: u64) -> Vec<u8> {
    let mut rem: u128 = 0;
    let mut out = vec![0u8; v.len()];
    for i in 0..v.len() {
        let cur = (rem << 8) | (v[i] as u128);
        out[i] = (cur / d as u128) as u8;
        rem = cur % d as u128;
    }
    out
}

#[derive(Clone, Debug)]
pub struct Block {
    pub header: Header,
    pub txs: Vec<Tx>,
}

impl Block {
    pub fn compute_merkle(&self) -> [u8; 32] {
        merkle_root(self.txs.iter().map(|t| t.txid()).collect())
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut o = self.header.serialize().to_vec();
        varint(&mut o, self.txs.len() as u64);
        for t in &self.txs {
            o.extend_from_slice(&t.serialize());
        }
        o
    }

    pub fn deserialize(b: &[u8]) -> Option<Block> {
        let mut r = Reader::new(b);
        let header = Header::read(&mut r)?;
        let n = r.varint()?;
        let mut txs = Vec::new();
        for _ in 0..n {
            txs.push(Tx::read(&mut r)?);
        }
        if r.done() { Some(Block { header, txs }) } else { None }
    }
}

pub fn header_from_display(prev_hex: Option<&str>, merkle_hex: &str, time: u32, bits: u32, nonce: u32) -> Header {
    Header {
        version: 1,
        prev: prev_hex.map(|h| rev(hex::decode32(h))).unwrap_or([0u8; 32]),
        merkle: rev(hex::decode32(merkle_hex)),
        time,
        bits,
        nonce,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_roundtrip() {
        for b in [0x1d00ffffu32, 0x1e2adc28, 0x207fffff] {
            assert_eq!(target_to_bits(&bits_to_target(b).unwrap()), b);
        }
    }

    #[test]
    fn mul_div_identity() {
        let t = bits_to_target(0x1d00ffff).unwrap();
        let q = div_small(&mul_small(&t, 1_209_600), 1_209_600);
        assert_eq!(&q[8..], &t[..]);
    }

    #[test]
    fn block_serialization_roundtrip() {
        let cb = Tx::coinbase(7, 5, vec![1u8; 20]);
        let mut b = Block {
            header: Header { version: 1, prev: [3u8; 32], merkle: [0u8; 32], time: 9, bits: 0x207fffff, nonce: 4 },
            txs: vec![cb],
        };
        b.header.merkle = b.compute_merkle();
        let d = b.serialize();
        let b2 = Block::deserialize(&d).unwrap();
        assert_eq!(b2.serialize(), d);
        assert_eq!(b2.compute_merkle(), b.header.merkle);
    }
}
