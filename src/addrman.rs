//! Address manager with Bitcoin-style bucketing (simplified).
//!
//! * `new` table: addresses heard about but never connected to (1024 buckets x 64 slots).
//! * `tried` table: addresses we connected to successfully (256 buckets x 64 slots).
//! * The bucket and slot of an address come from a keyed hash (secret key stored in peers.dat), so an attacker cannot
//!   predict or aim where its addresses land. Addresses announced by one network group can occupy at most 64 of the
//!   1024 new buckets, and addresses of one /16 can occupy at most 8 of the 256 tried buckets. A slot that is
//!   already taken by a healthy address is never overwritten by a newcomer.
//! Simplifications vs Bitcoin: each address lives in exactly one slot, and there is no test-before-evict.
use crate::sha256::sha256;
use k256::elliptic_curve::rand_core::{OsRng, RngCore};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

pub const NEW_BUCKETS: usize = 1024;
pub const TRIED_BUCKETS: usize = 256;
pub const SLOTS: usize = 64;
const NEW_BUCKETS_PER_SOURCE_GROUP: u64 = 64;
const TRIED_BUCKETS_PER_GROUP: u64 = 8;
const MAX_AGE: u32 = 30 * 24 * 3600;
const RETRY_AFTER: u32 = 600;
const MAX_FAILURES: u32 = 5;

pub fn now_secs() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().min(u32::MAX as u64) as u32)
        .unwrap_or(0)
}

fn is_public_v4(a: &Ipv4Addr) -> bool {
    let o = a.octets();
    !(a.is_private()
        || a.is_loopback()
        || a.is_link_local()
        || a.is_unspecified()
        || a.is_broadcast()
        || a.is_documentation()
        || a.is_multicast()
        || o[0] == 0
        || o[0] >= 240
        || (o[0] == 100 && (o[1] & 0xc0) == 64))
}

/// Globally routable address (not private, loopback, link-local, multicast, documentation, ...).
pub fn routable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => is_public_v4(a),
        IpAddr::V6(a) => {
            if let Some(m) = a.to_ipv4_mapped() {
                return is_public_v4(&m);
            }
            let s = a.segments();
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8))
        }
    }
}

/// Network group (IPv4 /16, IPv6 /32). Local/private ranges are grouped by their /16 as well.
pub fn group(ip: &IpAddr) -> Vec<u8> {
    let v4 = match ip {
        IpAddr::V4(a) => Some(*a),
        IpAddr::V6(a) => a.to_ipv4_mapped(),
    };
    match v4 {
        Some(a) => {
            let o = a.octets();
            vec![4, o[0], o[1]]
        }
        None => match ip {
            IpAddr::V6(a) => {
                let o = a.octets();
                vec![6, o[0], o[1], o[2], o[3]]
            }
            IpAddr::V4(_) => vec![],
        },
    }
}

fn rand_below(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    (OsRng.next_u64() % (n as u64)) as usize
}

fn addr_bytes(a: &SocketAddr) -> Vec<u8> {
    let v6: Ipv6Addr = match a.ip() {
        IpAddr::V4(v) => v.to_ipv6_mapped(),
        IpAddr::V6(v) => v,
    };
    let mut b = v6.octets().to_vec();
    b.extend_from_slice(&a.port().to_le_bytes());
    b
}

fn hash64(key: &[u8; 32], parts: &[&[u8]]) -> u64 {
    let mut buf = Vec::with_capacity(96);
    buf.extend_from_slice(key);
    for p in parts {
        buf.extend_from_slice(p);
    }
    let h = sha256(&buf);
    u64::from_le_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]])
}

#[derive(Clone, Debug)]
struct Info {
    last_seen: u32,
    last_try: u32,
    failures: u32,
    tried: bool,
    source: IpAddr,
}

fn terrible(i: &Info, now: u32) -> bool {
    now.saturating_sub(i.last_seen) > MAX_AGE || (!i.tried && i.failures >= MAX_FAILURES)
}

type Table = Vec<[Option<SocketAddr>; SLOTS]>;

pub struct AddrBook {
    key: [u8; 32],
    info: HashMap<SocketAddr, Info>,
    new_t: Table,
    tried_t: Table,
}

impl AddrBook {
    pub fn new() -> AddrBook {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        AddrBook::with_key(key)
    }

    fn with_key(key: [u8; 32]) -> AddrBook {
        AddrBook {
            key,
            info: HashMap::new(),
            new_t: vec![[None; SLOTS]; NEW_BUCKETS],
            tried_t: vec![[None; SLOTS]; TRIED_BUCKETS],
        }
    }

    pub fn len(&self) -> usize {
        self.info.len()
    }

    /// (new, tried) counts.
    pub fn counts(&self) -> (usize, usize) {
        let tried = self.info.values().filter(|i| i.tried).count();
        (self.info.len() - tried, tried)
    }

    fn new_pos(&self, addr: &SocketAddr, source: &IpAddr) -> (usize, usize) {
        let ab = addr_bytes(addr);
        let ag = group(&addr.ip());
        let sg = group(source);
        let h1 = hash64(&self.key, &[&b"N1"[..], &ag[..], &sg[..]]) % NEW_BUCKETS_PER_SOURCE_GROUP;
        let b = (hash64(&self.key, &[&b"N2"[..], &sg[..], &h1.to_le_bytes()[..]]) % NEW_BUCKETS as u64) as usize;
        let s = (hash64(&self.key, &[&b"N3"[..], &(b as u32).to_le_bytes()[..], &ab[..]]) % SLOTS as u64) as usize;
        (b, s)
    }

    fn tried_pos(&self, addr: &SocketAddr) -> (usize, usize) {
        let ab = addr_bytes(addr);
        let ag = group(&addr.ip());
        let h1 = hash64(&self.key, &[&b"K1"[..], &ab[..]]) % TRIED_BUCKETS_PER_GROUP;
        let b = (hash64(&self.key, &[&b"K2"[..], &ag[..], &h1.to_le_bytes()[..]]) % TRIED_BUCKETS as u64) as usize;
        let s = (hash64(&self.key, &[&b"K3"[..], &(b as u32).to_le_bytes()[..], &ab[..]]) % SLOTS as u64) as usize;
        (b, s)
    }

    /// Learn an address announced by `source`. Returns true if it was stored as a new entry.
    pub fn add(&mut self, addr: SocketAddr, source: IpAddr, last_seen: u32, allow_local: bool) -> bool {
        if addr.port() == 0 || (!allow_local && !routable(&addr.ip())) || addr.ip().is_unspecified() || addr.ip().is_multicast() {
            return false;
        }
        let now = now_secs();
        let ts = last_seen.min(now); // never trust timestamps from the future
        if now.saturating_sub(ts) > MAX_AGE {
            return false;
        }
        if let Some(i) = self.info.get_mut(&addr) {
            i.last_seen = i.last_seen.max(ts);
            return false;
        }
        let (b, s) = self.new_pos(&addr, &source);
        if let Some(old) = self.new_t[b][s] {
            let replace = match self.info.get(&old) {
                Some(i) => terrible(i, now),
                None => true,
            };
            if !replace {
                return false; // the slot belongs to a healthy address: newcomers cannot push it out
            }
            self.info.remove(&old);
        }
        self.new_t[b][s] = Some(addr);
        self.info.insert(addr, Info { last_seen: ts, last_try: 0, failures: 0, tried: false, source });
        true
    }

    pub fn mark_attempt(&mut self, addr: SocketAddr, now: u32) {
        if let Some(i) = self.info.get_mut(&addr) {
            i.last_try = now;
            i.failures = i.failures.saturating_add(1);
        }
    }

    /// Successful connection: the address moves to the tried table.
    pub fn mark_good(&mut self, addr: SocketAddr, now: u32) {
        let already = match self.info.get_mut(&addr) {
            Some(i) => {
                i.failures = 0;
                i.last_seen = now;
                i.tried
            }
            None => return,
        };
        if already {
            return;
        }
        self.move_to_tried(addr);
    }

    fn move_to_tried(&mut self, addr: SocketAddr) {
        let source = match self.info.get(&addr) {
            Some(i) => i.source,
            None => return,
        };
        let (nb, ns) = self.new_pos(&addr, &source);
        if self.new_t[nb][ns] == Some(addr) {
            self.new_t[nb][ns] = None;
        }
        let (tb, ts) = self.tried_pos(&addr);
        if let Some(old) = self.tried_t[tb][ts] {
            // the tried slot is taken: demote that entry back to the new table
            self.tried_t[tb][ts] = None;
            let old_source = self.info.get(&old).map(|i| i.source);
            match old_source {
                Some(src) => {
                    let (ob, os) = self.new_pos(&old, &src);
                    if let Some(prev) = self.new_t[ob][os] {
                        self.info.remove(&prev);
                    }
                    self.new_t[ob][os] = Some(old);
                    if let Some(oi) = self.info.get_mut(&old) {
                        oi.tried = false;
                    }
                }
                None => {}
            }
        }
        self.tried_t[tb][ts] = Some(addr);
        if let Some(i) = self.info.get_mut(&addr) {
            i.tried = true;
        }
    }

    /// Pick a random address to dial (50% tried / 50% new): not connected, not tried recently, not failing,
    /// and preferably in a network group we are not yet connected to.
    pub fn pick(&self, connected: &HashSet<SocketAddr>, used_groups: &[Vec<u8>], now: u32) -> Option<SocketAddr> {
        let tried_first = rand_below(2) == 0;
        for pass in 0..2 {
            let want_tried = if pass == 0 { tried_first } else { !tried_first };
            let cands: Vec<SocketAddr> = self
                .info
                .iter()
                .filter(|(a, i)| {
                    i.tried == want_tried
                        && !connected.contains(a)
                        && now.saturating_sub(i.last_try) >= RETRY_AFTER
                        && (i.tried || i.failures < MAX_FAILURES)
                })
                .map(|(a, _)| *a)
                .collect();
            let diverse: Vec<SocketAddr> = cands.iter().filter(|a| !used_groups.contains(&group(&a.ip()))).cloned().collect();
            let pool = if diverse.is_empty() { &cands } else { &diverse };
            if !pool.is_empty() {
                return Some(pool[rand_below(pool.len())]);
            }
        }
        None
    }

    /// Up to `n` (and at most 23% of the book) random recently-seen addresses to share with a peer.
    pub fn sample(&self, n: usize) -> Vec<(SocketAddr, u32)> {
        let now = now_secs();
        let mut v: Vec<(SocketAddr, u32)> = self
            .info
            .iter()
            .filter(|(_, i)| now.saturating_sub(i.last_seen) <= MAX_AGE)
            .map(|(a, i)| (*a, i.last_seen))
            .collect();
        for i in (1..v.len()).rev() {
            let j = rand_below(i + 1);
            v.swap(i, j);
        }
        let cap = (self.info.len() * 23 / 100).max(1).min(n);
        v.truncate(cap);
        v
    }

    /// (address, last_seen, tried), newest first.
    pub fn all(&self) -> Vec<(SocketAddr, u32, bool)> {
        let mut v: Vec<(SocketAddr, u32, bool)> = self.info.iter().map(|(a, i)| (*a, i.last_seen, i.tried)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }

    /// Text format: first line `key <hex>`, then `ip:port last_seen last_try failures tried source_ip`.
    pub fn save(&self, path: &Path) {
        let mut s = format!("key {}\n", crate::hex::encode(&self.key));
        for (a, i) in self.info.iter() {
            s.push_str(&format!("{} {} {} {} {} {}\n", a, i.last_seen, i.last_try, i.failures, i.tried as u8, i.source));
        }
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, s).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }

    /// Loads the book. The stored key keeps every address in the same bucket across restarts.
    pub fn load(path: &Path) -> AddrBook {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let mut lines = text.lines();
        let mut key = [0u8; 32];
        let mut have_key = false;
        let first = lines.next().unwrap_or("");
        if let Some(h) = first.strip_prefix("key ") {
            if let Some(v) = crate::hex::decode(h.trim()) {
                if v.len() == 32 {
                    key.copy_from_slice(&v);
                    have_key = true;
                }
            }
        }
        if !have_key {
            return AddrBook::new(); // unreadable or old format: start with a fresh key and an empty book
        }
        let mut b = AddrBook::with_key(key);
        for line in lines {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() != 6 {
                continue;
            }
            let (addr, ts, lt, fl, tr, src) = match (
                f[0].parse::<SocketAddr>(),
                f[1].parse::<u32>(),
                f[2].parse::<u32>(),
                f[3].parse::<u32>(),
                f[4].parse::<u8>(),
                f[5].parse::<IpAddr>(),
            ) {
                (Ok(a), Ok(ts), Ok(lt), Ok(fl), Ok(tr), Ok(src)) => (a, ts, lt, fl, tr, src),
                _ => continue,
            };
            if addr.port() == 0 || b.info.contains_key(&addr) {
                continue;
            }
            let mut tried = tr == 1;
            let mut placed = false;
            if tried {
                let (tb, ts_) = b.tried_pos(&addr);
                if b.tried_t[tb][ts_].is_none() {
                    b.tried_t[tb][ts_] = Some(addr);
                    placed = true;
                } else {
                    tried = false; // collision: keep it, but as a "new" entry
                }
            }
            if !placed {
                let (nb, ns) = b.new_pos(&addr, &src);
                if b.new_t[nb][ns].is_some() {
                    continue;
                }
                b.new_t[nb][ns] = Some(addr);
            }
            b.info.insert(addr, Info { last_seen: ts, last_try: lt, failures: fl, tried, source: src });
        }
        b
    }
}

/// addr message: count u16 | count * (ip[16] IPv6-mapped | port u16 | last_seen u32), all little-endian.
pub fn encode_addrs(list: &[(SocketAddr, u32)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 22 * list.len());
    out.extend_from_slice(&(list.len() as u16).to_le_bytes());
    for (a, ts) in list {
        out.extend_from_slice(&addr_bytes(a)[..16]);
        out.extend_from_slice(&a.port().to_le_bytes());
        out.extend_from_slice(&ts.to_le_bytes());
    }
    out
}

pub fn decode_addrs(p: &[u8]) -> Option<Vec<(SocketAddr, u32)>> {
    if p.len() < 2 {
        return None;
    }
    let n = u16::from_le_bytes([p[0], p[1]]) as usize;
    if n > 100 || p.len() != 2 + 22 * n {
        return None;
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let o = 2 + 22 * i;
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&p[o..o + 16]);
        let v6 = Ipv6Addr::from(ip);
        let ipa = match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        };
        let port = u16::from_le_bytes([p[o + 16], p[o + 17]]);
        let ts = u32::from_le_bytes([p[o + 18], p[o + 19], p[o + 20], p[o + 21]]);
        out.push((SocketAddr::new(ipa, port), ts));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn routable_rules() {
        for a in ["10.0.0.1", "192.168.1.5", "172.16.0.9", "127.0.0.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "255.255.255.255", "::1", "fe80::1", "fc00::1"] {
            assert!(!routable(&a.parse().unwrap()), "{}", a);
        }
        for a in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(routable(&a.parse().unwrap()), "{}", a);
        }
    }

    #[test]
    fn add_filters_and_clamps() {
        let mut b = AddrBook::new();
        let now = now_secs();
        let src = ip("8.8.4.4");
        assert!(!b.add(sa("192.168.1.2:19921"), src, now, false)); // private
        assert!(b.add(sa("192.168.1.2:19921"), src, now, true)); // allowed for LAN testing
        assert!(!b.add(sa("8.8.8.8:0"), src, now, false)); // port 0
        assert!(b.add(sa("8.8.8.8:19921"), src, now + 100_000, false)); // future timestamp is clamped
        assert!(!b.add(sa("9.9.9.9:19921"), src, now - 40 * 24 * 3600, false)); // too old
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn one_source_group_reaches_at_most_64_new_buckets() {
        let b = AddrBook::new();
        let src = ip("45.1.2.3");
        let mut buckets = HashSet::new();
        for i in 0..3000u32 {
            let a = sa(&format!("{}.{}.1.9:19921", 20 + i / 250, i % 250 + 1)); // 3000 distinct /16 groups
            buckets.insert(b.new_pos(&a, &src).0);
        }
        assert!(buckets.len() <= 64, "got {}", buckets.len());
        assert!(buckets.len() > 20); // and they do spread over many of those buckets
    }

    #[test]
    fn one_group_reaches_at_most_8_tried_buckets() {
        let b = AddrBook::new();
        let mut buckets = HashSet::new();
        for i in 0..2000u32 {
            let a = sa(&format!("77.5.{}.{}:19921", (i / 200) % 200 + 1, i % 200 + 1));
            buckets.insert(b.tried_pos(&a).0);
        }
        assert!(buckets.len() <= 8, "got {}", buckets.len());
    }

    #[test]
    fn placement_depends_on_secret_key() {
        let a = AddrBook::new();
        let b = AddrBook::new();
        let src = ip("45.1.2.3");
        let mut differ = false;
        for i in 1..30u32 {
            let x = sa(&format!("20.{}.1.1:19921", i));
            if a.new_pos(&x, &src) != b.new_pos(&x, &src) {
                differ = true;
            }
        }
        assert!(differ);
    }

    #[test]
    fn good_address_moves_to_tried_and_frees_its_new_slot() {
        let mut b = AddrBook::new();
        let now = now_secs();
        let x = sa("8.8.8.8:19921");
        let src = ip("9.9.9.9");
        assert!(b.add(x, src, now, false));
        assert_eq!(b.counts(), (1, 0));
        let (nb, ns) = b.new_pos(&x, &src);
        b.mark_good(x, now);
        assert_eq!(b.counts(), (0, 1));
        assert!(b.new_t[nb][ns].is_none());
        let (tb, ts) = b.tried_pos(&x);
        assert_eq!(b.tried_t[tb][ts], Some(x));
        assert!(!b.add(x, src, now, false)); // known address is not "new" again
    }

    #[test]
    fn pick_prefers_new_groups_and_skips_connected() {
        let mut b = AddrBook::new();
        let now = now_secs();
        let src = ip("1.1.1.1");
        b.add(sa("8.8.1.1:19921"), src, now, false);
        b.add(sa("9.9.1.1:19921"), src, now, false);
        let mut connected = HashSet::new();
        connected.insert(sa("8.8.1.1:19921"));
        let used = vec![group(&ip("8.8.1.1"))];
        for _ in 0..20 {
            assert_eq!(b.pick(&connected, &used, now), Some(sa("9.9.1.1:19921")));
        }
        b.mark_attempt(sa("9.9.1.1:19921"), now);
        assert_eq!(b.pick(&connected, &used, now), None); // retry delay
    }

    #[test]
    fn addr_message_roundtrip() {
        let list = vec![(sa("8.8.8.8:19921"), 123u32), (sa("[2606:4700:4700::1111]:19921"), 456u32)];
        let enc = encode_addrs(&list);
        assert_eq!(enc.len(), 2 + 44);
        assert_eq!(decode_addrs(&enc).unwrap(), list);
        assert!(decode_addrs(&enc[..enc.len() - 1]).is_none());
        let mut huge = vec![0u8; 2];
        huge[0] = 200;
        assert!(decode_addrs(&huge).is_none());
    }

    #[test]
    fn persistence_keeps_key_placement_and_tried_state() {
        let dir = std::env::temp_dir().join(format!("rylpeers-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("peers.dat");
        let mut b = AddrBook::new();
        let now = now_secs();
        let src = ip("9.9.9.9");
        b.add(sa("8.8.8.8:19921"), src, now, false);
        b.add(sa("8.8.4.4:19921"), src, now, false);
        b.mark_good(sa("8.8.8.8:19921"), now);
        b.save(&path);
        let c = AddrBook::load(&path);
        assert_eq!(c.counts(), (1, 1));
        assert_eq!(c.new_pos(&sa("8.8.4.4:19921"), &src), b.new_pos(&sa("8.8.4.4:19921"), &src));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
