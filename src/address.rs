//! Base58Check addresses. Address hash = first 20 bytes of double-SHA256(pubkey).
use crate::params::Network;
use crate::sha256::double_sha256;

const ALPHA: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn hash160(data: &[u8]) -> [u8; 20] {
    let h = double_sha256(data);
    let mut o = [0u8; 20];
    o.copy_from_slice(&h[..20]);
    o
}

pub fn b58_encode(data: &[u8]) -> String {
    let zeros = data.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &b in data {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut s = String::new();
    for _ in 0..zeros {
        s.push('1');
    }
    for d in digits.iter().rev() {
        s.push(ALPHA[*d as usize] as char);
    }
    s
}

pub fn b58_decode(s: &str) -> Option<Vec<u8>> {
    let zeros = s.bytes().take_while(|&c| c == b'1').count();
    let mut bytes: Vec<u8> = Vec::new();
    for c in s.bytes() {
        let mut carry = ALPHA.iter().position(|&a| a == c)? as u32;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Some(out)
}

pub fn encode_address(net: &Network, pkh: &[u8; 20]) -> String {
    let mut data = vec![net.pubkey_prefix];
    data.extend_from_slice(pkh);
    let ck = double_sha256(&data);
    data.extend_from_slice(&ck[..4]);
    b58_encode(&data)
}

pub fn decode_address(net: &Network, s: &str) -> Option<[u8; 20]> {
    let d = b58_decode(s)?;
    if d.len() != 25 || d[0] != net.pubkey_prefix {
        return None;
    }
    if double_sha256(&d[..21])[..4] != d[21..] {
        return None;
    }
    let mut o = [0u8; 20];
    o.copy_from_slice(&d[1..21]);
    Some(o)
}

pub fn encode_bech32(net: &Network, pkh: &[u8; 20]) -> String {
    let mut d = vec![0u8]; // witness-version-0 style prefix
    d.extend(crate::bech32::convert_bits(pkh, 8, 5, true).unwrap_or_default());
    crate::bech32::encode(net.bech32_hrp, &d)
}

pub fn decode_bech32(net: &Network, s: &str) -> Option<[u8; 20]> {
    let (hrp, d) = crate::bech32::decode(s)?;
    if hrp != net.bech32_hrp || d.is_empty() || d[0] != 0 {
        return None;
    }
    let b = crate::bech32::convert_bits(&d[1..], 5, 8, false)?;
    if b.len() != 20 {
        return None;
    }
    let mut o = [0u8; 20];
    o.copy_from_slice(&b);
    Some(o)
}

/// Accepts either address format.
pub fn decode_any(net: &Network, s: &str) -> Option<[u8; 20]> {
    decode_address(net, s).or_else(|| decode_bech32(net, s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::MAINNET;

    #[test]
    fn address_roundtrip() {
        let pkh = hash160(b"hello");
        let a = encode_address(&MAINNET, &pkh);
        assert_eq!(decode_address(&MAINNET, &a), Some(pkh));
        let mut bad = a.clone();
        bad.pop();
        bad.push(if a.ends_with('2') { '3' } else { '2' });
        assert_eq!(decode_address(&MAINNET, &bad), None);
    }

    #[test]
    fn bech32_address_roundtrip() {
        let mut pkh = [0u8; 20];
        for (i, b) in pkh.iter_mut().enumerate() {
            *b = i as u8;
        }
        let s = encode_bech32(&MAINNET, &pkh);
        assert_eq!(s, "rc1qqqqsyqcyq5rqwzqfpg9scrgwpugpzysnxu4z4s");
        assert_eq!(decode_any(&MAINNET, &s), Some(pkh));
        assert_eq!(decode_bech32(&crate::params::REGTEST, &s), None); // wrong network prefix
        assert_eq!(encode_bech32(&crate::params::REGTEST, &pkh), "rcrx1qqqqsyqcyq5rqwzqfpg9scrgwpugpzysnl4wc45");
    }

    #[test]
    fn base58_known() {
        assert_eq!(b58_encode(b"hello world"), "StV1DL6CwTryKyV");
    }
}
