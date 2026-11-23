//! Bech32 (BIP173) encoding. RiyalCoin addresses use witness-version-0 style: hrp + "1" + [0] + 20-byte hash.
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ (v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= *g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|c| c & 31));
    v
}

/// `data` holds 5-bit values.
pub fn encode(hrp: &str, data: &[u8]) -> String {
    let mut vals = hrp_expand(hrp);
    vals.extend_from_slice(data);
    vals.extend_from_slice(&[0u8; 6]);
    let m = polymod(&vals) ^ 1;
    let mut s = String::from(hrp);
    s.push('1');
    for &d in data {
        s.push(CHARSET[d as usize] as char);
    }
    for i in 0..6 {
        s.push(CHARSET[((m >> (5 * (5 - i))) & 31) as usize] as char);
    }
    s
}

/// Returns (hrp, 5-bit data without the checksum). Rejects mixed case and bad checksums.
pub fn decode(s: &str) -> Option<(String, Vec<u8>)> {
    if s.len() > 90 {
        return None;
    }
    let has_lower = s.bytes().any(|c| c.is_ascii_lowercase());
    let has_upper = s.bytes().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return None;
    }
    let s = s.to_ascii_lowercase();
    let pos = s.rfind('1')?;
    if pos == 0 || pos + 7 > s.len() {
        return None;
    }
    let hrp = &s[..pos];
    if !hrp.bytes().all(|c| (33..=126).contains(&c)) {
        return None;
    }
    let mut data = Vec::new();
    for c in s[pos + 1..].bytes() {
        data.push(CHARSET.iter().position(|&x| x == c)? as u8);
    }
    let mut vals = hrp_expand(hrp);
    vals.extend_from_slice(&data);
    if polymod(&vals) != 1 {
        return None;
    }
    data.truncate(data.len() - 6);
    Some((hrp.to_string(), data))
}

pub fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    let maxv: u32 = (1 << to) - 1;
    let max_acc: u32 = (1u32 << (from + to - 1)) - 1;
    for &v in data {
        if (v as u32) >> from != 0 {
            return None;
        }
        acc = ((acc << from) | v as u32) & max_acc;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip173_vector() {
        let h = crate::hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let mut d = vec![0u8];
        d.extend(convert_bits(&h, 8, 5, true).unwrap());
        assert_eq!(encode("bc", &d), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let (hrp, back) = decode("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4").unwrap();
        assert_eq!(hrp, "bc");
        assert_eq!(back, d);
        assert_eq!(convert_bits(&back[1..], 5, 8, false).unwrap(), h);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5").is_none()); // bad checksum
        assert!(decode("bc1Qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").is_none()); // mixed case
        assert!(decode("noseparator").is_none());
    }
}
