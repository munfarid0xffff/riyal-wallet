pub fn encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

pub fn decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

pub fn decode32(s: &str) -> [u8; 32] {
    let v = decode(s).expect("bad hex");
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}
