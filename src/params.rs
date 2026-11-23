//! Consensus parameters. Network values come from RiyalCoin.txt.

/// Smallest unit = millipiaster = 1e-11 RiyalCoin.
pub const COIN: u64 = 100_000_000_000;
/// Hard cap: 12,000,000 RiyalCoin. Fixed forever (non-expandable).
pub const MAX_MONEY: u64 = 12_000_000 * COIN;
pub const INITIAL_SUBSIDY: u64 = 25 * COIN;
/// 25 * 240,000 * 2 = 12,000,000 (geometric series limit).
pub const HALVING_INTERVAL: u32 = 240_000;
pub const TARGET_SPACING: u32 = 600; // seconds
pub const RETARGET_INTERVAL: u32 = 2016;

pub fn block_subsidy(height: u32) -> u64 {
    let halvings = height / HALVING_INTERVAL;
    if halvings >= 64 {
        return 0;
    }
    INITIAL_SUBSIDY >> halvings
}

pub struct Genesis {
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
    pub merkle: &'static str,
    pub hash: &'static str,
}

pub struct Network {
    pub name: &'static str,
    pub p2p_port: u16,
    pub rpc_port: u16,
    pub magic: [u8; 4],
    pub bech32_hrp: &'static str,
    pub pubkey_prefix: u8,
    pub script_prefix: u8,
    pub secret_prefix: u8,
    pub ext_public: [u8; 4],
    pub ext_secret: [u8; 4],
    pub genesis: Genesis,
}

pub const MAINNET: Network = Network {
    name: "mainnet", p2p_port: 19921, rpc_port: 19922,
    magic: [0xA7, 0x3C, 0x91, 0x5E], bech32_hrp: "rc",
    pubkey_prefix: 0x1B, script_prefix: 0x3F, secret_prefix: 0xA8,
    ext_public: [0x7A, 0xC3, 0x19, 0xE5], ext_secret: [0x3F, 0x81, 0xB6, 0x2D],
    genesis: Genesis { time: 1798761600, bits: 0x1d00ffff, nonce: 311902642,
        merkle: "4930b32337be790f6fa32ebfbf0d0d95b5420bc30d0033d4cd4da71bfc7b1a6b",
        hash: "0000000086bdac2c9dfeb57978a8fa1a455310f6e4ae08c34dd4272dae143426" },
};

pub const TESTNET3: Network = Network {
    name: "testnet3", p2p_port: 19923, rpc_port: 19924,
    magic: [0xD4, 0x0B, 0x7A, 0xE2], bech32_hrp: "rx",
    pubkey_prefix: 0x2C, script_prefix: 0x55, secret_prefix: 0xB9,
    ext_public: [0x1D, 0x94, 0xE7, 0x3A], ext_secret: [0xC5, 0x2B, 0x70, 0x9F],
    genesis: Genesis { time: 1798962939, bits: 0x1d00ffff, nonce: 87577752,
        merkle: "98ae02f977ebcb736301c34f40ec2b37841c359582e3b74f40be57dd40a06144",
        hash: "000000009c1fd2cab86f8324c278e1a1593d145971d3b56295eae43ec390317a" },
};

pub const TESTNET4: Network = Network {
    name: "testnet4", p2p_port: 19925, rpc_port: 19926,
    magic: [0x3E, 0xB9, 0x14, 0x8D], bech32_hrp: "rx",
    pubkey_prefix: 0x47, script_prefix: 0x6E, secret_prefix: 0xC4,
    ext_public: [0xB6, 0x2F, 0x58, 0xC1], ext_secret: [0x48, 0xDA, 0x13, 0x7E],
    genesis: Genesis { time: 1799147313, bits: 0x1d00ffff, nonce: 2508357954,
        merkle: "4950564492d051ed5c4a1123c469288619dc9458bda4b6ac65cc804dae28dd20",
        hash: "000000008a25117755bf0c992b7537ef88315e134eb40aa8aa04e885e0a56344" },
};

pub const SIGNET: Network = Network {
    name: "signet", p2p_port: 19927, rpc_port: 19928,
    magic: [0x6C, 0xF1, 0x2A, 0x57], bech32_hrp: "rx",
    pubkey_prefix: 0x5A, script_prefix: 0x7D, secret_prefix: 0xD1,
    ext_public: [0x4E, 0xA1, 0xD7, 0x2B], ext_secret: [0x92, 0x6C, 0xF0, 0x58],
    genesis: Genesis { time: 1799462841, bits: 0x1e2adc28, nonce: 314673,
        merkle: "95c0885a4fbe697f2a6d0d1dff43db2404f4fb67b5d9422729d5fa939adc7afe",
        hash: "000024e79d164dd6b609f232efbfe270167d0adbb08817ce2281f82406169149" },
};

pub const REGTEST: Network = Network {
    name: "regtest", p2p_port: 19929, rpc_port: 19930,
    magic: [0x9D, 0x48, 0xC3, 0x0F], bech32_hrp: "rcrx",
    pubkey_prefix: 0x8F, script_prefix: 0xA3, secret_prefix: 0xE7,
    ext_public: [0xE3, 0x5C, 0x80, 0x96], ext_secret: [0x0B, 0xB7, 0x4A, 0xD2],
    genesis: Genesis { time: 1799876238, bits: 0x207fffff, nonce: 2,
        merkle: "c4f905d2adafbd36f7353202be7be7ec63e0bceb4fdd978de4d1ef501480270e",
        hash: "0761093781c3c7530b9407f16e150fc4c46410013bb0f62e40c7d3ec84267984" },
};

pub fn by_name(n: &str) -> Option<&'static Network> {
    match n {
        "mainnet" | "main" => Some(&MAINNET),
        "testnet3" | "testnet" => Some(&TESTNET3),
        "testnet4" => Some(&TESTNET4),
        "signet" => Some(&SIGNET),
        "regtest" => Some(&REGTEST),
        _ => None,
    }
}

pub const ALL: [&Network; 5] = [&MAINNET, &TESTNET3, &TESTNET4, &SIGNET, &REGTEST];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supply_never_exceeds_cap() {
        let mut total: u128 = 0;
        for era in 0..70u32 {
            total += block_subsidy(era * HALVING_INTERVAL) as u128 * HALVING_INTERVAL as u128;
        }
        assert!(total <= MAX_MONEY as u128);
        // within 0.0001% of the cap
        assert!(total > (MAX_MONEY as u128) * 999_999 / 1_000_000);
    }
}

pub const MAX_BLOCK_SIZE: usize = 1_000_000;
/// Default wallet fee: 0.000001 RiyalCoin.
pub const DEFAULT_FEE: u64 = 100_000;
/// Relay policy: a transaction must pay at least this many units per serialized byte.
pub const MIN_RELAY_FEE_PER_BYTE: u64 = 100;
/// Wallet fee rate (units per byte, estimated size); DEFAULT_FEE is the floor.
pub const FEE_RATE_PER_BYTE: u64 = 200;
pub const MAX_MEMPOOL_TXS: usize = 5000;
pub const MAX_MEMPOOL_BYTES: usize = 10_000_000;

impl Network {
    /// Mainnet/testnets retarget every RETARGET_INTERVAL blocks; signet/regtest keep fixed bits.
    pub fn retargets(&self) -> bool {
        !(self.name == "regtest" || self.name == "signet")
    }
    pub fn coinbase_maturity(&self) -> u32 {
        if self.name == "regtest" { 2 } else { 100 }
    }
}

pub fn fmt_coins(units: u64) -> String {
    format!("{}.{:011}", units / COIN, units % COIN)
}

pub fn parse_coins(s: &str) -> Option<u64> {
    let (i, f) = match s.split_once('.') {
        Some((a, b)) => (a, b),
        None => (s, ""),
    };
    if f.len() > 11 || (i.is_empty() && f.is_empty()) {
        return None;
    }
    if !i.bytes().all(|c| c.is_ascii_digit()) || !f.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let iv: u64 = if i.is_empty() { 0 } else { i.parse().ok()? };
    let mut fs = f.to_string();
    while fs.len() < 11 {
        fs.push('0');
    }
    let fv: u64 = fs.parse().ok()?;
    iv.checked_mul(COIN)?.checked_add(fv)
}
