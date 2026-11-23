//! Library face of the RiyalCoin node, used by the GUI wallet (`wallet/src-tauri`).
//! The `riyalcoin` binary (src/main.rs) is unchanged and keeps working as before.
pub mod addrman;
pub mod address;
pub mod bech32;
pub mod block;
pub mod chain;
pub mod ecdsa;
pub mod embed;
pub mod hex;
pub mod node;
pub mod params;
pub mod rpc;
pub mod sha256;
pub mod wallet;
