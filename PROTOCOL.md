# RiyalCoin protocol (draft, as implemented in this repository)

All integers little-endian unless stated. `H(x)` = SHA-256(SHA-256(x)). Hashes are displayed byte-reversed.
This document describes the code; if they disagree, the code is the specification until this file is audited.

## Units and supply
- 1 RiyalCoin = 10^11 units (millipiaster). `MAX_MONEY` = 12,000,000 x 10^11. Consensus values are `u64`.
- Block subsidy: 25 RiyalCoin, halved (right shift) every 240,000 blocks, 0 after 64 halvings. Total < 12,000,000.
- Block fees are redistributed, never created: coinbase value <= subsidy + fees.

## Networks
Name, ports, magic, address prefixes and genesis headers are in `src/params.rs` (taken from RiyalCoin.txt).
Retargeting is active on mainnet/testnet3/testnet4 only; signet and regtest keep their genesis bits.

## Block header (80 bytes)
`version i32 | prev[32] | merkle[32] | time u32 | bits u32 | nonce u32`. Block hash = H(header).
Proof of work: reversed hash (big-endian) <= target(bits). Compact bits as in Bitcoin; target must not exceed the
network limit (genesis bits). Work per block ~ 2^128 / (top 128 bits of target + 1); the heaviest cumulative work wins.

## Block validity
1. PoW valid, target <= network limit, serialized size <= 1,000,000 bytes, merkle root (Bitcoin-style, duplicate last) matches.
2. First tx is the only coinbase. Coinbase `data` must equal the block height (u32 LE), its input carries no pubkey/sig,
   outputs are 20-byte hashes with 0 < value <= MAX_MONEY, total <= subsidy + fees.
3. `time` > previous block time; on retargeting networks (mainnet, testnet3/4) `time` <= now + 7200 s, where `now` is the
   node's wall clock (a local rule, as in Bitcoin). Genesis is dated in the future before launch, so no honest node
   accepts or mines a block until 2 hours before the genesis timestamp (mainnet: 2026-12-31 22:00 UTC).
4. `bits` = previous bits, except every 2016th block: new target = old target x clamp(actual, T/4, 4T) / T where
   T = 2016 x 600 s and actual = time(parent) - time(block 2015 steps before the parent); capped at the network limit.
5. No output may overwrite an existing unspent outpoint. Coinbase outputs mature after 100 blocks (regtest 2).
6. Reorganisation: the branch with more cumulative work replaces the active chain; if any block of it is invalid the
   node restores its previous chain.

## Transactions
Serialization: `version u32 | n_in varint | inputs | n_out varint | outputs | lock_time u32 | data varint+bytes`.
Input: `prev_txid[32] | index u32 | pubkey varint+64 bytes (x||y) | sig varint+64 bytes (r||s)`.
Output: `value u64 | script varint+20 bytes (address hash)`.
- `txid` = H(serialization WITHOUT pubkeys and signatures); `sighash` = txid. Every input signs the same digest with
  ECDSA/secp256k1; the pubkey must hash to the spent output's address hash.
- Address hash = first 20 bytes of H(pubkey64). Outputs of value 0 are invalid; sum(outputs) <= sum(inputs).
- Relay policy (not consensus): fee >= 100 units per serialized byte; mempool <= 5000 txs / 10 MB.

## Addresses
- Base58Check: `prefix(1) | hash(20) | H(prefix|hash)[0..4]`, prefix per network (`pubkey_prefix`).
- Bech32 (BIP173): hrp (`bech32_hrp`) + data `[0] + 20-byte hash` in 5-bit groups. Note: testnet3, testnet4 and signet
  share the hrp `rx`.

## P2P (TCP)
Frame: `magic[4] | command[12, NUL padded] | length u32 | H(payload)[0..4] | payload` (max payload 2,000,000).
Commands: `version` (best height u32 | listen port u16 | nonce u64; the last two are optional and the nonce detects
self-connections; must be the first message), `ping`, `getblock` (height u32), `getblk` (hash), `block` (serialized
block), `tx` (serialized tx), `getaddr` (empty) and `addr` (count u16 | count x [ip 16 bytes IPv6-mapped | port u16 |
last_seen u32], at most 100). An `addr` message is accepted only as the answer to our own `getaddr`, and a peer
answers `getaddr` once per connection.

Peer discovery: addresses come from `--seed`, `<datadir>/seeds.txt`, `--connect`, inbound peers' advertised listen port
and `addr` replies. They are kept in a bucketed address manager (`src/addrman.rs`):
- `new` table (1024 buckets x 64 slots) for heard-of addresses, `tried` table (256 x 64) for addresses we connected to.
- Bucket and slot come from SHA-256(secret key | ...), the key is random and stored in `peers.dat`.
  New bucket = H(key, group(source), H(key, group(addr), group(source)) mod 64) mod 1024, so one announcing network
  group reaches at most 64 new buckets. Tried bucket = H(key, group(addr), H(key, addr) mod 8) mod 256, so one /16
  reaches at most 8 tried buckets. A slot held by a healthy address is never overwritten by a newcomer; a successful
  connection moves an address to `tried` and demotes any previous occupant back to `new`.
- Dialing: 8 outbound connections, 50% from `tried`, 50% from `new`, preferring unused network groups, 10-minute
  retry delay, no retries after 5 failures (new entries). `getaddr` replies carry at most 23% of the book (max 100).
- Anchors: the two longest-lived outbound peers are written to `anchors.dat` (every 2 minutes and on shutdown) and are
  dialed first at the next start; the file is deleted when read.

## Storage
`blocks.dat`: repeated `length u32 | block` (active chain, rewritten after a reorg).
`wallet.dat`: see `src/wallet.rs` (plain hex lines, or `RYLWAL01` Argon2id + ChaCha20-Poly1305 file).
