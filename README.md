# RiyalCoin

SHA-256 proof-of-work blockchain in Rust, **fixed supply 12,000,000 RiyalCoin**. Consensus code is std-only; crypto uses audited RustCrypto crates (k256, argon2, chacha20poly1305, zeroize).

- Smallest unit: millipiaster = 1e-11 (`COIN = 10^11`); reward 25, halving every 240,000 blocks
- `MAX_MONEY` enforced on every block; fees are recirculated, never minted
- Networks (ports, magic, prefixes, genesis) from `RiyalCoin.txt`; all 5 genesis hashes are verified by tests
- secp256k1 ECDSA (own implementation), UTXO set, coinbase maturity (100; regtest 2), 2016-block retarget
  (not on regtest/signet), Base58Check addresses (net prefix from RiyalCoin.txt)
- P2P (framed messages: version/getblock/block/tx), mempool, mining, JSON-RPC (127.0.0.1 + cookie token),
  wallet.dat (hex secrets, mode 0600), blocks.dat storage

## Build and test (needs internet for the first build: it downloads the crates)
    cargo test
    cargo build --release

## Features
Mining (`--mine --threads=N`, `getmininginfo`), wallet history (`listunspent`, `listtransactions`), multi-recipient
payments (`sendmany ADDR AMT ADDR AMT ...`), bech32 addresses (`getnewaddress bech32`, both formats accepted when
sending), `backupwallet /absolute/path`, wallet encryption, see PROTOCOL.md for the wire/consensus format.

## Peer discovery
Mainnet/testnets/signet discover peers automatically (8 outbound connections). Give the node a starting point once:
`--seed=seed.example.org:19921` (DNS names may return many addresses) or list `host:port` lines in `<datadir>/seeds.txt`;
afterwards `peers.dat` is enough. Regtest does not discover unless you pass `--discover`; use `--allowlocal` to let a
LAN-only test network exchange private addresses. Inspect with `getpeerinfo`, `getaddrmaninfo` and `getnodeaddresses`. The address book is bucketed like Bitcoin's
(new/tried tables, secret-keyed placement) and the two longest-lived outbound peers are kept as anchors across restarts.
There are no built-in seeds yet: whoever launches the network must run public seed nodes and publish them.

## Run (regtest example)
    ./target/release/riyalcoin node --net=regtest --mine
    ./target/release/riyalcoin cli --net=regtest getnewaddress
    ./target/release/riyalcoin cli --net=regtest generate 5
    ./target/release/riyalcoin cli --net=regtest getbalance
    ./target/release/riyalcoin cli --net=regtest sendtoaddress <addr> 1.5
    ./target/release/riyalcoin cli --net=regtest getinfo

Two nodes on one device (regtest):

    ./target/release/riyalcoin node --net=regtest --datadir=$HOME/n1
    ./target/release/riyalcoin node --net=regtest --datadir=$HOME/n2 --p2pport=29929 --rpcport=29930 --connect=127.0.0.1:19929
    ./target/release/riyalcoin cli --net=regtest --datadir=$HOME/n2 --rpcport=29930 getinfo

## Security status (self-review, NOT an independent audit)
- Crypto: secp256k1 ECDSA via RustCrypto `k256` (constant-time arithmetic, RFC 6979); wallet encryption with
  Argon2id + ChaCha20-Poly1305 (`encryptwallet`, `walletpassphrase`, `walletlock`); secrets zeroized on lock/drop.
  Build with `cargo build --release --locked` after committing Cargo.lock, and run `cargo audit`.
- Wallet: encrypted file keeps addresses readable while locked; a damaged wallet.dat is an error, never replaced;
  writes are atomic; passphrases are typed at a hidden prompt by `cli`, never put on the command line.
- DoS: per-peer misbehaviour score and 24h IP bans, inbound/per-IP connection caps, handshake and idle timeouts,
  per-peer rate limits, bounded outgoing queues with writer threads (no network I/O under the node lock),
  signature verification done outside the node lock (with a cache), relay-fee floor, mempool and side-branch size
  caps, RPC connection cap.
- Consensus: coinbase must commit to height, no UTXO overwrite, block time <= wall clock + 2h on retargeting networks.
- Launch gate: before the network opens (genesis timestamp minus 2 h) `--mine` pauses with a message and nodes reject
  early blocks. This protects honest software only: a patched node can still mine a private chain in advance and
  publish it later, which no protocol rule can fully prevent. Publish a checkpoint (height + hash) after launch and
  announce the launch time, so everyone can verify they follow the same chain.
- Still open: no median-time-past rule, no peer discovery/addr relay (eclipse risk), unencrypted blocks.dat metadata,
  no formal fuzzing, and the whole project still needs an independent audit before any real-value use.

## Known limits (be honest before mainnet)
- Chain reorganisation: heaviest-work chain wins (work estimate in `bits_work`), side branches kept in memory only (max 10,000 blocks), undo data kept for the whole chain; no checkpoints or max reorg depth yet
- Address hash is truncated double-SHA256 (not RIPEMD160); bech32 not implemented (hrp kept in params)
- Discovery has eclipse defences (solicited addr only, bucketed address manager, group diversity, anchors) but is a
  simplified version of Bitcoin's: one slot per address, no test-before-evict, anchors are normal full-relay peers (no
  block-relay-only mode), no feeler connections, and no built-in seed list
- Mainnet/testnet genesis blocks carry no transaction (header values from the spec); the genesis reward is unspendable
- Never run on mainnet with real funds before an independent security review
