//! Minimal JSON-RPC over HTTP, bound to 127.0.0.1 only and protected by a cookie token
//! (`<datadir>/.cookie`, header `Authorization: Bearer <token>`).
use crate::address::{decode_any, encode_address, encode_bech32};
use crate::block::rev_hex;
use crate::node::*;
use crate::params::*;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

static ACTIVE_RPC: AtomicUsize = AtomicUsize::new(0);
const MAX_RPC_CONNS: usize = 16;

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
fn q(s: &str) -> String {
    format!("\"{}\"", esc(s))
}

pub fn json_str(body: &str, key: &str) -> Option<String> {
    let k = format!("\"{}\"", key);
    let i = body.find(&k)? + k.len();
    let rest = &body[i..];
    let c = rest.find(':')?;
    let rest = rest[c + 1..].trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Parses the "params" array: quoted strings (with escapes) and bare values, e.g. numbers.
pub fn json_params(body: &str) -> Vec<String> {
    let i = match body.find("\"params\"") {
        Some(i) => i + 8,
        None => return vec![],
    };
    let rest = &body[i..];
    let rest = match rest.find('[') {
        Some(a) => &rest[a + 1..],
        None => return vec![],
    };
    let mut out = Vec::new();
    let mut chars = rest.chars().peekable();
    loop {
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() || c == ',' {
                chars.next();
            } else {
                break;
            }
        }
        let c = chars.peek().copied();
        match c {
            None | Some(']') => break,
            Some('"') => {
                chars.next();
                let mut s = String::new();
                while let Some(ch) = chars.next() {
                    match ch {
                        '"' => break,
                        '\\' => match chars.next() {
                            Some('n') => s.push('\n'),
                            Some('t') => s.push('\t'),
                            Some('r') => s.push('\r'),
                            Some('u') => {
                                let h: String = chars.by_ref().take(4).collect();
                                if let Ok(v) = u32::from_str_radix(&h, 16) {
                                    if let Some(c2) = char::from_u32(v) {
                                        s.push(c2);
                                    }
                                }
                            }
                            Some(o) => s.push(o),
                            None => break,
                        },
                        o => s.push(o),
                    }
                }
                out.push(s);
            }
            Some(_) => {
                let mut s = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch == ',' || ch == ']' {
                        break;
                    }
                    s.push(ch);
                    chars.next();
                }
                out.push(s.trim().to_string());
            }
        }
    }
    out
}

fn call(shared: &Shared, method: &str, params: &[String]) -> Result<String, String> {
    let p = |i: usize| params.get(i).cloned().ok_or_else(|| format!("missing parameter {}", i + 1));
    match method {
        "getblockcount" => Ok(shared.lock().unwrap().chain.height().to_string()),
        "getbestblockhash" => Ok(q(&shared.lock().unwrap().chain.tip().header.hash_hex())),
        "getblockhash" => {
            let h: usize = p(0)?.parse().map_err(|_| "bad height")?;
            let n = shared.lock().unwrap();
            n.chain.blocks.get(h).map(|b| q(&b.header.hash_hex())).ok_or("height out of range".to_string())
        }
        "getblock" => {
            let h: usize = p(0)?.parse().map_err(|_| "bad height")?;
            let n = shared.lock().unwrap();
            let b = n.chain.blocks.get(h).ok_or("height out of range")?;
            let txids: Vec<String> = b.txs.iter().map(|t| q(&rev_hex(&t.txid()))).collect();
            Ok(format!(
                "{{\"hash\":{},\"height\":{},\"time\":{},\"bits\":\"{:#010x}\",\"nonce\":{},\"previousblockhash\":{},\"tx\":[{}]}}",
                q(&b.header.hash_hex()), h, b.header.time, b.header.bits, b.header.nonce, q(&rev_hex(&b.header.prev)), txids.join(",")
            ))
        }
        "getinfo" => {
            let n = shared.lock().unwrap();
            Ok(format!(
                "{{\"chain\":{},\"blocks\":{},\"bestblockhash\":{},\"bits\":\"{:#010x}\",\"issued\":{},\"max_supply\":{},\"peers\":{},\"mempool\":{}}}",
                q(n.chain.net.name), n.chain.height(), q(&n.chain.tip().header.hash_hex()), n.chain.tip().header.bits,
                q(&fmt_coins(n.chain.issued)), q(&fmt_coins(MAX_MONEY)), n.peers.len(), n.mempool.len()
            ))
        }
        "getmempoolinfo" => Ok(format!("{{\"size\":{}}}", shared.lock().unwrap().mempool.len())),
        "getwalletinfo" => {
            let mut n = shared.lock().unwrap();
            n.wallet.tick();
            Ok(format!(
                "{{\"encrypted\":{},\"locked\":{},\"keys\":{}}}",
                n.wallet.is_encrypted(), n.wallet.locked(), n.wallet.keys.len()
            ))
        }
        "encryptwallet" => {
            let mut n = shared.lock().unwrap();
            n.wallet.encrypt(&p(0)?)?;
            Ok(q("wallet encrypted and locked; copies of the old plaintext wallet.dat may remain on storage - consider moving funds to a new address"))
        }
        "walletpassphrase" => {
            let secs: u64 = p(1)?.parse().map_err(|_| "bad seconds")?;
            let mut n = shared.lock().unwrap();
            n.wallet.unlock(&p(0)?, secs)?;
            Ok(q("unlocked"))
        }
        "walletlock" => {
            shared.lock().unwrap().wallet.lock();
            Ok(q("locked"))
        }
        "getnewaddress" => {
            let mut n = shared.lock().unwrap();
            let pkh = n.wallet.new_key()?;
            if params.first().map(|s| s == "bech32").unwrap_or(false) {
                Ok(q(&encode_bech32(n.chain.net, &pkh)))
            } else {
                Ok(q(&encode_address(n.chain.net, &pkh)))
            }
        }
        "listaddresses" => {
            let n = shared.lock().unwrap();
            let v: Vec<String> = n.wallet.keys.iter().map(|k| q(&encode_address(n.chain.net, &k.pkh))).collect();
            Ok(format!("[{}]", v.join(",")))
        }
        "getmininginfo" => {
            let n = shared.lock().unwrap();
            Ok(format!(
                "{{\"threads\":{},\"hashes\":{},\"hashrate\":{},\"blocks\":{},\"bits\":\"{:#010x}\",\"opens_in_secs\":{}}}",
                MINING_THREADS.load(std::sync::atomic::Ordering::Relaxed),
                HASHES.load(std::sync::atomic::Ordering::Relaxed),
                RATE.load(std::sync::atomic::Ordering::Relaxed),
                n.chain.height(),
                n.chain.tip().header.bits,
                n.chain.mining_opens_in().unwrap_or(0)
            ))
        }
        "listunspent" => {
            let n = shared.lock().unwrap();
            let tip = n.chain.height();
            let items: Vec<String> = n
                .wallet
                .unspent(&n.chain)
                .iter()
                .map(|u| {
                    format!(
                        "{{\"txid\":{},\"vout\":{},\"address\":{},\"amount\":{},\"height\":{},\"confirmations\":{},\"spendable\":{}}}",
                        q(&rev_hex(&u.op.0)), u.op.1, q(&encode_address(n.chain.net, &u.pkh)), q(&fmt_coins(u.value)),
                        u.height, tip - u.height + 1, u.spendable
                    )
                })
                .collect();
            Ok(format!("[{}]", items.join(",")))
        }
        "listtransactions" => {
            let count: usize = match params.first() {
                Some(s) => s.parse().map_err(|_| "bad count")?,
                None => 20,
            };
            let n = shared.lock().unwrap();
            let h = n.wallet.history(&n.chain);
            let start = h.len().saturating_sub(count);
            let items: Vec<String> = h[start..]
                .iter()
                .map(|e| {
                    let sign = if e.amount < 0 { "-" } else { "" };
                    format!(
                        "{{\"txid\":{},\"height\":{},\"category\":{},\"amount\":{}}}",
                        q(&rev_hex(&e.txid)), e.height, q(e.category), q(&format!("{}{}", sign, fmt_coins(e.amount.unsigned_abs())))
                    )
                })
                .collect();
            Ok(format!("[{}]", items.join(",")))
        }
        "sendmany" => {
            if params.is_empty() || params.len() % 2 != 0 {
                return Err("usage: sendmany ADDR AMOUNT [ADDR AMOUNT ...]".into());
            }
            let mut n = shared.lock().unwrap();
            n.wallet.tick();
            let mut dests: Vec<([u8; 20], u64)> = Vec::new();
            for pair in params.chunks(2) {
                let to = decode_any(n.chain.net, &pair[0]).ok_or("bad address")?;
                let amt = parse_coins(&pair[1]).ok_or("bad amount")?;
                dests.push((to, amt));
            }
            let exclude = n.mempool_spent();
            let tx = n.wallet.create_tx_multi(&n.chain, &dests, DEFAULT_FEE, &exclude)?;
            let id = n.submit_tx(tx, None)?;
            Ok(q(&rev_hex(&id)))
        }
        "backupwallet" => {
            let n = shared.lock().unwrap();
            Ok(q(&n.wallet.backup(&p(0)?)?))
        }
        "getpeerinfo" => {
            let n = shared.lock().unwrap();
            let items: Vec<String> = n
                .peers
                .iter()
                .map(|p| {
                    let addr = match p.addr {
                        Some(a) => q(&a.to_string()),
                        None => "null".to_string(),
                    };
                    format!("{{\"id\":{},\"ip\":{},\"addr\":{},\"inbound\":{},\"score\":{},\"connected_secs\":{}}}",
                        p.id, q(&p.ip.to_string()), addr, p.inbound, p.score, p.since.elapsed().as_secs())
                })
                .collect();
            Ok(format!("[{}]", items.join(",")))
        }
        "getaddrmaninfo" => {
            let n = shared.lock().unwrap();
            let (new, tried) = n.addrs.counts();
            Ok(format!("{{\"new\":{},\"tried\":{}}}", new, tried))
        }
        "getnodeaddresses" => {
            let n = shared.lock().unwrap();
            let items: Vec<String> = n
                .addrs
                .all()
                .iter()
                .take(100)
                .map(|(a, ts, tried)| format!("{{\"address\":{},\"last_seen\":{},\"tried\":{}}}", q(&a.to_string()), ts, tried))
                .collect();
            Ok(format!("[{}]", items.join(",")))
        }
        "getbalance" => {
            let n = shared.lock().unwrap();
            Ok(q(&fmt_coins(n.wallet.balance(&n.chain))))
        }
        "sendtoaddress" => {
            let addr = p(0)?;
            let amount = parse_coins(&p(1)?).ok_or("bad amount")?;
            let mut n = shared.lock().unwrap();
            n.wallet.tick();
            let to = decode_any(n.chain.net, &addr).ok_or("bad address")?;
            let exclude = n.mempool_spent();
            let tx = n.wallet.create_tx(&n.chain, to, amount, DEFAULT_FEE, &exclude)?;
            let id = n.submit_tx(tx, None)?;
            Ok(q(&rev_hex(&id)))
        }
        "generate" => {
            if shared.lock().unwrap().chain.net.name != "regtest" {
                return Err("generate is only available on regtest; use node --mine".into());
            }
            let count: u32 = p(0)?.parse().map_err(|_| "bad count")?;
            if count == 0 || count > 1000 {
                return Err("count must be 1..1000".into());
            }
            let pkh = {
                let mut n = shared.lock().unwrap();
                let first = n.wallet.keys.first().map(|k| k.pkh);
                match first {
                    Some(p) => p,
                    None => n.wallet.new_key()?,
                }
            };
            let mut hashes = Vec::new();
            for _ in 0..count {
                match mine_one(shared, pkh, &|| true) {
                    Some(h) => hashes.push(q(&h)),
                    None => break,
                }
            }
            Ok(format!("[{}]", hashes.join(",")))
        }
        "addnode" => {
            connect(shared.clone(), &p(0)?)?;
            Ok("true".into())
        }
        "stop" => {
            shared.lock().unwrap().stop = true;
            Ok(q("stopping"))
        }
        _ => Err("unknown method".into()),
    }
}

fn respond(s: &mut TcpStream, status: &str, body: &str) {
    let r = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status, body.len(), body
    );
    let _ = s.write_all(r.as_bytes());
}

fn handle_conn(shared: Shared, mut s: TcpStream, token: String) {
    let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let n = match s.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > 65_536 {
            return;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut clen = 0usize;
    let mut auth = String::new();
    for line in head.lines() {
        let low = line.to_lowercase();
        if let Some(v) = low.strip_prefix("content-length:") {
            clen = v.trim().parse().unwrap_or(0);
        } else if low.starts_with("authorization:") {
            auth = line[line.find(':').unwrap() + 1..].trim().to_string();
        }
    }
    if clen > 1_000_000 {
        return;
    }
    while buf.len() < header_end + clen {
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    if auth != format!("Bearer {}", token) {
        respond(&mut s, "401 Unauthorized", "{\"result\":null,\"error\":\"unauthorized\",\"id\":1}");
        return;
    }
    let body = String::from_utf8_lossy(&buf[header_end..header_end + clen]).to_string();
    let method = json_str(&body, "method").unwrap_or_default();
    let params = json_params(&body);
    let out = match call(&shared, &method, &params) {
        Ok(r) => format!("{{\"result\":{},\"error\":null,\"id\":1}}", r),
        Err(e) => format!("{{\"result\":null,\"error\":{},\"id\":1}}", q(&e)),
    };
    respond(&mut s, "200 OK", &out);
}

pub fn start_rpc(shared: Shared, port: u16, token: String) -> Result<(), String> {
    let l = TcpListener::bind(("127.0.0.1", port)).map_err(|e| format!("rpc bind 127.0.0.1:{}: {}", port, e))?;
    thread::spawn(move || {
        for s in l.incoming().flatten() {
            if ACTIVE_RPC.load(Ordering::SeqCst) >= MAX_RPC_CONNS {
                continue; // too many concurrent RPC clients: drop the connection
            }
            ACTIVE_RPC.fetch_add(1, Ordering::SeqCst);
            let sh = shared.clone();
            let t = token.clone();
            thread::spawn(move || {
                handle_conn(sh, s, t);
                ACTIVE_RPC.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    Ok(())
}

/// Client used by `riyalcoin cli`.
pub fn client(port: u16, token: &str, method: &str, params: &[String]) -> Result<String, String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("cannot connect to node: {}", e))?;
    let ps: Vec<String> = params.iter().map(|x| q(x)).collect();
    let body = format!("{{\"method\":{},\"params\":[{}],\"id\":1}}", q(method), ps.join(","));
    let req = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        token, body.len(), body
    );
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut resp = String::new();
    s.read_to_string(&mut resp).map_err(|e| e.to_string())?;
    Ok(resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_parse() {
        let b = r#"{"method":"x","params":["a,b","c\"d",12, "e"],"id":1}"#;
        assert_eq!(json_params(b), vec!["a,b", "c\"d", "12", "e"]);
        assert_eq!(json_params(r#"{"params":[]}"#), Vec::<String>::new());
        assert_eq!(json_str(r#"{"method":"getinfo"}"#, "method"), Some("getinfo".to_string()));
    }
}
