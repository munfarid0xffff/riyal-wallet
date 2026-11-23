//! secp256k1 ECDSA through the RustCrypto `k256` crate: constant-time field/scalar arithmetic,
//! RFC 6979 deterministic nonces, OS randomness (works on Linux, Android, macOS and Windows).
//! The hand-written implementation was removed because it was not constant-time.
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::rand_core::OsRng;
use k256::FieldBytes;

/// 32 random bytes from the OS, valid as a secp256k1 secret.
pub fn random_secret() -> Option<[u8; 32]> {
    let sk = SigningKey::random(&mut OsRng);
    let b: [u8; 32] = sk.to_bytes().into();
    Some(b)
}

/// Public key as raw x||y (64 bytes).
pub fn pubkey(secret: &[u8; 32]) -> Option<[u8; 64]> {
    let sk = SigningKey::from_bytes(FieldBytes::from_slice(secret)).ok()?;
    let ep = sk.verifying_key().to_encoded_point(false);
    let bytes = ep.as_bytes();
    if bytes.len() != 65 || bytes[0] != 4 {
        return None;
    }
    let mut o = [0u8; 64];
    o.copy_from_slice(&bytes[1..]);
    Some(o)
}

/// ECDSA signature over a 32-byte digest, returned as r||s (64 bytes, low-s).
pub fn sign(secret: &[u8; 32], msg: &[u8; 32]) -> Option<[u8; 64]> {
    let sk = SigningKey::from_bytes(FieldBytes::from_slice(secret)).ok()?;
    let sig: Signature = sk.sign_prehash(msg).ok()?;
    let sig = sig.normalize_s().unwrap_or(sig);
    let b = sig.to_bytes();
    let mut o = [0u8; 64];
    o.copy_from_slice(&b);
    Some(o)
}

/// Verify; `pubkey` is raw x||y. Rejects points that are not on the curve.
pub fn verify(pubkey: &[u8], msg: &[u8; 32], sig: &[u8]) -> bool {
    if pubkey.len() != 64 || sig.len() != 64 {
        return false;
    }
    let mut sec1 = [0u8; 65];
    sec1[0] = 4;
    sec1[1..].copy_from_slice(pubkey);
    let vk = match VerifyingKey::from_sec1_bytes(&sec1) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let s = match Signature::from_slice(sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify_prehash(msg, &s).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;
    use crate::sha256::sha256;

    fn key(n: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[31] = n;
        k
    }

    #[test]
    fn known_public_keys() {
        let p1 = pubkey(&key(1)).unwrap();
        assert_eq!(hex::encode(&p1[..32]), "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let p2 = pubkey(&key(2)).unwrap();
        assert_eq!(hex::encode(&p2[..32]), "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sk = random_secret().unwrap();
        let pk = pubkey(&sk).unwrap();
        let msg = sha256(b"riyalcoin");
        let sig = sign(&sk, &msg).unwrap();
        assert!(verify(&pk, &msg, &sig));
        assert!(!verify(&pk, &sha256(b"riyalcoin!"), &sig));
        let mut bad = sig;
        bad[40] ^= 1;
        assert!(!verify(&pk, &msg, &bad));
        // off-curve key must be rejected
        let mut bad_pk = pk;
        bad_pk[63] ^= 1;
        assert!(!verify(&bad_pk, &msg, &sig));
    }

    #[test]
    fn deterministic_signatures() {
        let sk = key(7);
        let msg = sha256(b"x");
        assert_eq!(sign(&sk, &msg), sign(&sk, &msg));
    }
}
