use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine as _};
use sha2::{Digest, Sha256};

pub fn derive_key(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(b"github-c2-salt-v1");
    hasher.finalize().into()
}

pub fn encrypt(plaintext: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key = derive_key(password);
    let cipher = Aes256Gcm::new(&key.into());
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encryption failed: {:?}", e))?;
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(general_purpose::STANDARD.encode(&result))
}

pub fn decrypt(encrypted: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key = derive_key(password);
    let cipher = Aes256Gcm::new(&key.into());
    let data = general_purpose::STANDARD.decode(encrypted)?;
    if data.len() < 12 {
        return Err("Data too short".into());
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {:?}", e))?;
    Ok(String::from_utf8(plaintext)?)
}
