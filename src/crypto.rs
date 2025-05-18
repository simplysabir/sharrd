use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Encrypted data with metadata required for decryption
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedData {
    /// Base64-encoded ciphertext
    pub ciphertext: String,
    /// Base64-encoded nonce
    pub nonce: String,
    /// Base64-encoded salt used for key derivation
    pub salt: String,
}

/// Wrapper for handling sensitive data like passwords
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct SecretString {
    inner: String,
}

impl SecretString {
    /// Create a new SecretString
    pub fn new(value: String) -> Self {
        Self { inner: value }
    }
    
    /// Get a reference to the inner value
    pub fn as_str(&self) -> &str {
        &self.inner
    }
    
    /// Convert to bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self::new(s.to_string())
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

/// Encrypt data using AES-GCM with a password-derived key
pub fn encrypt(data: &[u8], password: &SecretString) -> Result<EncryptedData> {
    // Generate a random salt
    let salt = SaltString::generate(&mut OsRng);
    
    // Derive key from password
    let argon2 = Argon2::default();
    let mut key = [0u8; 32]; // AES-256 key
    argon2.hash_password_into(
        password.as_bytes(),
        salt.as_salt().as_ref().as_bytes(),
        &mut key,
    ).map_err(|e| anyhow!("Key derivation failed: {}", e))?;
    
    // Create cipher with the derived key
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;
    
    // Generate nonce
    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt the data
    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;
    
    // Base64 encode for storage
    let ciphertext_b64 = general_purpose::STANDARD.encode(&ciphertext);
    let nonce_b64 = general_purpose::STANDARD.encode(nonce);
    let salt_b64 = salt.as_str().to_string();
    
    // Zero out sensitive data
    key.zeroize();
    
    Ok(EncryptedData {
        ciphertext: ciphertext_b64,
        nonce: nonce_b64,
        salt: salt_b64,
    })
}

/// Decrypt data using AES-GCM with a password-derived key
pub fn decrypt(encrypted: &EncryptedData, password: &SecretString) -> Result<Vec<u8>> {
    // Decode base64 values
    let ciphertext = general_purpose::STANDARD.decode(&encrypted.ciphertext)
        .context("Failed to decode ciphertext")?;
    let nonce_bytes = general_purpose::STANDARD.decode(&encrypted.nonce)
        .context("Failed to decode nonce")?;
    
    // Derive key from password using the stored salt
    let argon2 = Argon2::default();
    let salt = SaltString::from_b64(&encrypted.salt)
        .map_err(|e| anyhow!("Invalid salt: {}", e))?;
    
    let mut key = [0u8; 32]; // AES-256 key
    argon2.hash_password_into(
        password.as_bytes(),
        salt.as_salt().as_ref().as_bytes(),
        &mut key,
    ).map_err(|e| anyhow!("Key derivation failed: {}", e))?;
    
    // Create cipher with the derived key
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;
    
    // Create nonce from decoded bytes
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Decrypt the data
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow!("Decryption failed. Incorrect password?"))?;
    
    // Zero out sensitive data
    key.zeroize();
    
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypt_decrypt() {
        let data = b"test data for encryption";
        let password = SecretString::from("test password");
        
        let encrypted = encrypt(data, &password).unwrap();
        let decrypted = decrypt(&encrypted, &password).unwrap();
        
        assert_eq!(data, decrypted.as_slice());
    }
    
    #[test]
    fn test_wrong_password() {
        let data = b"test data for encryption";
        let password = SecretString::from("correct password");
        let wrong_password = SecretString::from("wrong password");
        
        let encrypted = encrypt(data, &password).unwrap();
        let result = decrypt(&encrypted, &wrong_password);
        
        assert!(result.is_err());
    }
    
    #[test]
    fn test_secret_string_zeroize() {
        let secret = SecretString::from("sensitive data");
        let ptr = secret.inner.as_ptr();
        let len = secret.inner.len();
        
        // Zeroize happens implicitly when dropped
        drop(secret);
        
        // We can't directly check if memory is zeroed due to Rust's safety guarantees,
        // but this tests that the Zeroize trait is implemented
    }
}