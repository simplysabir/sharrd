use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::config::Config;
use crate::crypto::{self, EncryptedData, SecretString};
use crate::mnemonic::{self, MemorableWord};
use crate::shamir::{self, Share};

/// Type of the seed phrase
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum SeedPhraseType {
    /// 12-word seed phrase
    Words12,
    /// 24-word seed phrase
    Words24,
    /// Custom length seed phrase
    Custom,
}

/// Metadata about a stored secret
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecretMetadata {
    /// Name/identifier of the secret
    pub name: String,
    /// Type of the seed phrase
    pub phrase_type: SeedPhraseType,
    /// Total number of shares created
    pub total_shares: usize,
    /// Number of shares needed to reconstruct the secret
    pub threshold: usize,
    /// Date created (ISO 8601 format)
    pub created_at: String,
    /// Optional description 
    pub description: Option<String>,
    /// Whether access to this secret requires admin password
    pub protected: bool,
    /// Whether this secret uses memorable shares
    pub memorable_shares: bool,
}

/// A secret seed phrase that has been split into shares
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredSecret {
    /// Metadata about the secret
    pub metadata: SecretMetadata,
    /// Encrypted shares (each entry is a single share)
    pub shares: Vec<EncryptedData>,
}

impl Drop for StoredSecret {
    fn drop(&mut self) {
        // Metadata is automatically zeroized due to #[zeroize(drop)]
        // The EncryptedData doesn't need zeroizing because it's already encrypted
    }
}

/// A share ID with format information for display
#[derive(Debug, Clone)]
pub struct ShareInfo {
    /// Share ID (1-255)
    pub id: u8,
    /// Total number of shares
    pub total: usize,
    /// Threshold required to reconstruct
    pub threshold: usize,
    /// Secret name this share belongs to
    pub secret_name: String,
}

/// Main storage manager for Shard
pub struct Storage {
    config: Config,
    master_password: Option<SecretString>,
}

impl Storage {
    /// Create a new storage manager 
    pub fn new(config: Config) -> Self {
        Self {
            config,
            master_password: None,
        }
    }
    
    /// Set the master password
    pub fn set_master_password(&mut self, password: SecretString) {
        self.master_password = Some(password);
    }
    
    /// Get the master password or prompt if needed
    fn get_master_password(&self) -> Result<SecretString> {
        if let Some(ref pwd) = self.master_password {
            Ok(pwd.clone())
        } else if self.config.use_password {
            // Prompt for password
            let password = dialoguer::Password::new()
                .with_prompt("Enter master password")
                .interact()?;
            
            Ok(SecretString::new(password))
        } else {
            // Use empty password if not configured
            Ok(SecretString::from(""))
        }
    }
    
    /// Get the directory path for a secret
    fn secret_dir(&self, name: &str) -> PathBuf {
        self.config.storage_dir.join("secrets").join(name)
    }
    
    /// Get the metadata file path for a secret
    fn metadata_path(&self, name: &str) -> PathBuf {
        self.secret_dir(name).join("metadata.json")
    }
    
    /// Get the shares directory path for a secret
    fn shares_dir(&self, name: &str) -> PathBuf {
        self.secret_dir(name).join("shares")
    }
    
    /// List all stored secrets
    pub fn list_secrets(&self) -> Result<Vec<SecretMetadata>> {
        let secrets_dir = self.config.storage_dir.join("secrets");
        
        if !secrets_dir.exists() {
            return Ok(Vec::new());
        }
        
        let entries = fs::read_dir(secrets_dir)?;
        let mut secrets = Vec::new();
        
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                
                let metadata_path = self.metadata_path(&name);
                if metadata_path.exists() {
                    let content = fs::read_to_string(metadata_path)?;
                    let metadata: SecretMetadata = serde_json::from_str(&content)?;
                    secrets.push(metadata);
                }
            }
        }
        
        Ok(secrets)
    }
    
    /// Create a new secret using traditional Shamir shares
    pub fn create_secret(
        &self,
        name: &str,
        seed_words: Vec<String>,
        phrase_type: SeedPhraseType,
        shares: usize,
        threshold: usize,
        description: Option<String>,
        protected: bool,
    ) -> Result<()> {
        // Check if secret already exists
        if self.metadata_path(name).exists() {
            return Err(anyhow!("Secret with name '{}' already exists", name));
        }
        
        // Validate words
        if seed_words.is_empty() {
            return Err(anyhow!("Seed phrase cannot be empty"));
        }
        
        // Join words with spaces and convert to bytes
        let seed_phrase = seed_words.join(" ");
        let secret_bytes = seed_phrase.as_bytes();
        
        // Get master password
        let master_password = self.get_master_password()?;
        
        // Split the secret using Shamir's Secret Sharing
        let raw_shares = shamir::split(secret_bytes, shares, threshold, None)?;
        
        // Encrypt each share
        let mut encrypted_shares = Vec::with_capacity(shares);
        for share in raw_shares {
            // Serialize the share
            let share_bytes = bincode::serialize(&share)?;
            
            // Encrypt with master password
            let encrypted = crypto::encrypt(&share_bytes, &master_password)?;
            encrypted_shares.push(encrypted);
        }
        
        // Create metadata
        let metadata = SecretMetadata {
            name: name.to_string(),
            phrase_type,
            total_shares: shares,
            threshold,
            created_at: chrono::Utc::now().to_rfc3339(),
            description,
            protected,
            memorable_shares: false,
        };
        
        // Create stored secret
        let stored_secret = StoredSecret {
            metadata: metadata.clone(),
            shares: encrypted_shares,
        };
        
        // Create directory structure
        let secret_dir = self.secret_dir(name);
        fs::create_dir_all(&secret_dir)?;
        
        let shares_dir = self.shares_dir(name);
        fs::create_dir_all(&shares_dir)?;
        
        // Write metadata
        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        fs::write(self.metadata_path(name), metadata_json)?;
        
        // Write encrypted shares
        let stored_secret_json = serde_json::to_string_pretty(&stored_secret)?;
        fs::write(secret_dir.join("shares.json"), stored_secret_json)?;
        
        // Zero out sensitive data
        let mut seed_phrase = seed_phrase;
        seed_phrase.zeroize();
        
        Ok(())
    }
    
    /// Create a new secret with memorable words
    pub fn create_memorable_secret(
        &self,
        name: &str,
        seed_words: Vec<String>,
        phrase_type: SeedPhraseType,
        description: Option<String>,
        protected: bool,
    ) -> Result<Vec<MemorableWord>> {
        // Check if secret already exists
        if self.metadata_path(name).exists() {
            return Err(anyhow!("Secret with name '{}' already exists", name));
        }
        
        // Validate words
        if seed_words.is_empty() {
            return Err(anyhow!("Seed phrase cannot be empty"));
        }
        
        // Join words with spaces and convert to bytes
        let seed_phrase = seed_words.join(" ");
        let secret_bytes = seed_phrase.as_bytes();
        
        // Fixed values for memorable shares: 3 total, 2 needed
        let shares = 3;
        let threshold = 2;
        
        // Split the secret using Shamir's Secret Sharing
        let raw_shares = shamir::split(secret_bytes, shares, threshold, None)?;
        
        // Generate memorable words
        let mut memorable_words = Vec::with_capacity(shares);
        for (i, share) in raw_shares.iter().enumerate() {
            let memorable = mnemonic::generate_memorable_word(
                share.clone(), 
                i + 1
            )?;
            memorable_words.push(memorable);
        }
        
        // Store share data that can verify words later
        // Encrypted with master password for extra security if needed
        let master_password = self.get_master_password()?;
        
        // Encrypt raw shares for storage (with metadata but without words)
        let mut encrypted_share_data = Vec::with_capacity(shares);
        for share in &raw_shares {
            let share_bytes = bincode::serialize(share)?;
            let encrypted = crypto::encrypt(&share_bytes, &master_password)?;
            encrypted_share_data.push(encrypted);
        }
        
        // Create metadata
        let metadata = SecretMetadata {
            name: name.to_string(),
            phrase_type,
            total_shares: shares,
            threshold,
            created_at: chrono::Utc::now().to_rfc3339(),
            description,
            protected,
            memorable_shares: true,
        };
        
        // Create stored secret
        let stored_secret = StoredSecret {
            metadata: metadata.clone(),
            shares: encrypted_share_data,
        };
        
        // Create directory structure
        let secret_dir = self.secret_dir(name);
        fs::create_dir_all(&secret_dir)?;
        
        // Write metadata
        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        fs::write(self.metadata_path(name), metadata_json)?;
        
        // Write encrypted shares as JSON
        let stored_secret_json = serde_json::to_string_pretty(&stored_secret)?;
        fs::write(secret_dir.join("shares.json"), stored_secret_json)?;
        
        // Zero out sensitive data
        let mut seed_phrase = seed_phrase;
        seed_phrase.zeroize();
        
        Ok(memorable_words)
    }
    
    /// Access a secret with selected shares
    pub fn access_secret(
        &self,
        name: &str,
        provided_shares: &[usize],
    ) -> Result<Vec<String>> {
        // Check if secret exists
        let metadata_path = self.metadata_path(name);
        if !metadata_path.exists() {
            return Err(anyhow!("Secret with name '{}' does not exist", name));
        }
        
        // Read metadata
        let metadata_json = fs::read_to_string(metadata_path)?;
        let metadata: SecretMetadata = serde_json::from_str(&metadata_json)?;
        
        // Check if we have enough shares
        if provided_shares.len() < metadata.threshold {
            return Err(anyhow!(
                "Not enough shares provided. Need at least {} shares, got {}",
                metadata.threshold,
                provided_shares.len()
            ));
        }
        
        // Check if all requested shares are valid
        let max_share_id = metadata.total_shares;
        for &share_id in provided_shares {
            if share_id == 0 || share_id > max_share_id {
                return Err(anyhow!("Invalid share ID: {}", share_id));
            }
        }
        
        // Read stored secret
        let secret_dir = self.secret_dir(name);
        let stored_secret_json = fs::read_to_string(secret_dir.join("shares.json"))?;
        let stored_secret: StoredSecret = serde_json::from_str(&stored_secret_json)?;
        
        // Get master password
        let master_password = self.get_master_password()?;
        
        // Decrypt and collect shares
        let mut decrypted_shares = Vec::new();
        
        for &share_idx in provided_shares {
            // Shares are 1-indexed in the UI, 0-indexed in the storage
            let share_idx = share_idx - 1;
            
            if share_idx >= stored_secret.shares.len() {
                return Err(anyhow!("Share index out of bounds: {}", share_idx + 1));
            }
            
            let encrypted = &stored_secret.shares[share_idx];
            let share_bytes = crypto::decrypt(encrypted, &master_password)?;
            
            let share: Share = bincode::deserialize(&share_bytes)?;
            decrypted_shares.push(share);
        }
        
        // Combine shares to recover the original secret
        let recovered_bytes = shamir::combine(&decrypted_shares)?;
        
        // Convert bytes back to string
        let seed_phrase = String::from_utf8(recovered_bytes)
            .map_err(|_| anyhow!("Failed to decode recovered secret"))?;
        
        // Split into words
        let seed_words = seed_phrase.split_whitespace().map(String::from).collect();
        
        Ok(seed_words)
    }
    
    /// Access a memorable secret with provided words
    pub fn access_memorable_secret(
        &self,
        name: &str,
        words: &[String],
    ) -> Result<Vec<String>> {
        // Check if secret exists
        let metadata_path = self.metadata_path(name);
        if !metadata_path.exists() {
            return Err(anyhow!("Secret with name '{}' does not exist", name));
        }
        
        // Read metadata
        let metadata_json = fs::read_to_string(metadata_path)?;
        let metadata: SecretMetadata = serde_json::from_str(&metadata_json)?;
        
        // Verify this is a memorable share secret
        if !metadata.memorable_shares {
            return Err(anyhow!("Secret '{}' is not using memorable words", name));
        }
        
        // Check if we have enough words
        if words.len() < metadata.threshold {
            return Err(anyhow!(
                "Not enough words provided. Need at least {} words, got {}",
                metadata.threshold,
                words.len()
            ));
        }
        
        // Get master password
        let master_password = self.get_master_password()?;
        
        // Read stored shares for verification
        let secret_dir = self.secret_dir(name);
        let stored_secret_json = fs::read_to_string(secret_dir.join("shares.json"))?;
        let stored_secret: StoredSecret = serde_json::from_str(&stored_secret_json)?;
        
        // Decrypt shares for verification
        let mut original_shares = Vec::with_capacity(stored_secret.shares.len());
        for encrypted in &stored_secret.shares {
            let share_bytes = crypto::decrypt(encrypted, &master_password)?;
            let share: Share = bincode::deserialize(&share_bytes)?;
            original_shares.push(share);
        }
        
        // Try to recover shares from words
        let mut recovered_shares = Vec::with_capacity(words.len());
        for word in words {
            match mnemonic::recover_share_from_word(word, &original_shares) {
                Ok(share) => {
                    recovered_shares.push(share);
                }
                Err(e) => {
                    return Err(anyhow!("Invalid word '{}': {}", word, e));
                }
            }
        }
        
        // Check if we have enough valid shares
        if recovered_shares.len() < metadata.threshold {
            return Err(anyhow!(
                "Not enough valid words. Need at least {} valid words, got {}",
                metadata.threshold,
                recovered_shares.len()
            ));
        }
        
        // Combine shares to recover the original secret
        let recovered_bytes = shamir::combine(&recovered_shares[0..metadata.threshold])?;
        
        // Convert bytes back to string
        let seed_phrase = String::from_utf8(recovered_bytes)
            .map_err(|_| anyhow!("Failed to decode recovered secret"))?;
        
        // Split into words
        let seed_words = seed_phrase.split_whitespace().map(String::from).collect();
        
        Ok(seed_words)
    }
    
    /// Delete a secret
    pub fn delete_secret(&self, name: &str, admin_pw: Option<&SecretString>) -> Result<()> {
        // Check if secret exists
        let metadata_path = self.metadata_path(name);
        if !metadata_path.exists() {
            return Err(anyhow!("Secret with name '{}' does not exist", name));
        }
        
        // Read metadata
        let metadata_json = fs::read_to_string(&metadata_path)?;
        let metadata: SecretMetadata = serde_json::from_str(&metadata_json)?;
        
        // If secret is protected, require admin password
        if metadata.protected {
            let password = match admin_pw {
                Some(pw) => pw.clone(),
                None => {
                    // Prompt for admin password
                    let password = dialoguer::Password::new()
                        .with_prompt("Enter admin password to delete protected secret")
                        .interact()?;
                    
                    SecretString::new(password)
                }
            };
            
            // Verify password by trying to decrypt any share
            let secret_dir = self.secret_dir(name);
            let stored_secret_json = fs::read_to_string(secret_dir.join("shares.json"))?;
            let stored_secret: StoredSecret = serde_json::from_str(&stored_secret_json)?;
            
            if !stored_secret.shares.is_empty() {
                let encrypted = &stored_secret.shares[0];
                let _ = crypto::decrypt(encrypted, &password)
                    .map_err(|_| anyhow!("Incorrect admin password"))?;
            }
        }
        
        // Delete the secret directory
        let secret_dir = self.secret_dir(name);
        fs::remove_dir_all(secret_dir)?;
        
        Ok(())
    }
    
    /// Export shares for a secret
    pub fn export_shares(&self, name: &str) -> Result<Vec<ShareInfo>> {
        // Check if secret exists
        let metadata_path = self.metadata_path(name);
        if !metadata_path.exists() {
            return Err(anyhow!("Secret with name '{}' does not exist", name));
        }
        
        // Read metadata
        let metadata_json = fs::read_to_string(metadata_path)?;
        let metadata: SecretMetadata = serde_json::from_str(&metadata_json)?;
        
        // Read stored secret
        let secret_dir = self.secret_dir(name);
        let stored_secret_json = fs::read_to_string(secret_dir.join("shares.json"))?;
        let stored_secret: StoredSecret = serde_json::from_str(&stored_secret_json)?;
        
        // Get master password
        let master_password = self.get_master_password()?;
        
        // Decrypt shares to get information
        let mut share_infos = Vec::new();
        
        for (i, encrypted) in stored_secret.shares.iter().enumerate() {
            let share_bytes = crypto::decrypt(encrypted, &master_password)?;
            let share: Share = bincode::deserialize(&share_bytes)?;
            
            share_infos.push(ShareInfo {
                id: i as u8 + 1, // 1-indexed for users
                total: metadata.total_shares,
                threshold: metadata.threshold,
                secret_name: metadata.name.clone(),
            });
        }
        
        Ok(share_infos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    fn create_test_config() -> Config {
        let temp_dir = tempdir().unwrap();
        Config {
            storage_dir: temp_dir.path().to_path_buf(),
            default_shares: 3,
            default_threshold: 2,
            use_password: false,
        }
    }
    
    #[test]
    fn test_create_and_access_secret() {
        let config = create_test_config();
        let storage = Storage::new(config);
        
        // Create test seed phrase
        let seed_words = vec![
            "abandon".to_string(), "ability".to_string(), "able".to_string(),
            "about".to_string(), "above".to_string(), "absent".to_string(),
            "absorb".to_string(), "abstract".to_string(), "absurd".to_string(),
            "abuse".to_string(), "access".to_string(), "accident".to_string(),
        ];
        
        // Create a new secret
        storage.create_secret(
            "test-secret",
            seed_words.clone(),
            SeedPhraseType::Words12,
            3,
            2,
            Some("Test description".to_string()),
            false,
        ).unwrap();
        
        // List secrets
        let secrets = storage.list_secrets().unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "test-secret");
        
        // Access the secret with shares
        let recovered = storage.access_secret("test-secret", &[1, 2]).unwrap();
        assert_eq!(recovered, seed_words);
    }
    
    #[test]
    fn test_memorable_secret() {
        let config = create_test_config();
        let storage = Storage::new(config);
        
        // Create test seed phrase
        let seed_words = vec![
            "abandon".to_string(), "ability".to_string(), "able".to_string(),
            "about".to_string(), "above".to_string(), "absent".to_string(),
            "absorb".to_string(), "abstract".to_string(), "absurd".to_string(),
            "abuse".to_string(), "access".to_string(), "accident".to_string(),
        ];
        
        // Create a new memorable secret
        let memorable_words = storage.create_memorable_secret(
            "test-memorable",
            seed_words.clone(),
            SeedPhraseType::Words12,
            Some("Test memorable secret".to_string()),
            false,
        ).unwrap();
        
        assert_eq!(memorable_words.len(), 3);
        
        // Get the memorable words
        let word_strings: Vec<String> = memorable_words.iter()
            .map(|mw| mw.word.clone())
            .collect();
        
        // Access with 2 of the 3 words
        let recovered = storage.access_memorable_secret(
            "test-memorable", 
            &word_strings[0..2].to_vec()
        ).unwrap();
        
        assert_eq!(recovered, seed_words);
    }
    
    #[test]
    fn test_delete_secret() {
        let config = create_test_config();
        let storage = Storage::new(config);
        
        // Create test seed phrase
        let seed_words = vec![
            "abandon".to_string(), "ability".to_string(), "able".to_string(),
            "about".to_string(), "above".to_string(), "absent".to_string(),
            "absorb".to_string(), "abstract".to_string(), "absurd".to_string(),
            "abuse".to_string(), "access".to_string(), "accident".to_string(),
        ];
        
        // Create a new secret
        storage.create_secret(
            "test-delete",
            seed_words.clone(),
            SeedPhraseType::Words12,
            3,
            2,
            None,
            false,
        ).unwrap();
        
        // Verify it exists
        let secrets = storage.list_secrets().unwrap();
        assert_eq!(secrets.len(), 1);
        
        // Delete the secret
        storage.delete_secret("test-delete", None).unwrap();
        
        // Verify it's gone
        let secrets = storage.list_secrets().unwrap();
        assert_eq!(secrets.len(), 0);
    }
}