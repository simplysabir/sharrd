use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Configuration for the Shard application
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    /// Directory where secrets are stored
    pub storage_dir: PathBuf,
    /// Number of shares to create (default: 3)
    pub default_shares: usize,
    /// Threshold required to recover secret (default: 2)
    pub default_threshold: usize,
    /// Whether to encrypt secrets with a password (default: true)
    pub use_password: bool,
}

impl Default for Config {
    fn default() -> Self {
        // Default to storing in user's config directory
        let proj_dirs = ProjectDirs::from("com", "shard", "shard")
            .expect("Failed to determine configuration directory");
        
        let storage_dir = proj_dirs.data_dir().to_path_buf();
        
        Self {
            storage_dir,
            default_shares: 3,
            default_threshold: 2,
            use_password: true,
        }
    }
}

impl Config {
    /// Get config file path
    pub fn config_path() -> Result<PathBuf> {
        let proj_dirs = ProjectDirs::from("com", "shard", "shard")
            .context("Failed to determine configuration directory")?;
        
        let config_dir = proj_dirs.config_dir();
        fs::create_dir_all(config_dir).context("Failed to create config directory")?;
        
        Ok(config_dir.join("config.json"))
    }
    
    /// Load configuration from file
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        
        if path.exists() {
            let contents = fs::read_to_string(&path)
                .context("Failed to read config file")?;
            
            let config: Config = serde_json::from_str(&contents)
                .context("Failed to parse config file")?;
            
            Ok(config)
        } else {
            // Create default config
            let config = Config::default();
            config.save()?;
            Ok(config)
        }
    }
    
    /// Save configuration to file
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        
        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context("Failed to create config directory")?;
        }
        
        // Ensure storage directory exists
        fs::create_dir_all(&self.storage_dir)
            .context("Failed to create storage directory")?;
        
        let contents = serde_json::to_string_pretty(self)
            .context("Failed to serialize config")?;
        
        fs::write(&path, contents)
            .context("Failed to write config file")?;
        
        Ok(())
    }
    
    /// Initialize configuration with user input
    pub fn initialize() -> Result<Self> {
        use dialoguer::{Confirm, Input, Select};
        use console::style;
        
        println!("{}", style("Welcome to Shard - Secure Seed Phrase Manager").bold().green());
        println!("Let's set up your configuration...");
        
        // Get storage directory
        let default_dir = Config::default().storage_dir.display().to_string();
        let storage_dir: String = Input::new()
            .with_prompt(format!("Storage directory [default: {}]", default_dir))
            .allow_empty(true)
            .default(default_dir.clone())
            .interact_text()?;
        
        let storage_dir = if storage_dir.is_empty() {
            PathBuf::from(default_dir)
        } else {
            PathBuf::from(storage_dir)
        };
        
        // Default values for memorable shares (fixed as 3 shares, threshold of 2)
        let default_shares = 3;
        let default_threshold = 2;
        
        // Use password protection?
        let use_password = Confirm::new()
            .with_prompt("Encrypt storage with a master password?")
            .default(true)
            .interact()?;
        
        let config = Config {
            storage_dir,
            default_shares,
            default_threshold,
            use_password,
        };
        
        // Create directory if it doesn't exist
        fs::create_dir_all(&config.storage_dir)
            .context("Failed to create storage directory")?;
        
        // Save configuration
        config.save()?;
        
        println!("{}", style("\nConfiguration saved successfully!").green());
        
        Ok(config)
    }
}