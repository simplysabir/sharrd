mod commands;
mod config;
mod crypto;
mod mnemonic;
mod shamir;
mod storage;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use console::style;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "shard")]
#[command(about = "A secure seed phrase manager using Shamir's Secret Sharing", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize Shard configuration
    Init,
    
    /// Create a new secret
    Create,
    
    /// List all saved secrets
    #[command(alias = "ls")]
    List,
    
    /// Access and recover a secret
    Access {
        /// The name of the secret to access
        name: String,
    },
    
    /// Delete a secret
    Delete {
        /// The name of the secret to delete
        name: String,
    },
    
    /// Export information about shares for a secret
    Export {
        /// The name of the secret to export
        name: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Check for first-time setup
    if !matches!(cli.command, Commands::Init) {
        if !config::Config::config_path()?.exists() {
            println!("{}", style("Welcome to Shard!").bold().green());
            println!("It looks like this is your first time running Shard.");
            println!("Let's set up your configuration first.\n");
            
            commands::init()?;
            return Ok(());
        }
    }
    
    // Load config for all commands except init
    let config = match cli.command {
        Commands::Init => config::Config::default(),
        _ => config::Config::load().context("Failed to load configuration")?,
    };
    
    // Execute the appropriate command
    match cli.command {
        Commands::Init => commands::init()?,
        Commands::Create => commands::create(config)?,
        Commands::List => commands::list(config)?,
        Commands::Access { name } => commands::access(config, &name)?,
        Commands::Delete { name } => commands::delete(config, &name)?,
        Commands::Export { name } => commands::export(config, &name)?,
    }
    
    Ok(())
}