use anyhow::{anyhow, Context, Result};
use console::{style, Term};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, MultiSelect, Password, Select};
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;
use zeroize::Zeroize;

use crate::config::Config;
use crate::crypto::SecretString;
use crate::mnemonic::MemorableWord;
use crate::storage::{SeedPhraseType, Storage};

/// Execute the init command
pub fn init() -> Result<()> {
    // Initialize configuration with user input
    Config::initialize()?;
    Ok(())
}

/// Execute the create command (with memorable words)
pub fn create(config: Config) -> Result<()> {
    let term = Term::stdout();
    term.clear_screen()?;
    
    println!("{}", style("Create a New Secret").bold().green());
    println!("This will securely split your seed phrase into 3 memorable words\n");
    
    // Get master password if needed
    let mut storage = Storage::new(config.clone());
    if config.use_password {
        let password = Password::new()
            .with_prompt("Enter master password")
            .interact()?;
        storage.set_master_password(SecretString::new(password));
    }
    
    // Get secret name
    let name: String = Input::new()
        .with_prompt("Enter a name for this secret")
        .validate_with(|input: &String| {
            // Check if name is valid
            if input.is_empty() {
                return Err("Name cannot be empty");
            }
            if input.contains(char::is_whitespace) {
                return Err("Name cannot contain whitespace");
            }
            if input.contains('/') || input.contains('\\') {
                return Err("Name cannot contain path separators");
            }
            
            // Check if name already exists
            match storage.list_secrets() {
                Ok(existing) => {
                    if existing.iter().any(|s| s.name == *input) {
                        return Err("A secret with this name already exists");
                    }
                }
                Err(_) => {
                    return Err("Failed to check existing secrets");
                }
            }
            
            Ok(())
        })
        .interact_text()?;
    
    // Get seed phrase type
    let phrase_type_options = &[
        "12-word seed phrase",
        "24-word seed phrase",
        "Custom length seed phrase",
    ];
    
    let phrase_type_idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select seed phrase type")
        .default(0)
        .items(phrase_type_options)
        .interact()?;
    
    let phrase_type = match phrase_type_idx {
        0 => (SeedPhraseType::Words12, 12),
        1 => (SeedPhraseType::Words24, 24),
        2 => {
            let word_count: usize = Input::new()
                .with_prompt("How many words in your seed phrase?")
                .validate_with(|input: &usize| {
                    if *input > 0 {
                        Ok(())
                    } else {
                        Err("Please enter a positive number")
                    }
                })
                .interact()?;
            
            (SeedPhraseType::Custom, word_count)
        }
        _ => unreachable!(),
    };
    
    // Get description (optional)
    let description: String = Input::new()
        .with_prompt("Description (optional)")
        .allow_empty(true)
        .interact_text()?;
    
    let description = if description.is_empty() {
        None
    } else {
        Some(description)
    };
    
    // Ask if this secret should be protected (require password to delete)
    let protected = Confirm::new()
        .with_prompt("Protect this secret with password for deletion?")
        .default(true)
        .interact()?;
    
    println!("\n{}", style("Enter your seed phrase words one by one:").bold());
    println!("(Your input will be hidden for security)\n");
    
    // Collect seed words one by one
    let mut seed_words = Vec::with_capacity(phrase_type.1);
    for i in 1..=phrase_type.1 {
        let word = Password::new()
            .with_prompt(format!("Word {}", i))
            .interact()?;
        
        seed_words.push(word);
    }
    
    // Show progress bar while creating secret
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_style(
        ProgressStyle::with_template("{spinner:.green} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.set_message("Creating memorable words...");
    
    // Create the secret with memorable words
    let memorable_words = storage.create_memorable_secret(
        &name,
        seed_words.clone(),
        phrase_type.0,
        description,
        protected,
    )?;
    
    // Clean up sensitive data
    for word in &mut seed_words {
        word.zeroize();
    }
    
    pb.finish_with_message("Secret created successfully!");
    
    // Display the memorable words
    println!("\n{}", style("Your Memorable Words:").green().bold());
    println!("{}", style("─".repeat(50)).dim());
    println!("Remember these three words. You'll need any 2 to recover your secret.");
    println!("{}", style("─".repeat(50)).dim());
    
    for memorable in &memorable_words {
        println!("Word #{}: {}", memorable.index, style(&memorable.word).bold());
    }
    
    println!("{}", style("─".repeat(50)).dim());
    println!("\n{}", style("IMPORTANT:").yellow().bold());
    println!(" • Remember these 3 words");
    println!(" • You will need ANY 2 of them to recover your seed phrase");
    println!(" • They are not stored in plain text - you must remember them!");
    
    // Wait for user confirmation
    Confirm::new()
        .with_prompt("I have memorized or written down my words")
        .default(true)
        .interact()?;
    
    term.clear_screen()?;
    
    Ok(())
}

/// Execute the list command
pub fn list(config: Config) -> Result<()> {
    let storage = Storage::new(config);
    let secrets = storage.list_secrets()?;
    
    if secrets.is_empty() {
        println!("No secrets found.");
        return Ok(());
    }
    
    println!("{}", style("Stored Secrets:").bold());
    println!("{}", style("─".repeat(50)).dim());
    
    for (i, secret) in secrets.iter().enumerate() {
        println!("{}. {}", i + 1, style(&secret.name).bold());
        
        // Format the phrase type for display
        let phrase_type = match secret.phrase_type {
            SeedPhraseType::Words12 => "12-word seed phrase",
            SeedPhraseType::Words24 => "24-word seed phrase",
            SeedPhraseType::Custom => "Custom seed phrase",
        };
        
        println!("   Type: {}", phrase_type);
        println!("   Shares: {} (need {} to recover)", secret.total_shares, secret.threshold);
        
        if let Some(ref desc) = secret.description {
            println!("   Description: {}", desc);
        }
        
        println!("   Created: {}", secret.created_at.split('T').next().unwrap_or(""));
        
        // Show memorable indicator if applicable
        if secret.memorable_shares {
            println!("   {}", style("🧠 Memorable words").blue());
        }
        
        // Show lock icon if protected
        if secret.protected {
            println!("   {}", style("🔒 Protected").yellow());
        }
        
        if i < secrets.len() - 1 {
            println!("{}", style("─".repeat(50)).dim());
        }
    }
    
    println!("{}", style("─".repeat(50)).dim());
    
    Ok(())
}

/// Execute the access command (supporting memorable words)
pub fn access(config: Config, name: &str) -> Result<()> {
    let term = Term::stdout();
    
    // Initialize storage
    let mut storage = Storage::new(config.clone());
    if config.use_password {
        let password = Password::new()
            .with_prompt("Enter master password")
            .interact()?;
        storage.set_master_password(SecretString::new(password));
    }
    
    // Get list of available secrets
    let secrets = storage.list_secrets()?;
    
    // Find the requested secret
    let secret = secrets.iter().find(|s| s.name == name);
    if secret.is_none() {
        return Err(anyhow!("Secret with name '{}' not found", name));
    }
    
    let secret = secret.unwrap();
    
    // Check if this is a memorable secret or traditional secret
    if secret.memorable_shares {
        // Handle memorable secret (with words)
        println!("\n{}", style("Access Secret With Words").bold().green());
        println!("Secret: {}", style(&secret.name).bold());
        println!("You need at least 2 of the 3 memorable words to recover this secret.");
        
        // Collect words from user
        let mut words = Vec::new();
        let mut continue_adding = true;
        
        while continue_adding && words.len() < 3 {
            let word: String = Input::new()
                .with_prompt(format!("Enter word #{}", words.len() + 1))
                .interact_text()?;
            
            if !word.is_empty() {
                words.push(word);
            }
            
            // Check if we have enough words
            if words.len() >= 2 {
                // Ask if user wants to add more, only if we don't have all 3 yet
                if words.len() < 3 {
                    continue_adding = Confirm::new()
                        .with_prompt(format!("You have entered {} words (minimum needed is 2). Add another?", 
                                          words.len()))
                        .default(false)
                        .interact()?;
                } else {
                    continue_adding = false; // We have all 3 words
                }
            }
        }
        
        // Show progress bar while recovering secret
        let pb = ProgressBar::new_spinner();
        pb.enable_steady_tick(Duration::from_millis(100));
        pb.set_style(
            ProgressStyle::with_template("{spinner:.green} {msg}")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        pb.set_message("Recovering secret...");
        
        // Recover the secret
        let recovered_words = storage.access_memorable_secret(&secret.name, &words)?;
        
        pb.finish_and_clear();
        
        // Display the recovered seed phrase
        display_recovered_seed_phrase(term, &secret.name, recovered_words)?;
    } else {
        // Traditional Shamir share access
        println!("\n{}", style("Access Secret").bold().green());
        println!("Secret: {}", style(&secret.name).bold());
        println!("You need at least {} shares to recover this secret.", secret.threshold);
        
        // Create items for share selection (1 to total_shares)
        let share_items: Vec<String> = (1..=secret.total_shares)
            .map(|i| format!("Share {}", i))
            .collect();
        
        let selected = MultiSelect::new()
            .with_prompt("Select which shares to use (select at least 2 shares)")
            .items(&share_items)
            .interact()?;

        if selected.len() < secret.threshold {
            return Err(anyhow!(
                "You must select at least {} shares to recover the secret.",
                secret.threshold
            ));
        }
        if selected.len() > secret.total_shares {
            return Err(anyhow!(
                "You cannot select more than {} shares.",
                secret.total_shares
            ));
        }
        
        // Convert selected indices to share IDs (1-based)
        let share_ids: Vec<usize> = selected.iter().map(|&idx| idx + 1).collect();
        
        // Show progress bar while recovering secret
        let pb = ProgressBar::new_spinner();
        pb.enable_steady_tick(Duration::from_millis(100));
        pb.set_style(
            ProgressStyle::with_template("{spinner:.green} {msg}")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        pb.set_message("Recovering secret...");
        
        // Recover the secret
        let recovered_words = storage.access_secret(&secret.name, &share_ids)?;
        
        pb.finish_and_clear();
        
        // Display the recovered seed phrase
        display_recovered_seed_phrase(term, &secret.name, recovered_words)?;
    }
    
    Ok(())
}

/// Helper function to display a recovered seed phrase
fn display_recovered_seed_phrase(term: Term, secret_name: &str, recovered_words: Vec<String>) -> Result<()> {
    // Clear screen for security
    term.clear_screen()?;
    
    println!("{}", style("🔓 Secret Recovered Successfully").green().bold());
    println!("{}", style("─".repeat(50)).dim());
    println!("Secret: {}", style(secret_name).bold());
    println!("\n{}", style("Seed Phrase:").bold());
    
    // Show recovered words with numbering
    for (i, word) in recovered_words.iter().enumerate() {
        print!("{:2}. {:12}", i + 1, word);
        
        // Print 4 words per line
        if (i + 1) % 4 == 0 {
            println!();
        }
    }
    
    // Ensure there's a newline at the end
    if recovered_words.len() % 4 != 0 {
        println!();
    }
    
    println!("\n{}", style("─".repeat(50)).dim());
    println!("{}", style("IMPORTANT: Please write this down if needed. When you continue, it will be cleared from the screen.").yellow());
    
    // Wait for user confirmation before clearing
    Confirm::new()
        .with_prompt("Press enter to clear the screen")
        .default(true)
        .show_default(false)
        .wait_for_newline(true)
        .interact()?;
    
    // Clear screen for security
    term.clear_screen()?;
    
    Ok(())
}

/// Execute the delete command
pub fn delete(config: Config, name: &str) -> Result<()> {
    let mut storage = Storage::new(config.clone());
    
    // Get master password if needed
    if config.use_password {
        let password = Password::new()
            .with_prompt("Enter master password")
            .interact()?;
        storage.set_master_password(SecretString::new(password));
    }
    
    // Get list of available secrets
    let secrets = storage.list_secrets()?;
    
    // Find the requested secret
    let secret = secrets.iter().find(|s| s.name == name);
    if secret.is_none() {
        return Err(anyhow!("Secret with name '{}' not found", name));
    }
    
    let secret = secret.unwrap();
    
    // Ask for confirmation
    println!("\n{}", style("Delete Secret").bold().red());
    println!("Secret: {}", style(&secret.name).bold());
    
    if secret.protected {
        println!("{}", style("⚠️  This secret is protected and requires password confirmation to delete.").yellow());
    }
    
    let confirmed = Confirm::new()
        .with_prompt(format!("Are you sure you want to delete the secret '{}'? This cannot be undone.", name))
        .default(false)
        .interact()?;
    
    if !confirmed {
        println!("Deletion cancelled.");
        return Ok(());
    }
    
    // Delete the secret
    let admin_pw = if secret.protected {
        let password = Password::new()
            .with_prompt("Enter admin password to confirm deletion")
            .interact()?;
        Some(SecretString::new(password))
    } else {
        None
    };
    
    // Show progress bar during deletion
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_style(
        ProgressStyle::with_template("{spinner:.red} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.set_message("Deleting secret...");
    
    // Delete the secret
    storage.delete_secret(name, admin_pw.as_ref())?;
    
    pb.finish_with_message("Secret deleted successfully!");
    
    println!("\n{}", style("Secret deleted successfully!").green());
    
    Ok(())
}

/// Execute the export command
pub fn export(config: Config, name: &str) -> Result<()> {
    let mut storage = Storage::new(config.clone());
    
    // Get master password if needed
    if config.use_password {
        let password = Password::new()
            .with_prompt("Enter master password")
            .interact()?;
        storage.set_master_password(SecretString::new(password));
    }
    
    // Get list of available secrets
    let secrets = storage.list_secrets()?;
    
    // Find the requested secret
    let secret = secrets.iter().find(|s| s.name == name);
    if secret.is_none() {
        return Err(anyhow!("Secret with name '{}' not found", name));
    }
    
    let secret = secret.unwrap();
    
    println!("\n{}", style("Export Shares").bold().green());
    println!("Secret: {}", style(&secret.name).bold());
    
    if secret.memorable_shares {
        println!("\n{}", style("This secret uses memorable words.").blue());
        println!("There are 3 words associated with this secret, and you need any 2 to recover it.");
        println!("The actual words cannot be exported for security reasons - you must remember them.");
    } else {
        // Get share information for standard shares
        let share_infos = storage.export_shares(name)?;
        
        println!("\n{}", style("Share Information:").bold());
        println!("{}", style("─".repeat(50)).dim());
        
        for info in &share_infos {
            println!("Share ID: {}", info.id);
            println!("Total Shares: {}", info.total);
            println!("Threshold: {}", info.threshold);
            println!("{}", style("─".repeat(50)).dim());
        }
        
        println!("\nThis secret has {} shares, and you need at least {} to recover it.", 
                secret.total_shares, secret.threshold);
    }
    
    Ok(())
}