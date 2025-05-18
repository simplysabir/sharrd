# Sharrd

A secure tool for managing cryptocurrency seed phrases using Shamir's Secret Sharing algorithm.

## Overview

Sharrd is a command-line tool that securely splits your cryptocurrency wallet seed phrases (12 or 24 words) into three memorable words using Shamir's Secret Sharing (SSS). The key advantage is that you only need to remember any 2 of these 3 words to recover your complete seed phrase.

This approach is significantly more secure than simply making copies of your seed phrase or splitting it into halves, as each individual word reveals nothing about the original secret.

## Features

- **Secure Seed Phrase Management**: Split your seed phrase into 3 memorable words
- **2-of-3 Threshold**: Recover your secret with any 2 of the 3 words
- **User-Friendly CLI**: Simple commands with guided input for all operations
- **Zero Knowledge**: Individual words reveal nothing about the original secret
- **Deletion Protection**: Option to require password for deleting secrets

## Installation

```bash
# Install from source
cargo install --git https://github.com/simplysabir/sharrd

# Or clone and build
git clone https://github.com/simplysabir/sharrd
cd shard
cargo build --release
```

## Usage

### First-time Setup

The first time you run Shard, it will guide you through setting up your configuration:

```bash
sharrd list
```

### Creating a Secret

To create a new secret:

```bash
sharrd create
```

This will guide you through:
1. Naming your secret
2. Selecting the seed phrase type (12-word, 24-word, or custom)
3. Entering your seed phrase words one by one
4. Adding optional description and protection settings

You'll then be presented with 3 memorable words. Remember any 2 of these words to recover your seed phrase.

### Listing Secrets

To list all stored secrets:

```bash
sharrd list
# or
sharrd ls
```

### Accessing a Secret

To recover a seed phrase:

```bash
sharrd access <secret_name>
```

For secrets created with memorable words, you'll be prompted to enter the words you remember (you need at least 2 of the 3 words).

### Deleting a Secret

To delete a secret:

```bash
sharrd delete <secret_name>
```

If the secret was created with protection enabled, you'll need to provide the admin password.

### Exporting Share Information

To view details about the shares for a secret:

```bash
sharrd export <secret_name>
```

## Security Considerations

- The master password is used only to encrypt metadata
- Individual words reveal no information about the original secret
- All sensitive data is wiped from memory after use
- Consider memorizing the 3 words and storing them in separate secure locations
- Test recovery before relying on this system for critical assets

## Technical Details

- Written in Rust for memory safety and performance
- Uses GF(256) finite field arithmetic for Shamir's Secret Sharing
- AES-256-GCM for encrypting stored metadata
- Argon2id for key derivation from passwords
- Zero-copy, memory zeroing for sensitive data
- Blake3 for generating deterministic memorable words from shares

## License

MIT License