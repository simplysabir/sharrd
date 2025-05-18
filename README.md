# Sharrd

A secure tool for managing cryptocurrency seed phrases using Shamir's Secret Sharing algorithm.

## Overview

Shard is a command-line tool that securely splits your cryptocurrency wallet seed phrases (12 or 24 words) into multiple shares using Shamir's Secret Sharing (SSS). This allows you to:

- Split your seed phrase into N shares
- Define a threshold K (where K ≤ N) of shares needed to recover the secret
- Distribute shares across different physical locations or among trusted individuals
- Recover your seed phrase with ANY K shares, even if some are lost

This approach is significantly more secure than simply making copies of your seed phrase or splitting it into halves, as each individual share reveals nothing about the original secret.

## Features

- **Secure Seed Phrase Management**: Split and reconstruct 12-word, 24-word, or custom length seed phrases
- **Flexible Sharing**: Create multiple shares with configurable thresholds
- **Encrypted Storage**: Optional password protection of shares storage
- **User-Friendly CLI**: Simple commands with guided input for all operations
- **Zero Knowledge**: Individual shares reveal nothing about the original secret
- **Deletion Protection**: Option to require admin password for deleting secrets

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

The first time you run Sharrd, it will guide you through setting up your configuration:

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
3. Configuring number of shares and threshold
4. Entering your seed phrase words one by one
5. Adding optional description and protection settings

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

You'll be prompted to select which shares you want to use (you need at least the threshold number).

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

- The master password is used to encrypt the shares locally - make sure to use a strong password
- Individual shares reveal no information about the original secret
- All sensitive data is wiped from memory after use
- Consider distributing shares across different physical locations
- Test recovery before relying on this system for critical assets

## Technical Details

- Written in Rust for memory safety and performance
- Uses GF(256) finite field arithmetic for Shamir's Secret Sharing
- AES-256-GCM for encrypting stored shares
- Argon2id for key derivation from passwords
- Zero-copy, memory zeroing for sensitive data

## License

MIT License