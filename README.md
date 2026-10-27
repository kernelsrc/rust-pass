# rust-pass - A Secure CLI Password Manager

`rust-pass` is a local CLI password manager written in Rust. It securely stores your encrypted credentials locally on your machine using strong cryptography.

## Features

- **Init**: Initialize your vault with a master password
- **Add**: Store encrypted credentials for any service (with optional secure password generation)
- **Get**: Retrieve and decrypt passwords for a service
- **List**: List all stored services without exposing plaintext passwords
- **Delete**: Remove credentials from your vault
- **Clipboard**: Optionally copy passwords to your system clipboard

## Security

- Master password is never stored in plaintext
- Key derivation uses Argon2 (memory-hard password hashing)
- Encryption uses AES-256-GCM (authenticated encryption)
- Secure random password generation with symbols, letters, and numbers
- Derived keys are wiped from memory after use

## Installation / Build

```bash
# Clone or navigate to the project directory
cd rust-pass

# Build in release mode
cargo build --release

# The binary will be at target/release/rust-pass
```

## Usage

### Initialize vault

```bash
# Initialize a new vault at the default path (~/.local/share/rust-pass/vault.enc)
./target/release/rust-pass init your-master-password
```

### Add a credential

```bash
# Add with a provided password
./target/release/rust-pass add github myuser my-secret-password

# Add with a generated secure password
./target/release/rust-pass add github myuser --generate

# Add to a custom vault path
./target/release/rust-pass add github myuser my-secret-password --vault-path /custom/path/vault.enc
```

### Get a credential

```bash
# Display password on screen
./target/release/rust-pass get github

# Copy password to clipboard
./target/release/rust-pass get github --copy

# Or use short flag
./target/release/rust-pass get github -c
```

### List all services

```bash
./target/release/rust-pass list
```

### Delete a credential

```bash
./target/release/rust-pass delete github
```

## File Layout

By default, the encrypted vault is stored at:

```
~/.local/share/rust-pass/vault.enc
```

The vault file is a JSON file containing:
- A salt for Argon2 key derivation
- A list of encrypted credentials (service name, username, AES-256-GCM encrypted password)

## Project Structure

```
rust-pass/
├── Cargo.toml          # Manifest with dependencies
├── Cargo.lock
├── README.md           # This file
├── .gitignore          # Git ignore rules
└── src/
    └── main.rs         # Main CLI application
```

## License

GPL-3.0
