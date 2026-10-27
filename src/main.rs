use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{SaltString};
use base64::{Engine as _, engine::general_purpose};
use clap::Parser;
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;
use std::io::{self, Write};
use arboard::Clipboard;
use dirs;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser, Debug)]
enum Commands {
    /// Initialize the vault with a master password
    Init {
        /// Master password (will not be stored)
        password: String,
        /// Vault file path
        #[arg(short, long, default_value = "~/.local/share/rust-pass/vault.enc")]
        vault_path: String,
    },
    /// Add a new credential
    Add {
        /// Service name
        service: String,
        /// Username
        username: String,
        /// Password (optional, will generate if not provided)
        password: Option<String>,
        /// Generate a secure random password
        #[arg(short, long, action = clap::ArgAction::SetTrue)]
        generate: bool,
        /// Vault file path
        #[arg(short, long, default_value = "~/.local/share/rust-pass/vault.enc")]
        vault_path: String,
    },
    /// Get a credential password
    Get {
        /// Service name
        service: String,
        /// Vault file path
        #[arg(short, long, default_value = "~/.local/share/rust-pass/vault.enc")]
        vault_path: String,
        /// Copy to clipboard
        #[arg(short, long, action = clap::ArgAction::SetTrue)]
        copy: bool,
    },
    /// List all stored services
    List {
        /// Vault file path
        #[arg(short, long, default_value = "~/.local/share/rust-pass/vault.enc")]
        vault_path: String,
    },
    /// Delete a credential
    Delete {
        /// Service name
        service: String,
        /// Vault file path
        #[arg(short, long, default_value = "~/.local/share/rust-pass/vault.enc")]
        vault_path: String,
    },
}

#[derive(Serialize, Deserialize, Debug)]
struct Credential {
    service: String,
    username: String,
    encrypted_password: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Vault {
    master_key_hash: String,
    credentials: Vec<Credential>,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { password, vault_path } => {
            if let Err(e) = init_vault(&password, &vault_path) {
                eprintln!("Error initializing vault: {}", e);
                std::process::exit(1);
            }
            println!("Vault initialized at {}", vault_path);
        }
        Commands::Add { service, username, password, generate, vault_path } => {
            if let Err(e) = add_credential(&service, &username, password, generate, &vault_path) {
                eprintln!("Error adding credential: {}", e);
                std::process::exit(1);
            }
            println!("Credential added for service: {}", service);
        }
        Commands::Get { service, vault_path, copy } => {
            if let Err(e) = get_credential(&service, &vault_path, copy) {
                eprintln!("Error getting credential: {}", e);
                std::process::exit(1);
            }
        }
        Commands::List { vault_path } => {
            if let Err(e) = list_credentials(&vault_path) {
                eprintln!("Error listing credentials: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Delete { service, vault_path } => {
            if let Err(e) = delete_credential(&service, &vault_path) {
                eprintln!("Error deleting credential: {}", e);
                std::process::exit(1);
            }
            println!("Credential deleted for service: {}", service);
        }
    }
}

fn expand_path(path: &str) -> String {
    let expanded = if path.starts_with("~") {
        if let Some(home) = dirs::home_dir() {
            let rest = &path[2..];
            home.join(rest).to_string_lossy().to_string()
        } else {
            path.to_string()
        }
    } else {
        path.to_string()
    };
    expanded
}

fn derive_key(master_password: &str, salt: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let mut output = vec![0u8; 32]; // 32 bytes for AES-256 key
    let params = argon2::Argon2ParamsBuilder::default()
        .hash_len(32)
        .m_cost(65536)
        .t_cost(4)
        .build()?;
    
    Argon2::default()
        .hash_password_into(master_password.as_bytes(), salt, params, &mut output)
        .map_err(|e| anyhow::anyhow!("Failed to derive key: {}", e))?;
    
    Ok(output)
}

fn encrypt_password(key: &[u8], password: &str) -> Result<String, anyhow::Error> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce_bytes = rand::random::<[u8; 12]>(); // 96-bit nonce
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let cipher = Aes256Gcm::new(key);
    let ciphertext = cipher.encrypt(nonce, password.as_bytes())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
    
    // Combine nonce + ciphertext for storage
    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    
    // Encode as base64
    let encoded = general_purpose::STANDARD.encode(combined);
    Ok(encoded)
}

fn decrypt_password(key: &[u8], encrypted: &str) -> Result<String, anyhow::Error> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    
    // Decode base64
    let combined = general_purpose::STANDARD.decode(encrypted)
        .map_err(|e| anyhow::anyhow!("Failed to decode base64: {}", e))?;
    
    if combined.len() < 12 {
        return Err(anyhow::anyhow!("Invalid encrypted data length"));
    }
    
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    let cipher = Aes256Gcm::new(key);
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
    
    String::from_utf8(plaintext)
        .map_err(|e| anyhow::anyhow!("Failed to convert to UTF-8: {}", e))
}

fn init_vault(password: &str, vault_path: &str) -> Result<(), anyhow::Error> {
    let path = Path::new(&expand_path(vault_path));
    
    if path.exists() {
        return Err(anyhow::anyhow!("Vault already exists at {}", vault_path));
    }
    
    // Create vault directory if it doesn't exist
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    // Generate random salt for key derivation
    let salt = rand::random::<[u8; 16]>();
    
    // Derive master key
    let master_key = derive_key(password, &salt)?;
    
    // Create empty vault
    let vault = Vault {
        master_key_hash: general_purpose::STANDARD.encode(&salt),
        credentials: Vec::new(),
    };
    
    // Write vault to file
    let json = serde_json::to_string(&vault)?;
    fs::write(path, json)?;
    
    // Securely wipe the master key from memory
    for byte in master_key.iter_mut() {
        *byte = 0;
    }
    
    Ok(())
}

fn add_credential(
    service: &str,
    username: &str,
    password: Option<String>,
    generate: bool,
    vault_path: &str,
) -> Result<(), anyhow::Error> {
    let path = Path::new(&expand_path(vault_path));
    
    if !path.exists() {
        return Err(anyhow::anyhow!("Vault does not exist. Run 'rust-pass init' first."));
    }
    
    // Load vault
    let vault_json = fs::read_to_string(path)?;
    let mut vault: Vault = serde_json::from_str(&vault_json)?;
    
    // Prompt for master password or pass it in (simplified for CLI)
    println!("Enter master password:");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let master_password = input.trim();
    
    // Derive key from master password
    let salt = general_purpose::STANDARD.decode(&vault.master_key_hash)?;
    let key = derive_key(master_password, &salt)?;
    
    // Get or generate password
    let password_value = if generate {
        generate_secure_password()
    } else if let Some(pwd) = password {
        pwd
    } else {
        return Err(anyhow::anyhow!("Password required unless --generate is specified"));
    };
    
    // Encrypt the password
    let encrypted_password = encrypt_password(&key, &password_value)?;
    
    // Check if service already exists
    if vault.credentials.iter().any(|c| c.service == service) {
        return Err(anyhow::anyhow!("Service '{}' already exists", service));
    }
    
    // Add credential
    let credential = Credential {
        service: service.to_string(),
        username: username.to_string(),
        encrypted_password,
    };
    vault.credentials.push(credential);
    
    // Write vault back to file
    let updated_json = serde_json::to_string(&vault)?;
    fs::write(path, updated_json)?;
    
    // Securely wipe the key from memory
    for byte in key.iter_mut() {
        *byte = 0;
    }
    
    println!("Password generated: {}", password_value);
    
    Ok(())
}

fn get_credential(service: &str, vault_path: &str, copy: bool) -> Result<(), anyhow::Error> {
    let path = Path::new(&expand_path(vault_path));
    
    if !path.exists() {
        return Err(anyhow::anyhow!("Vault does not exist. Run 'rust-pass init' first."));
    }
    
    // Load vault
    let vault_json = fs::read_to_string(path)?;
    let vault: Vault = serde_json::from_str(&vault_json)?;
    
    // Find credential
    let credential = vault.credentials.iter()
        .find(|c| c.service == service)
        .ok_or_else(|| anyhow::anyhow!("Service '{}' not found", service))?;
    
    // Prompt for master password
    println!("Enter master password:");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let password = input.trim();
    
    // Derive key from master password
    let salt = general_purpose::STANDARD.decode(&vault.master_key_hash)?;
    let key = derive_key(password, &salt)?;
    
    // Decrypt password
    let decrypted_password = decrypt_password(&key, &credential.encrypted_password)?;
    
    // Securely wipe the key from memory
    for byte in key.iter_mut() {
        *byte = 0;
    }
    
    if copy {
        let mut clipboard = Clipboard::new()?;
        clipboard.set_text(decrypted_password.clone())?;
        println!("Password copied to clipboard");
    } else {
        println!("Password for '{}': {}", service, decrypted_password);
    }
    
    Ok(())
}

fn list_credentials(vault_path: &str) -> Result<(), anyhow::Error> {
    let path = Path::new(&expand_path(vault_path));
    
    if !path.exists() {
        return Err(anyhow::anyhow!("Vault does not exist. Run 'rust-pass init' first."));
    }
    
    // Load vault
    let vault_json = fs::read_to_string(path)?;
    let vault: Vault = serde_json::from_str(&vault_json)?;
    
    println!("Stored services:");
    for credential in &vault.credentials {
        println!("  - {}", credential.service);
    }
    
    Ok(())
}

fn delete_credential(service: &str, vault_path: &str) -> Result<(), anyhow::Error> {
    let path = Path::new(&expand_path(vault_path));
    
    if !path.exists() {
        return Err(anyhow::anyhow!("Vault does not exist. Run 'rust-pass init' first."));
    }
    
    // Load vault
    let vault_json = fs::read_to_string(path)?;
    let mut vault: Vault = serde_json::from_str(&vault_json)?;
    
    // Find credential
    let index = vault.credentials.iter()
        .position(|c| c.service == service)
        .ok_or_else(|| anyhow::anyhow!("Service '{}' not found", service))?;
    
    // Prompt for master password
    println!("Enter master password:");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let password = input.trim();
    
    // Derive key from master password
    let salt = general_purpose::STANDARD.decode(&vault.master_key_hash)?;
    let key = derive_key(password, &salt)?;
    
    // Remove credential
    vault.credentials.remove(index);
    
    // Write vault back to file
    let updated_json = serde_json::to_string(&vault)?;
    fs::write(path, updated_json)?;
    
    // Securely wipe the key from memory
    for byte in key.iter_mut() {
        *byte = 0;
    }
    
    Ok(())
}

fn generate_secure_password() -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    let mut rng = rand::thread_rng();
    let length = 16;
    
    (0..length)
        .map(|_| {
            let idx = rand::Rng::gen_range(&mut rng, 0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}