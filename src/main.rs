use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use argon2::{Argon2, Algorithm, Version, Params};
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
    let cli = Cli::try_parse();

    match cli {
        Ok(cli) => {
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
        Err(_) => {
            // No subcommand provided → launch interactive REPL
            if let Err(e) = run_interactive() {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Interactive REPL Mode
// ---------------------------------------------------------------------------

/// Holds the decrypted vault state and derived encryption key for an
/// interactive session.
struct VaultSession {
    vault: Vault,
    key: Vec<u8>,
    vault_path: String,
}

impl Drop for VaultSession {
    fn drop(&mut self) {
        for byte in self.key.iter_mut() {
            *byte = 0;
        }
    }
}

fn run_interactive() -> Result<(), anyhow::Error> {
    let vault_path = "~/.local/share/rust-pass/vault.enc".to_string();
    let expanded = expand_path(&vault_path);
    let path = Path::new(&expanded);

    if !path.exists() {
        eprintln!("No vault found at {}. Run 'rust-pass init <master-password>' first.", vault_path);
        return Ok(());
    }

    // Prompt for master password once
    let mut master_password = prompt_password("Enter master password: ")?;
    let salt = {
        let vault_json = fs::read_to_string(path)?;
        let vault: Vault = serde_json::from_str(&vault_json)?;
        general_purpose::STANDARD.decode(&vault.master_key_hash)?
    };
    let key = derive_key(&master_password, &salt)?;

    // Wipe the password string from memory
    unsafe {
        for byte in master_password.as_bytes_mut() {
            *byte = 0;
        }
    }

    let mut session = VaultSession {
        vault: Vault { master_key_hash: general_purpose::STANDARD.encode(&salt), credentials: Vec::new() },
        key,
        vault_path: vault_path.clone(),
    };

    // Re-read vault into session (we need the actual credentials list)
    let vault_json = fs::read_to_string(path)?;
    session.vault = serde_json::from_str(&vault_json)?;

    println!("Vault unlocked. {} service(s) stored.", session.vault.credentials.len());

    loop {
        let choice = dialoguer::Select::new()
            .with_prompt("Select an action")
            .items(&[
                "🔓 Get password (with clipboard option)",
                "➕ Add new entry",
                "🎲 Generate new password for service",
                "📋 List all services",
                "❌ Lock & Exit",
            ])
            .default(0)
            .interact()?;

        match choice {
            0 => match interactive_get(&mut session) {
                Ok(()) => {}
                Err(e) => eprintln!("Error: {}", e),
            },
            1 => match interactive_add(&mut session) {
                Ok(()) => {}
                Err(e) => eprintln!("Error: {}", e),
            },
            2 => match interactive_generate(&mut session) {
                Ok(()) => {}
                Err(e) => eprintln!("Error: {}", e),
            },
            3 => {
                println!("\nStored services:");
                for cred in &session.vault.credentials {
                    println!("  - {}", cred.service);
                }
                println!();
            }
            4 => {
                save_vault(&session)?;
                println!("Vault locked. Goodbye!");
                break;
            }
            _ => break,
        }
    }

    Ok(())
}

fn prompt_password(prompt: &str) -> Result<String, anyhow::Error> {
    use std::io::Write;
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn interactive_get(session: &mut VaultSession) -> Result<(), anyhow::Error> {
    let service = dialoguer::Input::<String>::new()
        .with_prompt("Service name")
        .interact_text()?;

    let credential = session.vault.credentials.iter()
        .find(|c| c.service == service)
        .ok_or_else(|| anyhow::anyhow!("Service '{}' not found", service))?;

    let decrypted = decrypt_password(&session.key, &credential.encrypted_password)?;

    let copy: bool = dialoguer::Confirm::new()
        .with_prompt("Copy to clipboard")
        .default(true)
        .interact()?;

    if copy {
        let mut clipboard = Clipboard::new()?;
        clipboard.set_text(decrypted.clone())?;
        println!("Password copied to clipboard");
    } else {
        println!("Password: {}", decrypted);
    }

    Ok(())
}

fn interactive_add(session: &mut VaultSession) -> Result<(), anyhow::Error> {
    let service = dialoguer::Input::<String>::new()
        .with_prompt("Service name")
        .interact_text()?;

    let username = dialoguer::Input::<String>::new()
        .with_prompt("Username")
        .interact_text()?;

    if session.vault.credentials.iter().any(|c| c.service == service) {
        return Err(anyhow::anyhow!("Service '{}' already exists", service));
    }

    let use_generated: bool = dialoguer::Confirm::new()
        .with_prompt("Generate a secure password")
        .default(true)
        .interact()?;

    let password_value = if use_generated {
        let pw = generate_secure_password();
        println!("Generated password: {}", pw);
        pw
    } else {
        let pw = prompt_password("Enter password: ")?;
        pw
    };

    let encrypted_password = encrypt_password(&session.key, &password_value)?;

    session.vault.credentials.push(Credential {
        service: service.clone(),
        username,
        encrypted_password,
    });

    save_vault(session)?;
    println!("Credential saved for '{}'.", service);

    Ok(())
}

fn interactive_generate(session: &mut VaultSession) -> Result<(), anyhow::Error> {
    let service = dialoguer::Input::<String>::new()
        .with_prompt("Service name")
        .interact_text()?;

    let credential = session.vault.credentials.iter_mut()
        .find(|c| c.service == service)
        .ok_or_else(|| anyhow::anyhow!("Service '{}' not found", service))?;

    let new_password = generate_secure_password();
    let encrypted = encrypt_password(&session.key, &new_password)?;
    credential.encrypted_password = encrypted;

    save_vault(session)?;
    println!("New password generated and saved for '{}'.", service);

    let copy: bool = dialoguer::Confirm::new()
        .with_prompt("Copy to clipboard")
        .default(true)
        .interact()?;

    if copy {
        let mut clipboard = Clipboard::new()?;
        clipboard.set_text(new_password.clone())?;
        println!("New password copied to clipboard");
    } else {
        println!("New password: {}", new_password);
    }

    Ok(())
}

fn save_vault(session: &VaultSession) -> Result<(), anyhow::Error> {
    let expanded = expand_path(&session.vault_path);
    let path = Path::new(&expanded);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string(&session.vault)?;
    fs::write(path, json)?;
    Ok(())
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
    let mut output = vec![0u8; 32];
    let params = Params::new(65536, 4, 4, Some(32)).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    hasher.hash_password_into(master_password.as_bytes(), salt, &mut output)
        .map_err(|e| anyhow::anyhow!("Failed to derive key: {}", e))?;
    Ok(output)
}

fn encrypt_password(key: &[u8], password: &str) -> Result<String, anyhow::Error> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, password.as_bytes())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    let encoded = general_purpose::STANDARD.encode(combined);
    Ok(encoded)
}

fn decrypt_password(key: &[u8], encrypted: &str) -> Result<String, anyhow::Error> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    let combined = general_purpose::STANDARD.decode(encrypted)
        .map_err(|e| anyhow::anyhow!("Failed to decode base64: {}", e))?;

    if combined.len() < 12 {
        return Err(anyhow::anyhow!("Invalid encrypted data length"));
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

    String::from_utf8(plaintext)
        .map_err(|e| anyhow::anyhow!("Failed to convert to UTF-8: {}", e))
}

fn init_vault(password: &str, vault_path: &str) -> Result<(), anyhow::Error> {
    let expanded = expand_path(vault_path);
    let path = Path::new(&expanded);

    if path.exists() {
        return Err(anyhow::anyhow!("Vault already exists at {}", vault_path));
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let salt = rand::random::<[u8; 16]>();
    let mut master_key = derive_key(password, &salt)?;

    let vault = Vault {
        master_key_hash: general_purpose::STANDARD.encode(&salt),
        credentials: Vec::new(),
    };

    let json = serde_json::to_string(&vault)?;
    fs::write(path, json)?;

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
    let expanded = expand_path(vault_path);
    let path = Path::new(&expanded);

    if !path.exists() {
        return Err(anyhow::anyhow!("Vault does not exist. Run 'rust-pass init' first."));
    }

    let vault_json = fs::read_to_string(path)?;
    let mut vault: Vault = serde_json::from_str(&vault_json)?;

    println!("Enter master password:");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let master_password = input.trim();

    let salt = general_purpose::STANDARD.decode(&vault.master_key_hash)?;
    let mut key = derive_key(master_password, &salt)?;

    let password_value = if generate {
        generate_secure_password()
    } else if let Some(pwd) = password {
        pwd
    } else {
        return Err(anyhow::anyhow!("Password required unless --generate is specified"));
    };

    let encrypted_password = encrypt_password(&key, &password_value)?;

    if vault.credentials.iter().any(|c| c.service == service) {
        return Err(anyhow::anyhow!("Service '{}' already exists", service));
    }

    let credential = Credential {
        service: service.to_string(),
        username: username.to_string(),
        encrypted_password,
    };
    vault.credentials.push(credential);

    let updated_json = serde_json::to_string(&vault)?;
    fs::write(path, updated_json)?;

    for byte in key.iter_mut() {
        *byte = 0;
    }

    println!("Password generated: {}", password_value);

    Ok(())
}

fn get_credential(service: &str, vault_path: &str, copy: bool) -> Result<(), anyhow::Error> {
    let expanded = expand_path(vault_path);
    let path = Path::new(&expanded);

    if !path.exists() {
        return Err(anyhow::anyhow!("Vault does not exist. Run 'rust-pass init' first."));
    }

    let vault_json = fs::read_to_string(path)?;
    let vault: Vault = serde_json::from_str(&vault_json)?;

    let credential = vault.credentials.iter()
        .find(|c| c.service == service)
        .ok_or_else(|| anyhow::anyhow!("Service '{}' not found", service))?;

    println!("Enter master password:");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let master_password = input.trim();

    let salt = general_purpose::STANDARD.decode(&vault.master_key_hash)?;
    let mut key = derive_key(master_password, &salt)?;

    let decrypted_password = decrypt_password(&key, &credential.encrypted_password)?;

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
    let expanded = expand_path(vault_path);
    let path = Path::new(&expanded);

    if !path.exists() {
        return Err(anyhow::anyhow!("Vault does not exist. Run 'rust-pass init' first."));
    }

    let vault_json = fs::read_to_string(path)?;
    let vault: Vault = serde_json::from_str(&vault_json)?;

    println!("Stored services:");
    for credential in &vault.credentials {
        println!("  - {}", credential.service);
    }

    Ok(())
}

fn delete_credential(service: &str, vault_path: &str) -> Result<(), anyhow::Error> {
    let expanded = expand_path(vault_path);
    let path = Path::new(&expanded);

    if !path.exists() {
        return Err(anyhow::anyhow!("Vault does not exist. Run 'rust-pass init' first."));
    }

    let vault_json = fs::read_to_string(path)?;
    let mut vault: Vault = serde_json::from_str(&vault_json)?;

    let index = vault.credentials.iter()
        .position(|c| c.service == service)
        .ok_or_else(|| anyhow::anyhow!("Service '{}' not found", service))?;

    println!("Enter master password:");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let master_password = input.trim();

    let salt = general_purpose::STANDARD.decode(&vault.master_key_hash)?;
    let mut key = derive_key(master_password, &salt)?;

    vault.credentials.remove(index);

    let updated_json = serde_json::to_string(&vault)?;
    fs::write(path, updated_json)?;

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
