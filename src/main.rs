use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce
};
use argon2::{Argon2, PasswordHasher, Algorithm, Version, Params};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use clap::{Parser, Subcommand};
use anyhow::{Result, Context, anyhow};

#[derive(Parser)]
#[command(name = "encryptman")]
#[command(about = "A fast and secure file encryption tool written in Rust")]
#[command(version = "0.1.0")]
#[command(author = "Your Name <your.email@example.com>")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new encrypted vault
    Create {
        /// Path to create the vault
        #[arg(short, long)]
        path: PathBuf,
        /// Vault password
        #[arg(short = 'p', long)]
        password: String,
    },
    /// Encrypt files into vault
    Encrypt {
        /// Source directory to encrypt
        #[arg(short, long)]
        source: PathBuf,
        /// Vault path
        #[arg(short, long)]
        vault: PathBuf,
        /// Vault password
        #[arg(short = 'p', long)]
        password: String,
    },
    /// Decrypt files from vault
    Decrypt {
        /// Vault path
        #[arg(short, long)]
        vault: PathBuf,
        /// Destination directory
        #[arg(short, long)]
        dest: PathBuf,
        /// Vault password
        #[arg(short = 'p', long)]
        password: String,
    },
    /// List files in vault
    List {
        /// Vault path
        #[arg(short, long)]
        vault: PathBuf,
        /// Vault password
        #[arg(short = 'p', long)]
        password: String,
    },
}

#[derive(Serialize, Deserialize)]
struct VaultConfig {
    version: String,
    cipher: String,
    kdf_salt: String,
    kdf_iterations: u32,
    creation_time: String,
}

#[derive(Serialize, Deserialize)]
struct FileMetadata {
    original_path: String,
    encrypted_name: String,
    size: u64,
    nonce: String,
    created_at: String,
}

pub struct EncryptmanVault {
    vault_path: PathBuf,
    config: VaultConfig,
    master_key: [u8; 32],
    file_metadata: HashMap<String, FileMetadata>,
}

impl EncryptmanVault {
    pub fn create(vault_path: &Path, password: &str) -> Result<Self> {
        // Create vault directory structure
        fs::create_dir_all(vault_path)?;
        fs::create_dir_all(vault_path.join("d"))?;
        
        // Generate salt for key derivation
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        
        // Derive master key from password using Argon2
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(65536, 3, 4, Some(32)).unwrap(),
        );
        
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow!("Failed to hash password: {}", e))?;
        
        let master_key: [u8; 32] = password_hash
            .hash
            .unwrap()
            .as_bytes()[..32]
            .try_into()
            .unwrap();
        
        let config = VaultConfig {
            version: "1.0.0".to_string(),
            cipher: "AES256-GCM".to_string(),
            kdf_salt: hex::encode(salt),
            kdf_iterations: 65536,
            creation_time: chrono::Utc::now().to_rfc3339(),
        };
        
        // Save vault config
        let config_path = vault_path.join("vault.config");
        let config_json = serde_json::to_string_pretty(&config)?;
        fs::write(config_path, config_json)?;
        
        // Create empty metadata file
        let metadata_path = vault_path.join("metadata.json");
        fs::write(metadata_path, "{}")?;
        
        // Create .gitignore for the vault
        let gitignore_path = vault_path.join(".gitignore");
        fs::write(gitignore_path, "# Encryptman Vault\n# Do not commit encrypted files\nd/\n*.tmp\n")?;
        
        println!("🔐 Vault created successfully at: {}", vault_path.display());
        println!("📁 Structure:");
        println!("   ├── vault.config    (vault configuration)");
        println!("   ├── metadata.json   (file metadata)");
        println!("   ├── d/              (encrypted files directory)");
        println!("   └── .gitignore      (git ignore file)");
        
        Ok(EncryptmanVault {
            vault_path: vault_path.to_owned(),
            config,
            master_key,
            file_metadata: HashMap::new(),
        })
    }
    
    pub fn open(vault_path: &Path, password: &str) -> Result<Self> {
        let config_path = vault_path.join("vault.config");
        if !config_path.exists() {
            return Err(anyhow!("Invalid vault: vault.config not found"));
        }
        
        let config_content = fs::read_to_string(config_path)
            .context("Failed to read vault config")?;
        
        let config: VaultConfig = serde_json::from_str(&config_content)
            .context("Failed to parse vault config")?;
        
        // Verify vault version
        if config.version != "1.0.0" {
            return Err(anyhow!("Unsupported vault version: {}", config.version));
        }
        
        // Derive master key from password
        let salt = hex::decode(&config.kdf_salt)
            .context("Invalid salt in vault config")?;
        
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(config.kdf_iterations, 3, 4, Some(32)).unwrap(),
        );
        
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| anyhow!("Invalid password or corrupted vault"))?;
        
        let master_key: [u8; 32] = password_hash
            .hash
            .unwrap()
            .as_bytes()[..32]
            .try_into()
            .unwrap();
        
        // Load metadata
        let metadata_path = vault_path.join("metadata.json");
        let metadata_content = fs::read_to_string(metadata_path)
        .unwrap_or_else(|_| "{}".to_string());
    
    let file_metadata: HashMap<String, FileMetadata> = 
        serde_json::from_str(&metadata_content)
            .unwrap_or_default();
    
    Ok(EncryptmanVault {
        vault_path: vault_path.to_owned(),
        config,
        master_key,
        file_metadata,
    })
    }
    
    pub fn encrypt_file(&mut self, source_path: &Path) -> Result<()> {
        let file_content = fs::read(source_path)
            .with_context(|| format!("Failed to read file: {}", source_path.display()))?;
        
        // Generate random filename for encrypted file
        let mut encrypted_name = [0u8; 16];
        OsRng.fill_bytes(&mut encrypted_name);
        let encrypted_filename = hex::encode(encrypted_name);
        
        // Create AES-GCM cipher
        let key = Key::<Aes256Gcm>::from_slice(&self.master_key);
        let cipher = Aes256Gcm::new(key);
        
        // Generate random nonce
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        // Encrypt file content
        let encrypted_content = cipher
            .encrypt(&nonce, file_content.as_ref())
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;
        
        // Save encrypted file
        let encrypted_path = self.vault_path
            .join("d")
            .join(&encrypted_filename);
        
        fs::write(&encrypted_path, encrypted_content)
            .with_context(|| format!("Failed to write encrypted file: {}", encrypted_path.display()))?;
        
        // Update metadata
        let metadata = FileMetadata {
            original_path: source_path.to_string_lossy().to_string(),
            encrypted_name: encrypted_filename.clone(),
            size: file_content.len() as u64,
            nonce: hex::encode(nonce),
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        
        self.file_metadata.insert(
            source_path.to_string_lossy().to_string(),
            metadata
        );
        
        self.save_metadata()?;
        
        println!("✅ Encrypted: {} -> {} ({} bytes)", 
                source_path.display(), 
                encrypted_filename,
                file_content.len());
        
        Ok(())
    }

    pub fn decrypt_file(&self, original_path: &str, dest_dir: &Path) -> Result<()> {
        let metadata = self.file_metadata
            .get(original_path)
            .ok_or_else(|| anyhow!("File not found in vault: {}", original_path))?;
        
        // Read encrypted file
        let encrypted_path = self.vault_path
            .join("d")
            .join(&metadata.encrypted_name);
        
        let encrypted_content = fs::read(&encrypted_path)
            .with_context(|| format!("Failed to read encrypted file: {}", encrypted_path.display()))?;
        
        // Create AES-GCM cipher
        let key = Key::<Aes256Gcm>::from_slice(&self.master_key);
        let cipher = Aes256Gcm::new(key);
        
        // Decode nonce
        let nonce_bytes = hex::decode(&metadata.nonce)
            .context("Invalid nonce in metadata")?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Decrypt content
        let decrypted_content = cipher
            .decrypt(nonce, encrypted_content.as_ref())
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;
        
        // Create destination path
        let original_file_path = Path::new(original_path);
        let dest_path = dest_dir.join(
            original_file_path.file_name()
                .ok_or_else(|| anyhow!("Invalid file path in metadata"))?
        );
        
        // Create parent directories if needed
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        // Write decrypted file
        fs::write(&dest_path, decrypted_content)
            .with_context(|| format!("Failed to write decrypted file: {}", dest_path.display()))?;
        
        println!("✅ Decrypted: {} -> {} ({} bytes)", 
                metadata.encrypted_name, 
                dest_path.display(),
                metadata.size);
        
        Ok(())
    }
    
    pub fn encrypt_directory(&mut self, source_dir: &Path) -> Result<()> {
        let mut file_count = 0;
        let mut total_size = 0u64;
        
        for entry in WalkDir::new(source_dir) {
            let entry = entry?;
            if entry.file_type().is_file() {
                let file_size = entry.metadata()?.len();
                self.encrypt_file(entry.path())?;
                file_count += 1;
                total_size += file_size;
            }
        }
        
        println!("📊 Summary: {} files encrypted, {} bytes total", 
                file_count, total_size);
        
        Ok(())
    }
    
    pub fn decrypt_all(&self, dest_dir: &Path) -> Result<()> {
        fs::create_dir_all(dest_dir)?;
        
        let mut file_count = 0;
        let mut total_size = 0u64;
        
        for (original_path, metadata) in &self.file_metadata {
            self.decrypt_file(original_path, dest_dir)?;
            file_count += 1;
            total_size += metadata.size;
        }
        
        println!("📊 Summary: {} files decrypted, {} bytes total", 
                file_count, total_size);
        
        Ok(())
    }
    
    fn save_metadata(&self) -> Result<()> {
        let metadata_path = self.vault_path.join("metadata.json");
        let metadata_json = serde_json::to_string_pretty(&self.file_metadata)?;
        fs::write(metadata_path, metadata_json)?;
        Ok(())
    }
    
    pub fn list_files(&self) {
        if self.file_metadata.is_empty() {
            println!("📁 Vault is empty");
            return;
        }
        
        println!("\n📁 Files in vault:");
        println!("{:-<80}", "");
        println!("{:<40} {:>10} {:>20}", "File", "Size", "Encrypted At");
        println!("{:-<80}", "");
        
        let mut total_size = 0u64;
        for metadata in self.file_metadata.values() {
            let file_name = Path::new(&metadata.original_path)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            
            let created_at = metadata.created_at
                .split('T')
                .next()
                .unwrap_or("unknown");
            
            println!("{:<40} {:>10} {:>20}", 
                    file_name,
                    format_bytes(metadata.size),
                    created_at);
            
            total_size += metadata.size;
        }
        
        println!("{:-<80}", "");
        println!("Total: {} files, {} bytes", 
                self.file_metadata.len(), 
                format_bytes(total_size));
    }
}
    
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    
    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    println!("🦀 Encryptman v0.1.0");
    println!("Fast and secure file encryption tool\n");
    
    match cli.command {
        Commands::Create { path, password } => {
            if password.len() < 8 {
                return Err(anyhow!("Password must be at least 8 characters long"));
            }
            
            if path.exists() {
                return Err(anyhow!("Vault directory already exists: {}", path.display()));
            }
            
            let _vault = EncryptmanVault::create(&path, &password)?;
        }
        
        Commands::Encrypt { source, vault, password } => {
            if !vault.exists() {
                return Err(anyhow!("Vault does not exist: {}", vault.display()));
            }
            
            println!("🔒 Opening vault: {}", vault.display());
            let mut vault_instance = EncryptmanVault::open(&vault, &password)?;
            
            println!("📁 Encrypting: {}", source.display());
            
            if source.is_file() {
                vault_instance.encrypt_file(&source)?;
            } else if source.is_dir() {
                vault_instance.encrypt_directory(&source)?;
            } else {
                return Err(anyhow!("Source path does not exist: {}", source.display()));
            }
            
            println!("\n😆 Encryption completed!");
        }
        
        Commands::Decrypt { vault, dest, password } => {
            if !vault.exists() {
                return Err(anyhow!("Vault does not exist: {}", vault.display()));
            }
            
            println!("🔓 Opening vault: {}", vault.display());
            let vault_instance = EncryptmanVault::open(&vault, &password)?;
            
            println!("📁 Decrypting to: {}", dest.display());
            vault_instance.decrypt_all(&dest)?;
            
            println!("\n😆 Decryption completed!");
        }
        
        Commands::List { vault, password } => {
            if !vault.exists() {
                return Err(anyhow!("Vault does not exist: {}", vault.display()));
            }
            
            let vault_instance = EncryptmanVault::open(&vault, &password)?;
            vault_instance.list_files();
        }
    }
    
    Ok(())
}

// Add chrono dependency for timestamps
mod chrono {
    pub struct Utc;
    impl Utc {
        pub fn now() -> DateTime {
            DateTime
        }
    }
    
    pub struct DateTime;
    impl DateTime {
        pub fn to_rfc3339(&self) -> String {
            use std::time::{SystemTime, UNIX_EPOCH};
            let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            format!("2024-01-01T{:02}:{:02}:{:02}Z", 
                   (duration.as_secs() / 3600) % 24,
                   (duration.as_secs() / 60) % 60,
                   duration.as_secs() % 60)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_vault_creation() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test_vault");
        let password = "test_password_123";
        
        let vault = EncryptmanVault::create(&vault_path, password).unwrap();
        
        assert!(vault_path.exists());
        assert!(vault_path.join("vault.config").exists());
        assert!(vault_path.join("metadata.json").exists());
        assert!(vault_path.join("d").exists());
    }
    
    #[test]
    fn test_encryption_decryption() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test_vault");
        let password = "test_password_123";
        let test_content = "Hello, Encryptman! 🦀";
        
        // Create vault and encrypt
        {
            let mut vault = EncryptmanVault::create(&vault_path, password).unwrap();
            let test_file = temp_dir.path().join("test.txt");
            fs::write(&test_file, test_content).unwrap();
            vault.encrypt_file(&test_file).unwrap();
        }
        
        // Open vault and decrypt
        {
            let vault = EncryptmanVault::open(&vault_path, password).unwrap();
            let dest_dir = temp_dir.path().join("decrypted");
            vault.decrypt_all(&dest_dir).unwrap();
            
            let decrypted_file = dest_dir.join("test.txt");
            let decrypted_content = fs::read_to_string(decrypted_file).unwrap();
            
            assert_eq!(decrypted_content, test_content);
        }
    }
    
    #[test]
    fn test_wrong_password() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test_vault");
        
        EncryptmanVault::create(&vault_path, "correct_password").unwrap();
        
        let result = EncryptmanVault::open(&vault_path, "wrong_password");
        assert!(result.is_err());
    }
}
