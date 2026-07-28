//! `crypto` command namespace.
//! Cryptographic operations accessible from the CLI.

use clap::{Args, Subcommand};
use ucx_crypto::{hash, HashAlgorithm, SymmetricKey, Aes256GcmCipher, SymmetricCipher, Nonce, EncryptedData};

#[derive(Debug, Args)]
pub struct CryptoArgs {
    #[command(subcommand)]
    pub command: CryptoCommands,
}

#[derive(Debug, Subcommand)]
pub enum CryptoCommands {
    /// Compute a hash of a file or data.
    Hash(HashArgs),
    /// Encrypt a file.
    Encrypt(EncryptArgs),
    /// Decrypt a file.
    Decrypt(DecryptArgs),
    /// Generate a new key.
    Keygen(KeygenArgs),
}

#[derive(Debug, Args)]
pub struct HashArgs {
    /// Path to file or data string.
    pub target: String,
    /// Hash algorithm (sha256, sha512, blake3).
    #[arg(long, default_value = "sha256")]
    pub algorithm: String,
    /// Whether target is raw data (not a file path).
    #[arg(long)]
    pub raw: bool,
}

#[derive(Debug, Args)]
pub struct EncryptArgs {
    /// Input file path.
    pub input: String,
    /// Output file path.
    pub output: String,
    /// Hex-encoded key (32 bytes = 64 hex chars).
    #[arg(long)]
    pub key: Option<String>,
}

#[derive(Debug, Args)]
pub struct DecryptArgs {
    /// Input encrypted file.
    pub input: String,
    /// Output decrypted file.
    pub output: String,
    /// Hex-encoded key.
    #[arg(long)]
    pub key: Option<String>,
}

#[derive(Debug, Args)]
pub struct KeygenArgs {
    /// Type of key (symmetric, ed25519).
    #[arg(long, default_value = "symmetric")]
    pub key_type: String,
    /// Output file.
    #[arg(short, long)]
    pub output: Option<String>,
}

pub async fn execute(args: &CryptoArgs) -> Result<(), String> {
    match &args.command {
        CryptoCommands::Hash(hargs) => compute_hash(hargs).await,
        CryptoCommands::Encrypt(eargs) => encrypt_file(eargs).await,
        CryptoCommands::Decrypt(dargs) => decrypt_file(dargs).await,
        CryptoCommands::Keygen(kargs) => generate_key(kargs).await,
    }
}

async fn compute_hash(args: &HashArgs) -> Result<(), String> {
    let algorithm = match args.algorithm.to_lowercase().as_str() {
        "sha256" => HashAlgorithm::Sha256,
        "sha512" => HashAlgorithm::Sha512,
        "blake3" => HashAlgorithm::Blake3,
        other => return Err(format!("unsupported algorithm: {other}")),
    };

    let result = if args.raw {
        hash(args.target.as_bytes(), algorithm)
    } else {
        let path = std::path::Path::new(&args.target);
        if !path.exists() {
            return Err(format!("file not found: {}", args.target));
        }
        let data = std::fs::read(path).map_err(|e| e.to_string())?;
        hash(&data, algorithm)
    };

    println!("Hash ({:?}):", algorithm);
    println!("  {}", result.to_hex());
    Ok(())
}

async fn encrypt_file(args: &EncryptArgs) -> Result<(), String> {
    let input_path = std::path::Path::new(&args.input);
    if !input_path.exists() {
        return Err(format!("input file not found: {}", args.input));
    }

    let key = match &args.key {
        Some(hex_key) => {
            let bytes = hex::decode(hex_key).map_err(|e| format!("invalid key hex: {e}"))?;
            SymmetricKey::from_slice(&bytes).map_err(|e| e.to_string())?
        }
        None => {
            println!("No key provided. Generating new key...");
            SymmetricKey::generate()
        }
    };

    let data = std::fs::read(input_path).map_err(|e| e.to_string())?;
    let cipher = Aes256GcmCipher::new();
    let nonce = Nonce::generate_12();

    let encrypted = cipher
        .encrypt(&key, &nonce, &data, None)
        .map_err(|e| e.to_string())?;

    // Serialize encrypted data to JSON
    let json = serde_json::to_string_pretty(&encrypted).map_err(|e| e.to_string())?;
    std::fs::write(&args.output, &json).map_err(|e| e.to_string())?;

    println!("Encrypted: {} -> {}", args.input, args.output);
    println!("Key (hex, save this!): {}", hex::encode(key.as_bytes()));

    Ok(())
}

async fn decrypt_file(args: &DecryptArgs) -> Result<(), String> {
    let input_path = std::path::Path::new(&args.input);
    if !input_path.exists() {
        return Err(format!("input file not found: {}", args.input));
    }

    let key = match &args.key {
        Some(hex_key) => {
            let bytes = hex::decode(hex_key).map_err(|e| format!("invalid key hex: {e}"))?;
            SymmetricKey::from_slice(&bytes).map_err(|e| e.to_string())?
        }
        None => return Err("key required for decryption (use --key)".into()),
    };

    let json = std::fs::read_to_string(input_path).map_err(|e| e.to_string())?;
    let encrypted: EncryptedData = serde_json::from_str(&json).map_err(|e| e.to_string())?;

    let cipher = Aes256GcmCipher::new();
    let decrypted = cipher.decrypt(&key, &encrypted).map_err(|e| e.to_string())?;

    std::fs::write(&args.output, &decrypted).map_err(|e| e.to_string())?;
    println!("Decrypted: {} -> {}", args.input, args.output);

    Ok(())
}

async fn generate_key(args: &KeygenArgs) -> Result<(), String> {
    match args.key_type.to_lowercase().as_str() {
        "symmetric" => {
            let key = SymmetricKey::generate();
            let hex = hex::encode(key.as_bytes());
            println!("Symmetric Key (AES-256):");
            println!("  {}", hex);
            if let Some(output) = &args.output {
                std::fs::write(output, &hex).map_err(|e| e.to_string())?;
                println!("  Saved to: {output}");
            }
        }
        "ed25519" => {
            let kp = ucx_crypto::SignatureKeypair::generate();
            let secret_hex = hex::encode(kp.secret_key_bytes());
            let public_hex = hex::encode(kp.public_key().as_bytes());
            println!("Ed25519 Keypair:");
            println!("  Secret: {secret_hex}");
            println!("  Public: {public_hex}");
        }
        other => return Err(format!("unsupported key type: {other}")),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_hash_sha256() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let args = HashArgs {
            target: "hello".into(),
            algorithm: "sha256".into(),
            raw: true,
        };
        let result = rt.block_on(compute_hash(&args));
        assert!(result.is_ok());
    }

    #[test]
    fn test_compute_hash_unsupported() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let args = HashArgs {
            target: "test".into(),
            algorithm: "md5".into(),
            raw: true,
        };
        let result = rt.block_on(compute_hash(&args));
        assert!(result.is_err());
    }
}
