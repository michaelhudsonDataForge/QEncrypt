use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rand::rngs::OsRng;
use rand::RngCore;
use rpassword::prompt_password;
use zeroize::Zeroize;

use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{PasswordHash, PasswordHasher as _, SaltString};
use argon2::{Algorithm, Params, Version};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

/// Simple file encryptor using Argon2id + XChaCha20-Poly1305 (AEAD)
#[derive(Parser)]
#[command(name = "rse", version, about = "Rust Simple Encryptor")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Encrypt a file to <output>
    Encrypt { input: PathBuf, output: PathBuf },
    /// Decrypt a file to <output>
    Decrypt { input: PathBuf, output: PathBuf },
}

// File format:
// [ magic: 4 bytes "RSE1" ]
// [ salt_len: u8 ] [ salt bytes ]
// [ nonce: 24 bytes ]
// [ ciphertext ... ]
const MAGIC: &[u8; 4] = b"RSE1";
const NONCE_LEN: usize = 24; // XChaCha20-Poly1305 nonce

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Encrypt { input, output } => encrypt_cmd(&input, &output),
        Cmd::Decrypt { input, output } => decrypt_cmd(&input, &output),
    }
}

fn encrypt_cmd(input: &PathBuf, output: &PathBuf) -> Result<()> {
    // read plaintext
    let mut plaintext = fs::read(input)
        .with_context(|| format!("reading input file {:?}", input))?;

    // prompt for password
    let mut password = prompt_password("Password: ")?;
    let mut confirm  = prompt_password("Confirm password: ")?;
    if password != confirm {
        confirm.zeroize();
        password.zeroize();
        anyhow::bail!("passwords do not match");
    }
    confirm.zeroize();

    // derive key with Argon2id
    // Params: ~19 MB memory, 2 passes, 1 lane (adjust up for stronger)
    let params = Params::new(19 * 1024, 2, 1, Some(32))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // random salt
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .context("deriving key")?;
    password.zeroize();

    // Extract raw hash bytes (32 bytes defined above)
    let raw_hash = hash.hash.ok_or_else(|| anyhow::anyhow!("missing hash"))?;
    let key = Key::from_slice(raw_hash.as_bytes());

    // AEAD
    let cipher = XChaCha20Poly1305::new(key);

    // random 24-byte nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    // encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .context("encrypting")?;

    // we no longer need plaintext
    plaintext.zeroize();

    // write output
    let mut f = File::create(output)
        .with_context(|| format!("creating output file {:?}", output))?;

    f.write_all(MAGIC)?;                        // magic
    f.write_all(&[salt.as_salt().as_str().len() as u8])?; // salt length (fits typical SaltString)
    f.write_all(salt.as_salt().as_str().as_bytes())?;     // salt bytes
    f.write_all(&nonce_bytes)?;                 // nonce
    f.write_all(&ciphertext)?;                  // ciphertext
    f.flush()?;

    println!("Encrypted → {:?}", output);
    Ok(())
}

fn decrypt_cmd(input: &PathBuf, output: &PathBuf) -> Result<()> {
    let mut data = fs::read(input)
        .with_context(|| format!("reading input file {:?}", input))?;
    let mut cursor = 0usize;

    // check magic
    if data.len() < MAGIC.len() || &data[0..4] != MAGIC {
        anyhow::bail!("invalid file: bad magic");
    }
    cursor += 4;

    // salt
    if cursor >= data.len() { anyhow::bail!("truncated file (salt length)"); }
    let salt_len = data[cursor] as usize;
    cursor += 1;

    if cursor + salt_len + NONCE_LEN > data.len() {
        anyhow::bail!("truncated file (salt/nonce)");
    }
    let salt_bytes = &data[cursor..cursor + salt_len];
    cursor += salt_len;

    // nonce
    let nonce_slice = &data[cursor..cursor + NONCE_LEN];
    cursor += NONCE_LEN;

    let ciphertext = &data[cursor..];

    // prompt password
    let mut password = prompt_password("Password: ")?;

    // re-derive key
    let params = Params::new(19 * 1024, 2, 1, Some(32))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Build a fake PHC string so we can reuse argon2 parsing
    let phc_string = format!(
        "$argon2id$v=19$m=19456,t=2,p=1${}${}",
        base64::encode_config("", base64::STANDARD_NO_PAD), // no salt in this field
        base64::encode_config("", base64::STANDARD_NO_PAD)  // no hash here either
    );
    // We won’t actually use this PHC; we’ll call hash_password manually with our real salt.
    // But Argon2 crate wants a SaltString, so parse the salt into that.
    let salt_str = std::str::from_utf8(salt_bytes).context("salt utf8")?;
    let salt = SaltString::new(salt_str).context("salt parse")?;

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .context("deriving key")?;
    password.zeroize();

    let raw_hash = hash.hash.ok_or_else(|| anyhow::anyhow!("missing hash"))?;
    let key = Key::from_slice(raw_hash.as_bytes());
    let cipher = XChaCha20Poly1305::new(key);

    let nonce = XNonce::from_slice(nonce_slice);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .context("decryption failed (bad password or corrupted file)")?;

    // write plaintext
    let mut f = File::create(output)
        .with_context(|| format!("creating output file {:?}", output))?;
    f.write_all(&plaintext)?;
    f.flush()?;

    println!("Decrypted → {:?}", output);
    Ok(())
}
