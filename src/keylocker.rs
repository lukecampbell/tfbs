use std::env::VarError;

use argon2::{Argon2, ParamsBuilder, Version};
use base64::prelude::*;
use base64::DecodeError;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::Payload;
use chacha20poly1305::Key;
use chacha20poly1305::KeyInit;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XNonce;
use hkdf::Hkdf;
use rand::Rng;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use sha2::Sha256;
use uuid::Uuid;

#[derive(thiserror::Error, Debug)]
pub enum ServerKeyError {
    #[error("VarError: {0}")]
    Var(#[from] VarError),

    #[error("Decode: {0}")]
    Decode(#[from] DecodeError),

    #[error("KeyLength: Server Key size is invalid. Must be 32 bytes")]
    KeyLength,
}

/// Loads the 32-byte server key from the `SERVER_KEY` environment variable (base64-encoded).
pub fn get_server_key() -> Result<[u8; 32], ServerKeyError> {
    let server_key = std::env::var("SERVER_KEY")?;
    let key = BASE64_STANDARD.decode(server_key)?;
    if key.len() != 32 {
        return Err(ServerKeyError::KeyLength);
    }
    let valid_key: [u8; 32] = key.try_into().unwrap();
    Ok(valid_key)
}

#[derive(thiserror::Error, Debug)]
pub enum KdfError {
    #[error("UserKey: Failed to derive user key: {0}")]
    User(argon2::Error),

    #[error("OutputKey: Failed to derive output key: {0}")]
    OutputKey(#[from] hkdf::InvalidLength),
}

#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("ServerKeyError: {0}")]
    ServerKey(#[from] ServerKeyError),

    #[error("KdfError: {0}")]
    Kdf(#[from] KdfError),

    #[error("ChaCha20Poly1305Error: {0}")]
    ChaCha20Poly1305(chacha20poly1305::Error),
}

pub struct ArgonKeyDerivation;

impl ArgonKeyDerivation {
    // Default parameters for the profile
    pub const DEFAULT_M_COST: u32 = 0x4C00;
    pub const DEFAULT_T_COST: u32 = 0x2;
    pub const DEFAULT_P_COST: u32 = 0x1;

    /// Derives a 32-byte user key from a passphrase and per-user salt using Argon2id.
    pub fn get_user_key(passphrase: &str, salt: &[u8; 16]) -> Result<[u8; 32], KdfError> {
        let params = ParamsBuilder::new()
            .m_cost(Self::DEFAULT_M_COST)
            .t_cost(Self::DEFAULT_T_COST)
            .p_cost(Self::DEFAULT_P_COST)
            .build()
            .map_err(KdfError::User)?;
        let argon = Argon2::new(argon2::Algorithm::Argon2id, Version::default(), params);
        let mut key = [0u8; 32];
        argon
            .hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .map_err(KdfError::User)?;
        Ok(key)
    }

    /// Combines the user-derived key with the server key via HKDF-SHA256 to produce the final
    /// 32-byte encryption key. The server key acts as salt, ensuring that compromise of the
    /// database alone cannot be used to brute-force user passphrases.
    pub fn get_final_key(user_key: &[u8; 32], server_key: &[u8; 32]) -> Result<[u8; 32], KdfError> {
        let kdf = Hkdf::<Sha256>::new(Some(server_key), user_key);
        let info = "tfbs-keylocker-v1";
        let mut okm = [0u8; 32];
        kdf.expand(info.as_bytes(), &mut okm)?;
        Ok(okm)
    }
}

pub struct ChaChaEncryption;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CryptEntry {
    #[serde(
        rename = "n",
        serialize_with = "serialize_b64",
        deserialize_with = "deserialize_nonce"
    )]
    nonce: [u8; 24],
    #[serde(
        rename = "ct",
        serialize_with = "serialize_b64",
        deserialize_with = "deserialize_ciphertext"
    )]
    ciphertext: Vec<u8>,
}

fn serialize_b64<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&BASE64_STANDARD.encode(value))
}

fn deserialize_nonce<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 24], D::Error> {
    let s: &str = Deserialize::deserialize(deserializer)?;
    let bytes = BASE64_STANDARD
        .decode(s)
        .map_err(serde::de::Error::custom)?;
    bytes
        .try_into()
        .map_err(|_| serde::de::Error::custom("expected 24 bytes for nonce"))
}

fn deserialize_ciphertext<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s: &str = Deserialize::deserialize(deserializer)?;
    BASE64_STANDARD.decode(s).map_err(serde::de::Error::custom)
}

impl ChaChaEncryption {
    /// Constructs the AEAD associated data by concatenating user_id and entry_id.
    /// This binds each ciphertext to its owner and row, preventing row-swapping attacks.
    fn make_ad(user_id: &Uuid, entry_id: &Uuid) -> [u8; 32] {
        let mut ad = [0u8; 32];
        ad[..16].copy_from_slice(user_id.as_bytes());
        ad[16..].copy_from_slice(entry_id.as_bytes());
        ad
    }
    /// Encrypts plaintext with XChaCha20-Poly1305 using AD binding.
    /// A random 24-byte nonce is generated if one is not provided.
    pub fn encrypt(
        encryption_key: &[u8; 32],
        plaintext: &[u8],
        nonce: Option<&[u8; 24]>,
        user_id: &Uuid,
        entry_id: &Uuid,
    ) -> Result<CryptEntry, chacha20poly1305::Error> {
        let mut rng = rand::rng();
        let ad = Self::make_ad(user_id, entry_id);

        // Use provided nonce or generate a random one
        let nonce = match nonce {
            Some(n) => *n,
            None => {
                let mut buf = [0u8; 24];
                rng.fill_bytes(&mut buf);
                buf
            }
        };

        // Encrypt with associated data binding ciphertext to this user/entry pair
        let mykey = Key::from_slice(encryption_key);
        let cipher = XChaCha20Poly1305::new(mykey);
        let nonce_array = GenericArray::from_slice(&nonce);
        let payload = Payload {
            msg: plaintext,
            aad: &ad,
        };
        let ciphertext = cipher.encrypt(nonce_array, payload)?;
        Ok(CryptEntry { nonce, ciphertext })
    }

    /// Decrypts a CryptEntry using XChaCha20-Poly1305 with AD binding.
    /// The AD is reconstructed from the row's user_id and entry_id — not read from stored data —
    /// so that a row moved between users or entries will fail authentication.
    pub fn decrypt(
        encryption_key: &[u8; 32],
        crypt_entry: &CryptEntry,
        user_id: &Uuid,
        entry_id: &Uuid,
    ) -> Result<Vec<u8>, chacha20poly1305::Error> {
        let key = Key::from_slice(encryption_key);
        let ad = Self::make_ad(user_id, entry_id);
        let cipher = XChaCha20Poly1305::new(key);
        let nonce = GenericArray::from_slice(&crypt_entry.nonce);
        let payload = Payload {
            msg: &crypt_entry.ciphertext,
            aad: &ad,
        };
        cipher.decrypt(nonce, payload)
    }
}

pub struct ServerSideEncryption;

impl ServerSideEncryption {
    /// Encrypts plaintext using a key derived solely from the server key.
    /// Used for hint data that should be recoverable without the user's passphrase,
    /// but still encrypted at rest in the database.
    pub fn encrypt(plaintext: &[u8]) -> Result<CryptEntry, CryptoError> {
        let mut rng = rand::rng();

        // Derive a dedicated encryption key from the server key using a hints-specific context
        let server_key = get_server_key()?;
        let mut okm = [0u8; 32];
        Hkdf::<Sha256>::new(None, &server_key)
            .expand(b"tfbs-keylocker-hints-v1", &mut okm)
            .map_err(KdfError::from)?;

        // Encrypt with a random nonce
        let nonce = {
            let mut buf = [0u8; 24];
            rng.fill_bytes(&mut buf);
            buf
        };
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&okm));
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .map_err(CryptoError::ChaCha20Poly1305)?;

        Ok(CryptEntry { ciphertext, nonce })
    }

    /// Decrypts a CryptEntry that was encrypted with the server-side hints key.
    pub fn decrypt(crypt_entry: &CryptEntry) -> Result<Vec<u8>, CryptoError> {
        // Derive the same hints key from the server key
        let server_key = get_server_key()?;
        let mut okm = [0u8; 32];
        Hkdf::<Sha256>::new(None, &server_key)
            .expand(b"tfbs-keylocker-hints-v1", &mut okm)
            .map_err(KdfError::from)?;

        let nonce = XNonce::from_slice(&crypt_entry.nonce);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&okm));
        let plaintext = cipher
            .decrypt(nonce, crypt_entry.ciphertext.as_slice())
            .map_err(CryptoError::ChaCha20Poly1305)?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Display;

    use pretty_hex::*;
    use rand::rngs::ThreadRng;
    use rand::Rng;

    use crate::keylocker::ChaChaEncryption;

    use super::ArgonKeyDerivation;
    fn to_anyhow<E: Display>(e: E) -> anyhow::Error {
        anyhow::anyhow!("{e}")
    }

    #[test]
    fn test_key_construction() -> anyhow::Result<()> {
        let mut salt = [0u8; 16];
        let mut rng = ThreadRng::default();
        rng.fill_bytes(&mut salt);
        let user_ikm =
            ArgonKeyDerivation::get_user_key("bob", &salt).map_err(|e| anyhow::anyhow!("{e}"))?;
        let server_key = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let final_key = ArgonKeyDerivation::get_final_key(&user_ikm, &server_key)?;
        println!("{:?}", final_key.hex_dump());
        Ok(())
    }

    #[test]
    fn test_encryption() -> anyhow::Result<()> {
        let mut rng = ThreadRng::default();
        let mut encryption_key = [0u8; 32];
        rng.fill_bytes(&mut encryption_key);
        let plaintext = b"this is a secret";
        let user_id = uuid::uuid!("25439966-8cb2-4560-95c2-e2f090507aff");
        let entry_id = uuid::uuid!("d5f23ade-5014-421c-9f6f-e9820f911f24");
        let crypt_entry =
            ChaChaEncryption::encrypt(&encryption_key, plaintext, None, &user_id, &entry_id)
                .map_err(to_anyhow)?;
        println!("{:?}", crypt_entry.ciphertext.hex_dump());
        let round_trip =
            ChaChaEncryption::decrypt(&encryption_key, &crypt_entry, &user_id, &entry_id)
                .map_err(to_anyhow)?;
        println!("{:?}", round_trip.hex_dump());
        assert_eq!(round_trip.as_slice(), plaintext);
        Ok(())
    }
}
