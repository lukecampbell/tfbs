use std::env::VarError;

use argon2::{Argon2, ParamsBuilder, Version};
use base64::DecodeError;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::Payload;
use chacha20poly1305::Key;
use chacha20poly1305::KeyInit;
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use sha2::Sha256;
use uuid::Uuid;
use base64::prelude::*;

#[derive(thiserror::Error, Debug)]
pub enum ServerKeyError {
    #[error("VarError: {0}")]
    VarError(#[from] VarError),

    #[error("Decode: {0}")]
    DecodeError(#[from] DecodeError),

    #[error("KeyLength: Server Key size is invalid. Must be 32 bytes")]
    KeyLength,
}


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
    UserKey(argon2::Error),

    #[error("OutputKey: Failed to derive output key: {0}")]
    OutputKey(#[from] hkdf::InvalidLength)
}

pub struct ArgonKeyDerivation;

impl ArgonKeyDerivation {
    // Default parameters for the profile
    pub const DEFAULT_M_COST: u32 = 0x4C00;
    pub const DEFAULT_T_COST: u32 = 0x2;
    pub const DEFAULT_P_COST: u32 = 0x1;

    pub fn get_user_key(passphrase: &str, salt: &[u8; 16]) -> Result<[u8; 32], KdfError> {
        let params = ParamsBuilder::new()
            .m_cost(Self::DEFAULT_M_COST)
            .t_cost(Self::DEFAULT_T_COST)
            .p_cost(Self::DEFAULT_P_COST)
            .build().map_err(KdfError::UserKey)?;
        let argon = Argon2::new(argon2::Algorithm::Argon2id, Version::default(), params);
        let mut key = [0u8; 32];
        argon.hash_password_into(passphrase.as_bytes(), salt, &mut key).map_err(KdfError::UserKey)?;
        Ok(key)
    }

    pub fn get_final_key(
        user_key: &[u8; 32],
        server_key: &[u8; 32],
    ) -> Result<[u8; 32], KdfError> {
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
    #[serde(rename = "n")]
    nonce: [u8; 24],
    #[serde(rename = "ct")]
    ciphertext: Vec<u8>,
}

impl ChaChaEncryption {
    fn make_ad(user_id: &Uuid, entry_id: &Uuid) -> [u8; 32] {
        let mut ad = [0u8; 32];
        ad[..16].copy_from_slice(user_id.as_bytes());
        ad[16..].copy_from_slice(entry_id.as_bytes());
        ad
    }
    pub fn encrypt(
        encryption_key: &[u8; 32],
        plaintext: &[u8],
        nonce: Option<&[u8; 24]>,
        user_id: &Uuid,
        entry_id: &Uuid,
    ) -> Result<CryptEntry, chacha20poly1305::Error> {
        let mut rng = rand::rng();
        let ad = Self::make_ad(user_id, entry_id);
        let mykey = Key::from_slice(encryption_key);
        let cipher = XChaCha20Poly1305::new(mykey);
        let nonce = match nonce {
            Some(n) => *n,
            None => {
                let mut buf = [0u8; 24];
                rng.fill_bytes(&mut buf);
                buf
            }
        };
        let nonce_array = GenericArray::from_slice(&nonce);
        let payload = Payload {
            msg: plaintext,
            aad: &ad,
        };
        let ciphertext = cipher.encrypt(nonce_array, payload)?;
        Ok(CryptEntry { nonce, ciphertext })
    }

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
