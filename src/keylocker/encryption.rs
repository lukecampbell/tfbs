use base64::prelude::*;
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

use super::{get_server_key, CryptoError, KdfError};

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
    pub ciphertext: Vec<u8>,
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

pub struct ChaChaEncryption;

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
