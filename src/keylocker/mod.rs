pub mod encryption;
pub mod error;
pub mod key_derivation;

pub use encryption::{ChaChaEncryption, CryptEntry, ServerSideEncryption};
pub use error::{CryptoError, KdfError, ServerKeyError};
pub use key_derivation::ArgonKeyDerivation;

use base64::prelude::*;

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

#[cfg(test)]
mod tests {
    use std::fmt::Display;

    use pretty_hex::*;
    use rand::rngs::ThreadRng;
    use rand::Rng;

    use super::{ArgonKeyDerivation, ChaChaEncryption};

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
