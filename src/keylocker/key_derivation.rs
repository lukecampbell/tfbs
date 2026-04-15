use argon2::{Argon2, ParamsBuilder, Version};
use hkdf::Hkdf;
use sha2::Sha256;

use super::KdfError;

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
