use argon2::{
    password_hash::{self, rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, PasswordHash,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct User {
    pub id: Uuid,
    /// Login
    pub login: String,
    /// argon2 hashed password
    pub password_hash: String,
    /// Email to use for resetting and tokens
    pub reset_email: Option<String>,
    /// Roles available to this account
    pub roles: Vec<String>,
}

impl User {
    pub fn new(
        login: &str,
        password: &str,
        reset_email: Option<&str>,
        roles: Vec<String>,
    ) -> Result<Self, password_hash::Error> {
        Ok(Self {
            id: Uuid::new_v4(),
            login: login.to_string(),
            password_hash: Self::hash_password(password)?,
            reset_email: reset_email.map(|v| v.to_string()),
            roles,
        })
    }

    /// Hash the password
    pub fn hash_password(password: &str) -> Result<String, password_hash::Error> {
        let argon2 = Argon2::default();
        let salt = SaltString::generate(&mut OsRng);
        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|v| v.to_string())
    }

    /// Return true if the password is verified and valid
    #[allow(dead_code)]
    pub fn verify_password(&self, password: &str) -> bool {
        let argon2 = Argon2::default();
        let Ok(parsed_hash) = PasswordHash::new(&self.password_hash) else {
            return false;
        };
        argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use crate::data::User;

    #[test]
    fn test_password_hashing() -> anyhow::Result<()> {
        let user = User::new("bob", "bad-password", None, Default::default())
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        assert!(user.verify_password("bad-password"));
        assert!(!user.verify_password("good-password"));
        Ok(())
    }
}
