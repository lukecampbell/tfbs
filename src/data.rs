use argon2::{Argon2, PasswordHash, password_hash::{self, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng}};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct User {
    #[sqlx(try_from = "String")]
    pub id: Uuid,
    /// Login
    pub login: String,
    /// argon2 hashed password
    pub password_hash: String,
    /// Email to use for resetting and tokens
    pub reset_email: Option<String>,
}

impl User {
    pub fn new(login: &str, password: &str, reset_email: Option<&str>) -> Result<Self, password_hash::Error> {
        Ok(Self {
            id: Uuid::new_v4(),
            login: login.to_string(),
            password_hash: Self::hash_password(password)?,
            reset_email: reset_email.map(|v| v.to_string())
        })
    }

    /// Hash the password
    pub fn hash_password(password: &str) -> Result<String, password_hash::Error> {
        let argon2 = Argon2::default();
        let salt = SaltString::generate(&mut OsRng);
        argon2.hash_password(password.as_bytes(), &salt).map(|v| v.to_string())
    }

    /// Return true if the password is verified and valid
    pub fn verify_password(&self, password: &str) -> bool {
        let argon2 = Argon2::default();
        let Ok(parsed_hash) = PasswordHash::new(&self.password_hash) else {
            return false;
        };
        argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use crate::data::User;

    #[test]
    fn test_password_hashing() -> anyhow::Result<()> {
        let user = User::new("bob", "bad-password", None)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        assert!(user.verify_password("bad-password"));
        assert!(!user.verify_password("good-password"));
        Ok(())
    }
}