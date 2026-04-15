use std::collections::HashMap;

use actix_session::Session;
use actix_web::{web, HttpResponse};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    data::{KeylockerRow, User},
    error::AppError,
    keylocker::{
        get_server_key, ArgonKeyDerivation, ChaChaEncryption, CryptEntry, ServerSideEncryption,
    },
};

#[derive(Serialize, Deserialize, Debug, Clone, utoipa::ToSchema)]
pub struct KeylockerEntry {
    name: String,
    description: Option<String>,
    #[serde(default = "chrono::Utc::now")]
    created_date: DateTime<Utc>,
    fields: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, utoipa::ToSchema)]
pub struct KeylockerEntryWithHints {
    #[serde(flatten)]
    entry: KeylockerEntry,
    hints: Option<KeylockerHint>,
}

#[derive(Serialize, Deserialize, Debug, Clone, utoipa::ToSchema)]
pub struct KeylockerHint {
    description: Option<String>,
}

#[derive(Clone, Debug, Deserialize, utoipa::ToSchema)]
#[serde(untagged)]
pub enum KeylockerRequest {
    CreateKeylockerEntry(CreateKeylockerEntry),
    ReadKeylockerEntries(ReadKeylockerEntries),
    ReadKeylockerHints(ReadKeylockerHints),
}

#[derive(Clone, Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadKeylockerHints {
    #[allow(dead_code)]
    show_hints: bool,
}

#[derive(Clone, Debug, Deserialize, utoipa::ToSchema)]
pub struct ReadKeylockerEntries {
    passphrase: String,
}

#[derive(Clone, Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateKeylockerEntry {
    passphrase: String,
    hint: Option<KeylockerHint>,
    entry: KeylockerEntry,
}

#[utoipa::path(post, path="/api/keylocker", responses(
    (status = 200, body = Vec<KeylockerEntry>),
    (status = 201, description = "Created a new keylocker entry"),
    (status = 401, description = "Use is not logged in"),
))]
/// Unified keylocker endpoint. Dispatches to create, read entries, or read hints
/// based on the shape of the JSON request body (untagged enum).
pub async fn keylocker_api(
    session: Session,
    db: web::Data<PgPool>,
    req: web::Json<KeylockerRequest>,
) -> actix_web::Result<HttpResponse> {
    let Ok(Some(user)) = session.get::<User>("user") else {
        return Ok(HttpResponse::Unauthorized().finish());
    };
    match &*req {
        KeylockerRequest::ReadKeylockerEntries(read_req) => {
            get_keylocker_entries(&user, read_req, db.get_ref()).await
        }
        KeylockerRequest::CreateKeylockerEntry(create_req) => {
            create_keylocker_entry(&user, create_req, db.get_ref()).await
        }
        KeylockerRequest::ReadKeylockerHints(_hint_req) => {
            get_keylocker_user_hints(&user, db.get_ref()).await
        }
    }
}

/// Create a new keylocker entry. The entry JSON is encrypted with the user's
/// passphrase-derived key, and an optional hint is encrypted with the server key.
pub async fn create_keylocker_entry(
    user: &User,
    req: &CreateKeylockerEntry,
    db: &PgPool,
) -> actix_web::Result<HttpResponse> {
    let entry_id = Uuid::new_v4();

    // Derive the final encryption key from the user's passphrase and server key
    let server_key = get_server_key().map_err(AppError::ServerKey)?;
    let user_salt: [u8; 16] = user
        .kdf_salt
        .clone()
        .try_into()
        .map_err(|_| AppError::UserSalt)?;
    let user_ikm = ArgonKeyDerivation::get_user_key(&req.passphrase, &user_salt)
        .map_err(AppError::KdfError)?;
    let okm =
        ArgonKeyDerivation::get_final_key(&user_ikm, &server_key).map_err(AppError::KdfError)?;

    // Encrypt the entry payload with the user's derived key
    let plaintext = serde_json::to_string(&req.entry).map_err(AppError::SerializationError)?;
    let entry = ChaChaEncryption::encrypt(&okm, plaintext.as_bytes(), None, &user.id, &entry_id)
        .map_err(AppError::EncryptionError)?;
    let ldata = serde_json::to_string(&entry)?;

    // Optionally encrypt the hint with the server-side key (no passphrase needed to read hints)
    let hint_data = req
        .hint
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?
        .map(|hint_json| ServerSideEncryption::encrypt(hint_json.as_bytes()))
        .transpose()
        .map_err(AppError::CryptoError)?
        .map(|crypt_entry| serde_json::to_string(&crypt_entry))
        .transpose()?;

    sqlx::query("INSERT INTO keylocker(id, user_id, ldata, hint) VALUES ($1, $2, $3, $4)")
        .bind(entry_id)
        .bind(user.id)
        .bind(ldata)
        .bind(hint_data)
        .execute(db)
        .await
        .map_err(AppError::DatabaseError)?;

    tracing::info!("Created Keylocker");
    Ok(HttpResponse::Created().finish())
}

/// Decrypt and return all keylocker entries that match the given passphrase.
/// Entries encrypted under a different passphrase silently fail decryption and
/// are omitted — this is by design, as different passphrases partition the vault.
pub async fn get_keylocker_entries(
    user: &User,
    req: &ReadKeylockerEntries,
    db: &PgPool,
) -> actix_web::Result<HttpResponse> {
    // Derive the final encryption key from the user's passphrase and server key
    let server_key = get_server_key().map_err(AppError::ServerKey)?;
    let user_salt: [u8; 16] = user
        .kdf_salt
        .clone()
        .try_into()
        .map_err(|_| AppError::UserSalt)?;
    let user_ikm = ArgonKeyDerivation::get_user_key(&req.passphrase, &user_salt)
        .map_err(AppError::KdfError)?;
    let okm =
        ArgonKeyDerivation::get_final_key(&user_ikm, &server_key).map_err(AppError::KdfError)?;

    let keylockers =
        sqlx::query_as::<_, KeylockerRow>("SELECT id, ldata, hint FROM keylocker WHERE user_id=$1")
            .bind(user.id)
            .fetch_all(db)
            .await
            .map_err(AppError::DatabaseError)?;

    // Attempt to decrypt each row; rows that fail (wrong passphrase) are skipped
    let crypt_entries: Vec<KeylockerEntryWithHints> = keylockers
        .iter()
        .filter_map(|row| {
            // Decrypt the entry payload with the user's derived key
            let crypt_entry: CryptEntry = serde_json::from_str(&row.ldata).ok()?;
            let decrypted_bytes =
                ChaChaEncryption::decrypt(&okm, &crypt_entry, &user.id, &row.id).ok()?;
            let keylocker: KeylockerEntry = serde_json::from_slice(&decrypted_bytes).ok()?;

            // Decrypt the optional hint with the server-side key
            let hint_data: Option<KeylockerHint> = row.hint.as_ref().and_then(|json_str| {
                let crypt_entry: CryptEntry = serde_json::from_str(json_str).ok()?;
                let decrypted_bytes = match ServerSideEncryption::decrypt(&crypt_entry) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        tracing::error!("Failed to decrypt hint data: {e}");
                        None
                    }
                }?;
                serde_json::from_slice(decrypted_bytes.as_slice()).ok()
            });
            Some(KeylockerEntryWithHints {
                entry: keylocker,
                hints: hint_data,
            })
        })
        .collect();

    Ok(HttpResponse::Ok().json(crypt_entries))
}

/// Return all keylocker hints for the user, decrypted with the server key.
/// Does not require the user's passphrase — hints are server-side encrypted only.
pub async fn get_keylocker_user_hints(user: &User, db: &PgPool) -> actix_web::Result<HttpResponse> {
    let keylockers =
        sqlx::query_as::<_, KeylockerRow>("SELECT id, ldata, hint FROM keylocker WHERE user_id=$1")
            .bind(user.id)
            .fetch_all(db)
            .await
            .map_err(AppError::DatabaseError)?;
    let hints: Vec<KeylockerHint> = keylockers
        .iter()
        .filter_map(|row| {
            let hint_json = row.hint.as_ref()?;
            let crypt_entry: CryptEntry = serde_json::from_str(hint_json).ok()?;
            let decrypted_bytes = match ServerSideEncryption::decrypt(&crypt_entry) {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::error!("Failed to decrypt hint data: {e}");
                    None
                }
            }?;
            serde_json::from_slice(decrypted_bytes.as_slice()).ok()?
        })
        .collect();
    Ok(HttpResponse::Ok().json(hints))
}
