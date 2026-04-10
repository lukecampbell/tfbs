use std::collections::HashMap;

use actix_session::Session;
use actix_web::{web, HttpResponse, Responder};
use argon2::password_hash;
use chrono::{DateTime, Utc};
use clap::Arg;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{data::User, error::AppError, keylocker::{ArgonKeyDerivation, ChaChaEncryption, get_server_key}};

#[derive(Clone, Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateUser {
    pub login: String,
    pub password: String,
    pub reset_email: Option<String>,
    pub roles: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, utoipa::ToSchema)]
pub struct LoginRequest {
    pub login: String,
    pub password: String,
}

impl TryFrom<&CreateUser> for User {
    type Error = password_hash::Error;

    fn try_from(value: &CreateUser) -> Result<Self, password_hash::Error> {
        Self::new(
            &value.login,
            &value.password,
            value.reset_email.as_deref(),
            value.roles.clone(),
        )
    }
}

#[utoipa::path(
    post,
    path = "/api/users",
    request_body = CreateUser,
    responses(
        (status = 201, description = "User created", body = User),
        (status = 400, description = "Invalid input"),
        (status = 500, description = "Internal error"),
    )
)]
pub async fn create_user(
    pool: web::Data<PgPool>,
    body: web::Json<CreateUser>,
) -> actix_web::Result<HttpResponse> {
    let user = User::try_from(&*body).map_err(|e| AppError::PasswordHash(e.to_string()))?;
    sqlx::query("INSERT INTO users(id, login, password_hash, reset_email) VALUES ($1, $2, $3, $4)")
        .bind(user.id)
        .bind(&user.login)
        .bind(&user.password_hash)
        .bind(&user.reset_email)
        .execute(pool.get_ref())
        .await
        .map_err(AppError::DatabaseError)?;

    Ok(HttpResponse::Created().json(&user))
}

#[utoipa::path(
    post,
    path = "/api/login",
    request_body = LoginRequest,
    responses(
        (status = 204, description = "Authenticated Successfully"),
        (status = 401, description = "Invalid credentials"),
    )
)]
pub async fn login(
    session: Session,
    pool: web::Data<PgPool>,
    req: web::Json<LoginRequest>,
) -> actix_web::Result<HttpResponse> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, login, password_hash, reset_email, roles, kdf_salt FROM users WHERE login=$1",
    )
    .bind(&req.login)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(AppError::DatabaseError)?;
    match user {
        Some(user) if user.verify_password(&req.password) => {
            session.insert("user", &user).unwrap();
            Ok(HttpResponse::Ok().json(serde_json::json!({"login": user.login})))
        }
        _ => {
            Ok(HttpResponse::Unauthorized()
                .json(serde_json::json!({"error": "Invalid credentials"})))
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/logout",
    responses(
        (status = 204, description = "User session is cleared")
    )
)]
pub async fn logout(session: Session) -> actix_web::Result<HttpResponse> {
    session.purge();
    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    post,
    path = "/api/verify",
    responses(
        (status = 200, description = "User is logged in"),
        (status = 401, description = "User is not logged in"),
    )
)]
pub async fn verify(session: Session) -> actix_web::Result<HttpResponse> {
    let Ok(Some(user)) = session.get::<User>("user") else {
        return Ok(HttpResponse::Unauthorized().finish());
    };
    Ok(HttpResponse::Ok().json(serde_json::json!({"user": &user.login})))
}

#[derive(Clone, Serialize, Debug, utoipa::ToSchema)]
pub struct SessionUser {
    pub login: String,
    pub roles: Vec<String>,
}

impl From<&User> for SessionUser {
    fn from(user: &User) -> Self {
        SessionUser {
            login: user.login.clone(),
            roles: user.roles.clone(),
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/user",
    responses(
        (status = 200, description = "User is logged in", body = SessionUser),
        (status = 401, description = "User is not logged in"),
    )
)]
pub async fn get_user(session: Session) -> actix_web::Result<HttpResponse> {
    let Ok(Some(user)) = session.get::<User>("user") else {
        return Ok(HttpResponse::Unauthorized().finish());
    };
    Ok(HttpResponse::Ok().json(SessionUser::from(&user)))
}

#[utoipa::path(get, path="/api/files", responses(
    (status = 200, description = "Available file sessions", body = Vec<String>),
    (status = 401, description = "Use is not logged in"),
))]
pub async fn get_files(
    session: Session,
    redis: web::Data<redis::Client>,
) -> actix_web::Result<impl Responder> {
    let Ok(Some(_user)) = session.get::<User>("user") else {
        return Ok(HttpResponse::Unauthorized().finish());
    };
    let mut redis_conn = redis
        .get_multiplexed_async_connection()
        .await
        .map_err(AppError::RedisError)?;
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("*")
        .query_async(&mut redis_conn)
        .await
        .map_err(AppError::RedisError)?;
    Ok(HttpResponse::Ok().json(keys))
}


#[derive(Serialize, Deserialize, Debug, Clone, utoipa::ToSchema)]
pub struct KeylockerEntry {
    name: String,
    description: Option<String>,
    #[serde(default = "chrono::Utc::now")]
    created_date: DateTime<Utc>,
    fields: HashMap<String, String>
}

#[derive(Clone, Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateKeylockerEntry {
    passphrase: String,
    entry: KeylockerEntry,
}

pub async fn create_keylocker_entry(session: Session, req: web::Json<CreateKeylockerEntry>) -> actix_web::Result<HttpResponse> {
    let entry_id = Uuid::new_v4();
    let Ok(Some(user)) = session.get::<User>("user") else {
        return Ok(HttpResponse::Unauthorized().finish());
    };
    let server_key = get_server_key().map_err(AppError::ServerKey)?;
    let user_salt: [u8; 16] = user.kdf_salt.clone().try_into().map_err(|e| AppError::UserSalt)?;
    let user_ikm = ArgonKeyDerivation::get_user_key(&req.passphrase, &user_salt).map_err(AppError::KdfError)?;
    let okm = ArgonKeyDerivation::get_final_key(&user_ikm, &server_key).map_err(AppError::KdfError)?;
    let plaintext = serde_json::to_string(&req.entry).map_err(AppError::SerializationError)?;
    let entry = ChaChaEncryption::encrypt(&okm, plaintext.as_bytes(), None, &user.id, &entry_id).map_err(AppError::EncryptionError)?;
    println!("{:?}", entry);
    Ok(HttpResponse::Created().finish())
}