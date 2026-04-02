use actix_web::{web, HttpResponse};
use argon2::password_hash;
use serde::Deserialize;
use sqlx::AnyPool;

use crate::{data::User, error::AppError};

#[derive(Clone, Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateUser {
    pub login: String,
    pub password: String,
    pub reset_email: Option<String>,
}

impl TryFrom<&CreateUser> for User {
    type Error = password_hash::Error;

    fn try_from(value: &CreateUser) -> Result<Self, password_hash::Error> {
        Self::new(&value.login, &value.password, value.reset_email.as_deref())
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
    pool: web::Data<AnyPool>,
    body: web::Json<CreateUser>,
) -> actix_web::Result<HttpResponse> {
    let user = User::try_from(&*body).map_err(|e| AppError::PasswordHash(e.to_string()))?;
    sqlx::query("INSERT INTO users(id, login, password_hash, reset_email) VALUES ($1, $2, $3, $4)")
        .bind(user.id.to_string())
        .bind(&user.login)
        .bind(&user.password_hash)
        .bind(&user.reset_email)
        .execute(pool.get_ref())
        .await
        .map_err(AppError::DatabaseError)?;

    Ok(HttpResponse::Created().json(&user))
}
