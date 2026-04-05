use std::net::ToSocketAddrs;

use actix_files::{Files, NamedFile};
use actix_session::storage::RedisSessionStore;
use actix_session::SessionMiddleware;
use actix_web::cookie::Key;
use actix_web::{web, App, HttpServer};
use anyhow::Context;
use clap::Parser;
use rand::RngExt;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tracing_actix_web::TracingLogger;
use tracing_subscriber::EnvFilter;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::data::User;

mod api;
mod data;
mod error;
mod tls;

#[derive(OpenApi)]
#[openapi(
    paths(api::create_user, api::login, api::logout, api::verify, api::get_user),
    components(schemas(data::User, api::CreateUser, api::LoginRequest, api::SessionUser))
)]
struct ApiDoc;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short = 'H', long, default_value = "localhost")]
    host: String,

    #[arg(short, long, default_value_t = 8080u16)]
    port: u16,

    #[arg(long, default_value_t = false)]
    tls: bool,

    /// Admin account login. Try to avoid "admin" or "super" they're fairly predictable.
    #[arg(long, default_value = "elliot")]
    admin_name: String,
}

impl Args {
    fn to_sock_addr(&self) -> impl ToSocketAddrs {
        (self.host.clone(), self.port)
    }
}

async fn download_cert() -> actix_web::Result<NamedFile> {
    Ok(NamedFile::open(tls::CERT_PATH)?.set_content_disposition(
        actix_web::http::header::ContentDisposition::attachment("server.pem"),
    ))
}

fn sanitize_database_url(database_url: &str) -> String {
    match url::Url::parse(database_url) {
        Ok(mut parsed) => {
            if parsed.username() != "" {
                let _ = parsed.set_username("***");
            }
            if parsed.password().is_some() {
                let _ = parsed.set_password(Some("***"));
            }
            parsed.to_string()
        }
        Err(_) => "***".to_string(),
    }
}

async fn initialize_admin(args: &Args, pool: &PgPool) -> anyhow::Result<()> {
    let mut rng = rand::rng();
    let password: String = if let Ok(pass) = std::env::var("ADMIN_PASSWORD") {
        pass
    } else {
        (1..16)
            .map(|_| rng.sample(rand::distr::Alphanumeric) as char)
            .collect()
    };
    tracing::info!("New session password is {}", password);
    let user = User::new(&args.admin_name, &password, None, vec!["admin".to_string()])
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("Failed to create admin user")?;
    sqlx::query("INSERT INTO users(id, login, password_hash, reset_email) VALUES ($1, $2, $3, $4) ON CONFLICT(login) DO UPDATE SET password_hash = $3")
        .bind(user.id)
        .bind(&user.login)
        .bind(&user.password_hash)
        .bind(&user.reset_email)
        .execute(pool)
        .await
        .context("Failed to upsert admin user")?;

    Ok(())
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let use_tls = args.tls;
    let secret_key = Key::generate();

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let redis_store = RedisSessionStore::new(&redis_url)
        .await
        .context("Failed to connect to Redis")?;

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://tfbs:tfbs@localhost:5432/tfbs".to_string());

    tracing::info!(
        "Creating database pool for {}",
        sanitize_database_url(&database_url)
    );
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .context("Failed to connect to database")?;
    tracing::info!("Migrating database");
    sqlx::migrate!()
        .run(&pool)
        .await
        .context("Failed to run migrations")?;
    tracing::info!("Migration complete");
    initialize_admin(&args, &pool).await?;

    let server = HttpServer::new(move || {
        let mut app = App::new().wrap(TracingLogger::default());
        if use_tls {
            app = app.route("/cert", web::get().to(download_cert));
        }
        app.wrap(SessionMiddleware::builder(redis_store.clone(), secret_key.clone()).build())
            .service(
                web::scope("/api")
                    .route("/user", web::get().to(api::get_user))
                    .route("/users", web::post().to(api::create_user))
                    .route("/login", web::post().to(api::login))
                    .route("/logout", web::get().to(api::logout))
                    .route("/verify", web::post().to(api::verify)),
            )
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}")
                    .url("/api-docs/openapi.json", ApiDoc::openapi()),
            )
            .service(Files::new("/", "./static").index_file("index.html"))
            .app_data(web::Data::new(pool.clone()))
    });

    let server = if args.tls {
        let tls_config = tls::load_or_generate_config(&args.host)?;
        server
            .bind_rustls_0_23(args.to_sock_addr(), tls_config)
            .context(format!("Failed to bind TLS to {}:{}", args.host, args.port))?
    } else {
        server
            .bind(args.to_sock_addr())
            .context(format!("Failed to bind to {}:{}", args.host, args.port))?
    };

    server.run().await.context("Server error")?;
    Ok(())
}
