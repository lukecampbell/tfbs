use std::net::ToSocketAddrs;

use actix_files::{Files, NamedFile};
use actix_web::{App, HttpServer, web};
use anyhow::Context;
use clap::Parser;
use tracing_actix_web::TracingLogger;
use tracing_subscriber::EnvFilter;
use sqlx::any::AnyPoolOptions;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

mod tls;
mod data;
mod api;
mod error;

#[derive(OpenApi)]
#[openapi(
    paths(api::create_user),
    components(schemas(data::User, api::CreateUser))
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
}

impl Args {
    fn to_sock_addr(&self) -> impl ToSocketAddrs {
        (self.host.clone(), self.port)
    }
}

async fn download_cert() -> actix_web::Result<NamedFile> {
    Ok(NamedFile::open(tls::CERT_PATH)?
        .set_content_disposition(actix_web::http::header::ContentDisposition::attachment("server.pem")))
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

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let use_tls = args.tls;
    sqlx::any::install_default_drivers();
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://tfbs.db?mode=rwc".to_string());

    tracing::info!("Creating database pool for {}", sanitize_database_url(&database_url));
    let pool = AnyPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .context("Failed to connect to database")?;
    tracing::info!("Migrating database");
    sqlx::migrate!().run(&pool).await.context("Failed to run migrations")?;
    tracing::info!("Migration complete");

    let server = HttpServer::new(move || {
        let mut app = App::new()
            .wrap(TracingLogger::default());
        if use_tls {
            app = app.route("/cert", web::get().to(download_cert));
        }
        app.service(
            web::scope("/api")
                .route("/users", web::post().to(api::create_user))
        )
            .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/api-docs/openapi.json", ApiDoc::openapi()))
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
