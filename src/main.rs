//! tfbs I don't really know just yet
//!
//! TODO Long Description
//!
//! # Examples
//!
//! TODO Example

use std::net::ToSocketAddrs;

use actix_web::{App, HttpResponse, HttpServer, Responder};
use askama::Template;
use clap::Parser;
use anyhow::Context;
use tracing_actix_web::TracingLogger;
use tracing_subscriber::EnvFilter;



/// Program Arguments
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short = 'H', long, default_value = "localhost")]
    host: String,

    #[arg(short, long, default_value_t = 8080u16)]
    port: u16,
}

impl Args {
    fn to_sock_addr(&self) -> impl ToSocketAddrs {
        (self.host.clone(), self.port)
    }
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {

}

#[actix_web::get("/")]
async fn index() -> impl Responder {
    let template = IndexTemplate { };
    HttpResponse::Ok().content_type("text/html; charset=utf-8")
        .body(template.render().unwrap())
}

/// Main entry point
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse arguments
    let args = Args::parse();
    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).init();
    let server = HttpServer::new(|| {
        App::new()
            .wrap(TracingLogger::default())
            .service(index)
    })
    .bind(args.to_sock_addr())
    .context(format!("Failed to bind to {}:{}", args.host, args.port))?
    .run()
    .await
    .context("Server error")?;
    Ok(())
}
