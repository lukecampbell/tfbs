use std::fs;
use std::path::Path;

use anyhow::Context;
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use time::{Duration, OffsetDateTime};

pub const CERT_PATH: &str = "certs/server.pem";
const KEY_PATH: &str = "certs/server.key";

pub fn load_or_generate_config(host: &str) -> anyhow::Result<ServerConfig> {
    if !Path::new(CERT_PATH).exists() || !Path::new(KEY_PATH).exists() {
        generate_self_signed(host)?;
    }

    let cert_chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(CERT_PATH)
        .context("Failed to open certificate file")?
        .collect::<Result<_, _>>()?;

    let key = PrivateKeyDer::from_pem_file(KEY_PATH).context("Failed to read private key")?;

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .context("Failed to build TLS config")
}

fn generate_self_signed(host: &str) -> anyhow::Result<()> {
    tracing::info!(cn = host, "Generating self-signed certificate");

    let san = if host.parse::<std::net::IpAddr>().is_ok() {
        SanType::IpAddress(host.parse().unwrap())
    } else {
        SanType::DnsName(host.try_into()?)
    };
    tracing::debug!(?san, "Using SAN");

    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, host);
    params.subject_alt_names = vec![san];
    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(30);
    tracing::debug!(not_before = %params.not_before, not_after = %params.not_after, "Certificate validity");

    let key_pair = KeyPair::generate().context("Failed to generate key pair")?;
    let cert = params
        .self_signed(&key_pair)
        .context("Failed to generate self-signed certificate")?;

    fs::create_dir_all("certs").context("Failed to create certs directory")?;
    fs::write(CERT_PATH, cert.pem()).context("Failed to write certificate")?;
    fs::write(KEY_PATH, key_pair.serialize_pem()).context("Failed to write key")?;
    tracing::info!(
        cert_path = CERT_PATH,
        key_path = KEY_PATH,
        "Certificate written"
    );
    Ok(())
}
