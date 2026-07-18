pub mod ca;
pub mod handler;
pub mod server;

use std::{env, net::SocketAddr, path::PathBuf};

pub use ca::{ensure_ca_certificate, install_ca_system_trust, CaAuthority, DomainCertificate};
pub use handler::{Decision, InterceptHandler, LoggingHandler, ProxyRequest, ProxyResponse};
pub use server::run_proxy;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub listen_addr: SocketAddr,
    pub ca_cert_path: PathBuf,
    pub ca_key_path: PathBuf,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        let listen_addr = env::var("PROXIMA_PROXY_LISTEN")
            .ok()
            .and_then(|addr| addr.parse().ok())
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 8080)));

        Self {
            listen_addr,
            ca_cert_path: PathBuf::from("certs/proxima-ca.pem"),
            ca_key_path: PathBuf::from("certs/proxima-ca-key.pem"),
        }
    }
}
