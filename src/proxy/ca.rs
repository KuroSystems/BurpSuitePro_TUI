use std::{fs, path::Path, process::Command};

use color_eyre::eyre::{bail, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{info, warn};

use super::ProxyConfig;

#[derive(Debug, Clone)]
pub struct CaAuthority {
    cert_pem: String,
    key_pem: String,
}

pub struct DomainCertificate {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
}

impl CaAuthority {
    pub fn issue_domain_certificate(&self, domain: &str) -> Result<DomainCertificate> {
        let mut params = CertificateParams::new(vec![domain.to_string()])
            .wrap_err("failed to create domain certificate params")?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, domain);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];

        let subject_key = KeyPair::generate().wrap_err("failed to generate domain key pair")?;
        let signing_key = KeyPair::from_pem(&self.key_pem).wrap_err("failed to parse CA key PEM")?;
        let issuer = Issuer::from_ca_cert_pem(&self.cert_pem, signing_key)
            .wrap_err("failed to build CA issuer from PEM")?;
        let cert = params
            .signed_by(&subject_key, &issuer)
            .wrap_err("failed to sign domain certificate")?;

        Ok(DomainCertificate {
            cert_chain: vec![cert.der().clone()],
            private_key: PrivateKeyDer::from(subject_key),
        })
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }
}

pub fn ensure_ca_certificate(config: &ProxyConfig) -> Result<CaAuthority> {
    if config.ca_cert_path.exists() && config.ca_key_path.exists() {
        let cert_pem = fs::read_to_string(&config.ca_cert_path)
            .with_context(|| format!("failed to read {}", config.ca_cert_path.display()))?;
        let key_pem = fs::read_to_string(&config.ca_key_path)
            .with_context(|| format!("failed to read {}", config.ca_key_path.display()))?;
        return Ok(CaAuthority { cert_pem, key_pem });
    }

    if let Some(parent) = config.ca_cert_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    if let Some(parent) = config.ca_key_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "Proxima TUI Local MITM CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Proxima TUI");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    let signing_key = KeyPair::generate().wrap_err("failed to generate CA key pair")?;
    let cert = params
        .self_signed(&signing_key)
        .wrap_err("failed to generate self-signed CA certificate")?;

    let cert_pem = cert.pem();
    let key_pem = signing_key.serialize_pem();

    fs::write(&config.ca_cert_path, &cert_pem)
        .with_context(|| format!("failed to write {}", config.ca_cert_path.display()))?;
    fs::write(&config.ca_key_path, &key_pem)
        .with_context(|| format!("failed to write {}", config.ca_key_path.display()))?;

    info!(
        cert = %config.ca_cert_path.display(),
        key = %config.ca_key_path.display(),
        "generated local MITM CA"
    );

    Ok(CaAuthority { cert_pem, key_pem })
}

pub fn install_ca_system_trust(ca_cert_path: &Path) -> Result<()> {
    if cfg!(target_os = "linux") {
        let destination = Path::new("/usr/local/share/ca-certificates/proxima-tui-ca.crt");
        let copy_status = Command::new("sudo")
            .arg("cp")
            .arg(ca_cert_path)
            .arg(destination)
            .status()
            .wrap_err("failed to invoke sudo cp for CA installation")?;
        if !copy_status.success() {
            bail!("failed to copy CA certificate into system trust store");
        }

        let update_status = Command::new("sudo")
            .arg("update-ca-certificates")
            .status()
            .wrap_err("failed to invoke update-ca-certificates")?;
        if !update_status.success() {
            bail!("update-ca-certificates failed");
        }

        info!(cert = %ca_cert_path.display(), "installed CA into Linux system trust store");
        return Ok(());
    }

    warn!(
        cert = %ca_cert_path.display(),
        "automatic CA installation is not implemented on this platform; import this certificate manually"
    );
    Ok(())
}
