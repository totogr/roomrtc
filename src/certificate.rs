//! Generacion de certificados y verificacion de fingerprints.

use rcgen::{Certificate, CertificateParams, DistinguishedName};
use sha2::{Digest, Sha256};

/// Certificado y clave privada junto con su fingerprint SHA-256
pub struct CertificateInfo {
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
    pub fingerprint: String,
}

/// Implementacion de metodos para CertificateInfo
impl CertificateInfo {
    /// Generate a new self-signed certificate and compute its SHA-256 fingerprint
    pub fn generate() -> Result<Self, String> {
        // Generate a self-signed certificate
        let mut params =
            CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]);
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "RoomRTC");

        let cert = Certificate::from_params(params)
            .map_err(|e| format!("Failed to generate certificate: {}", e))?;

        let certificate_der = cert
            .serialize_der()
            .map_err(|e| format!("Failed to serialize certificate: {}", e))?;

        let private_key_der = cert.serialize_private_key_der();

        // Compute SHA-256 fingerprint of the certificate
        let mut hasher = Sha256::new();
        hasher.update(&certificate_der);
        let hash = hasher.finalize();

        // Format fingerprint as "sha-256 XX:XX:XX:..."
        let fingerprint = format!(
            "sha-256 {}",
            hash.iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(":")
        );

        Ok(CertificateInfo {
            certificate: certificate_der,
            private_key: private_key_der,
            fingerprint,
        })
    }

    /// Verifica si el fingerprint dado coincide con el del certificado proporcionado
    pub fn verify_fingerprint(cert_der: &[u8], expected_fingerprint: &str) -> Result<bool, String> {
        // Compute SHA-256 fingerprint of the certificate
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        let hash = hasher.finalize();

        // Format fingerprint as "sha-256 XX:XX:XX:..."
        let computed_fingerprint = format!(
            "sha-256 {}",
            hash.iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(":")
        );

        Ok(computed_fingerprint == expected_fingerprint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_certificate() {
        let cert_info = CertificateInfo::generate().expect("Certificate generation failed");

        assert!(!cert_info.certificate.is_empty());
        assert!(!cert_info.private_key.is_empty());
        assert!(cert_info.fingerprint.starts_with("sha-256 "));
    }

    #[test]
    fn test_verify_fingerprint() {
        let cert_info = CertificateInfo::generate().expect("Certificate generation failed");

        let is_valid =
            CertificateInfo::verify_fingerprint(&cert_info.certificate, &cert_info.fingerprint)
                .expect("Fingerprint verification failed");

        assert!(is_valid);
    }

    #[test]
    fn test_fingerprint_mismatch() {
        let cert_info = CertificateInfo::generate().expect("Certificate generation failed");
        let wrong_fingerprint = "sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";

        let is_valid =
            CertificateInfo::verify_fingerprint(&cert_info.certificate, wrong_fingerprint)
                .expect("Fingerprint verification failed");

        assert!(!is_valid);
    }
}
