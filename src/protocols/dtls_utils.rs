//! Utilidades para generar y manejar fingerprints DTLS.

use sha2::{Digest, Sha256};

/// Genera un fingerprint SHA-256 a partir de datos (tipicamente un certificado).
pub fn generate_fingerprint(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    format_fingerprint(&hash)
}

/// Formatea un hash de bytes como "sha-256 XX:YY:ZZ:..."
pub fn format_fingerprint(hash: &[u8]) -> String {
    let hex_string = hash
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":");
    format!("sha-256 {}", hex_string)
}

/// Parsea un fingerprint en formato "sha-256 XX:YY:ZZ:..." y retorna el hash como bytes
pub fn parse_fingerprint(fingerprint: &str) -> Option<Vec<u8>> {
    // Expected format: "sha-256 XX:YY:ZZ:..."
    let parts: Vec<&str> = fingerprint.splitn(2, ' ').collect();
    if parts.len() != 2 {
        return None;
    }

    let algorithm = parts[0];
    if algorithm != "sha-256" {
        return None;
    }

    let hex_pairs: Vec<&str> = parts[1].split(':').collect();
    let mut hash = Vec::new();

    for hex in hex_pairs {
        match u8::from_str_radix(hex, 16) {
            Ok(byte) => hash.push(byte),
            Err(_) => return None,
        }
    }

    if hash.len() == 32 {
        // SHA-256 produces 32 bytes
        Some(hash)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_fingerprint() {
        let hash = vec![0x12, 0x34, 0x56, 0x78];
        let fingerprint = format_fingerprint(&hash);
        assert_eq!(fingerprint, "sha-256 12:34:56:78");
    }

    #[test]
    fn test_parse_fingerprint() {
        // SHA-256 produces 32 bytes, so we need 32 hex pairs
        let fingerprint = "sha-256 12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF";
        let parsed = parse_fingerprint(fingerprint);
        assert!(parsed.is_some());
        let hash = parsed.unwrap();
        assert_eq!(hash.len(), 32);
        assert_eq!(hash[0], 0x12);
        assert_eq!(hash[31], 0xEF);
    }

    #[test]
    fn test_generate_and_parse() {
        let data = b"test certificate";
        let fingerprint = generate_fingerprint(data);
        assert!(fingerprint.starts_with("sha-256 "));

        let parsed = parse_fingerprint(&fingerprint);
        assert!(parsed.is_some());
    }
}
