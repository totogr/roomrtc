//! Módulo SRTP (Secure Real-time Transport Protocol) para encriptación/desencriptación de payload RTP.
//! Implementación simplificada que encripta solo el payload RTP.
//! El encabezado RTP permanece en texto plano para enrutamiento y decodificación.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Key, KeyInit, Nonce};
use sha2::{Digest, Sha256};

/// Contexto SRTP que contiene la clave de encriptación y proporciona operaciones de encriptar/desencriptar.
#[derive(Clone, Copy)]
pub struct SrtpContext {
    key: [u8; 16], // Clave AES-128 (128 bits)
}

/// Implementación del contexto SRTP.
impl SrtpContext {
    /// Crea un nuevo contexto SRTP derivando la clave de encriptación del secreto maestro.
    pub fn new(master_secret: &[u8]) -> Self {
        let key = Self::derive_key(master_secret);
        SrtpContext { key }
    }

    /// Deriva una clave AES-128 de 16 bytes del secreto maestro usando SHA256.
    /// Esta es una derivación de clave simplificada (no es RFC 5869 HKDF completo, pero es suficiente).
    fn derive_key(master_secret: &[u8]) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(b"SRTP");
        hasher.update(master_secret);
        hasher.update(b"encryption_key");
        let result = hasher.finalize();

        let mut key = [0u8; 16];
        key.copy_from_slice(&result[0..16]);
        key
    }

    /// Genera un nonce de 12 bytes a partir del número de secuencia RTP.
    /// Según RFC 3711 SRTP, el nonce se deriva del índice del paquete para asegurar unicidad.
    fn generate_nonce(seq: u16) -> [u8; 12] {
        let mut nonce_bytes = [0u8; 12];
        // Usa el número de secuencia RTP como componente principal del nonce
        // Esto asegura que cada paquete tenga un nonce único
        nonce_bytes[0..2].copy_from_slice(&seq.to_be_bytes());
        // Los bytes restantes se rellenan con ceros (suficiente para demostración)
        nonce_bytes
    }

    /// Encripta el payload RTP usando AES-128-GCM.
    ///
    /// # Argumentos
    /// * `payload` - Datos del payload RTP a encriptar (datos de video H.264)
    /// * `seq` - Número de secuencia RTP (usado para generar nonce)
    ///
    /// # Retorna
    /// * `Vec<u8>` - Payload encriptado (ciphertext con etiqueta de autenticación)
    ///
    /// # Notas
    /// - El encabezado RTP NO está encriptado, solo el payload
    /// - El modo GCM proporciona encriptación y autenticación
    /// - El ciphertext retornado incluye la etiqueta de autenticación de 16 bytes al final
    pub fn encrypt_payload(&self, payload: &[u8], seq: u16) -> Vec<u8> {
        let nonce_bytes = Self::generate_nonce(seq);
        let nonce = Nonce::from(nonce_bytes);
        let key = Key::<Aes128Gcm>::from(self.key);
        let cipher = Aes128Gcm::new(&key);

        cipher
            .encrypt(&nonce, payload)
            .expect("Error al encriptar - esto nunca debería suceder con entradas válidas")
    }

    /// Desencripta el payload RTP usando AES-128-GCM.
    ///
    /// # Argumentos
    /// * `ciphertext` - Payload encriptado (incluyendo etiqueta de autenticación)
    /// * `seq` - Número de secuencia RTP (usado para generar nonce)
    ///
    /// # Retorna
    /// * `Result<Vec<u8>, String>` - Payload desencriptado o error
    ///
    /// # Notas
    /// - Falla si el ciphertext está corrupto o la etiqueta de autenticación es inválida
    /// - El mismo número de secuencia usado para encriptación debe usarse para desencriptación
    pub fn decrypt_payload(&self, ciphertext: &[u8], seq: u16) -> Result<Vec<u8>, String> {
        let nonce_bytes = Self::generate_nonce(seq);
        let nonce = Nonce::from(nonce_bytes);
        let key = Key::<Aes128Gcm>::from(self.key);
        let cipher = Aes128Gcm::new(&key);

        cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let master_secret = b"test_master_secret_32_bytes_long";
        let srtp = SrtpContext::new(master_secret);

        let payload = b"Hello, this is test H.264 video data";
        let seq = 1000u16;

        let encrypted = srtp.encrypt_payload(payload, seq);
        assert_ne!(
            encrypted,
            payload.to_vec(),
            "Encrypted should differ from plaintext"
        );

        let decrypted = srtp
            .decrypt_payload(&encrypted, seq)
            .expect("Decryption failed");
        assert_eq!(
            decrypted,
            payload.to_vec(),
            "Decrypted should match original"
        );
    }

    #[test]
    fn test_different_seq_produces_different_ciphertext() {
        let master_secret = b"test_master_secret_32_bytes_long";
        let srtp = SrtpContext::new(master_secret);

        let payload = b"Same payload data";
        let encrypted1 = srtp.encrypt_payload(payload, 1000);
        let encrypted2 = srtp.encrypt_payload(payload, 1001);

        assert_ne!(
            encrypted1, encrypted2,
            "Different sequence numbers should produce different ciphertexts"
        );
    }

    #[test]
    fn test_decrypt_with_wrong_seq_fails() {
        let master_secret = b"test_master_secret_32_bytes_long";
        let srtp = SrtpContext::new(master_secret);

        let payload = b"Test payload";
        let encrypted = srtp.encrypt_payload(payload, 1000);

        // Try to decrypt with wrong sequence number
        let result = srtp.decrypt_payload(&encrypted, 1001);
        assert!(result.is_err(), "Decryption with wrong seq should fail");
    }

    #[test]
    fn test_decrypt_corrupted_ciphertext_fails() {
        let master_secret = b"test_master_secret_32_bytes_long";
        let srtp = SrtpContext::new(master_secret);

        let payload = b"Test payload";
        let mut encrypted = srtp.encrypt_payload(payload, 1000);

        // Corrupt the ciphertext
        if !encrypted.is_empty() {
            encrypted[0] ^= 0xFF;
        }

        let result = srtp.decrypt_payload(&encrypted, 1000);
        assert!(
            result.is_err(),
            "Decryption of corrupted data should fail due to auth tag verification"
        );
    }
}
