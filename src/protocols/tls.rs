//! Capa de cifrado simetrico para la conexion TCP cliente-servidor.
//!
//! Encriptar el protocolo textual de signaling usando
//! AES-256-GCM sobre una clave derivada de un PSK configurable.
//!
//! Framing en la conexion TCP:
//!   <len>\n<nonce_len><nonce><ciphertext>
//!
//! donde:
//!  - <len> es la longitud total de (nonce_len + nonce + ciphertext)
//!  - nonce_len es un byte (normalmente 12)
//!  - nonce son bytes aleatorios por mensaje
//!  - ciphertext = AES-256-GCM(plaintext)

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce}; // Nonce de 96 bits (12 bytes)
use rand::{RngCore, rng};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};

/// Longitud de nonce para AES-GCM (96 bits)
const NONCE_LEN: usize = 12;

/// Tipo de clave simetrica para AES-256-GCM.
pub type TlsKey = [u8; 32];

/// Deriva una clave de 256 bits a partir de un PSK arbitrario usando SHA-256.
pub fn derive_key_from_psk(psk: &str) -> TlsKey {
    let mut hasher = Sha256::new();
    hasher.update(psk.as_bytes());
    let result = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Encripta un mensaje en claro devolviendo (ciphertext, nonce).
fn encrypt_message(plaintext: &[u8], key: &TlsKey) -> io::Result<(Vec<u8>, [u8; NONCE_LEN])> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| io::Error::other(format!("TLS key error: {e}")))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    let mut rng = rng();
    rng.fill_bytes(&mut nonce_bytes);

    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| io::Error::other(format!("TLS encrypt error: {e}")))?;

    Ok((ciphertext, nonce_bytes))
}

/// Desencripta un mensaje dado ciphertext y nonce.
fn decrypt_message(ciphertext: &[u8], nonce_bytes: &[u8], key: &TlsKey) -> io::Result<Vec<u8>> {
    if nonce_bytes.len() != NONCE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS nonce length invalido",
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| io::Error::other(format!("TLS key error: {e}")))?;

    #[allow(deprecated)]
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("TLS decrypt error: {e}"),
        )
    })?;

    Ok(plaintext)
}

/// Escribe un mensaje en claro `msg` en el stream, encriptandolo y aplicando framing.
pub fn write_encrypted<W: Write>(writer: &mut W, msg: &str, key: &TlsKey) -> io::Result<()> {
    let (ciphertext, nonce_bytes) = encrypt_message(msg.as_bytes(), key)?;
    let nonce_len = nonce_bytes.len();

    if nonce_len > u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS nonce demasiado largo",
        ));
    }

    let total_len = 1 + nonce_len + ciphertext.len();

    // prefijo con longitud total
    writer.write_all(format!("{total_len}\n").as_bytes())?;
    // primer byte: longitud del nonce
    writer.write_all(&[nonce_len as u8])?;
    // nonce
    writer.write_all(&nonce_bytes)?;
    // ciphertext
    writer.write_all(&ciphertext)?;
    writer.flush()?;

    Ok(())
}

/// Lee un mensaje del stream, aplicando framing + desencriptado,
/// devolviendo el texto en claro (UTF-8).
pub fn read_encrypted<R: Read>(reader: &mut R, key: &TlsKey) -> io::Result<String> {
    // lee la l�nea de longitud: "<len>\n"
    let mut size_line = String::new();
    let mut buf = [0u8; 1];

    loop {
        match reader.read_exact(&mut buf) {
            Ok(a) => a,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "Cliente cerro conexion",
                ));
            }
            Err(e) => return Err(e),
        }
        let c = buf[0] as char;
        if c == '\n' {
            break;
        }
        size_line.push(c);
    }

    let size: usize = size_line.trim().parse().map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("TLS invalid size: {e}"))
    })?;

    // lee exactamente size bytes
    let mut data = vec![0u8; size];
    reader.read_exact(&mut data)?;

    // parsea nonce_len, nonce, ciphertext
    if data.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "TLS frame vacio",
        ));
    }

    let nonce_len = data[0] as usize;
    if nonce_len == 0 || nonce_len > NONCE_LEN || 1 + nonce_len > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS nonce_len invalido",
        ));
    }

    let nonce_bytes = &data[1..1 + nonce_len];
    let ciphertext = &data[1 + nonce_len..];

    let plaintext = decrypt_message(ciphertext, nonce_bytes, key)?;
    let text = String::from_utf8(plaintext).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("TLS mensaje no es UTF-8 valido: {e}"),
        )
    })?;

    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let key = derive_key_from_psk("test-psk");
        let msg = "HELLO|username=toto|password=123";

        let (cipher, nonce) = encrypt_message(msg.as_bytes(), &key).unwrap();
        assert_ne!(cipher, msg.as_bytes());

        let plain = decrypt_message(&cipher, &nonce, &key).unwrap();
        assert_eq!(msg.as_bytes(), plain.as_slice());
    }
}
