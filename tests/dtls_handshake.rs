//! Pruebas de integración: Handshake DTLS (Datagram Transport Layer Security)
//!
//! Estos tests verifican el proceso de negociación segura entre dos peers:
//! 1. Inicialización de roles (cliente y servidor)
//! 2. Validación de certificados y fingerprints
//! 3. Intercambio de randoms y derivación de master_secret
//! 4. Verificación de integridad del proceso end-to-end

use roomrtc::certificate::CertificateInfo;
use roomrtc::protocols::dtls::DtlsAgent;

/// Test: Validación de certificados REALES con fingerprint correcto
/// Verifica que la validación exitosa de un certificado REAL con fingerprint correcto
/// establece fingerprint_verified = true. Testea la cadena real:
/// certificado DER → hash SHA-256 → fingerprint → validación
#[test]
fn test_dtls_certificate_validation_with_matching_fingerprint() {
    let cert_client = CertificateInfo::generate().expect("Fallo al generar cert cliente");
    let cert_server = CertificateInfo::generate().expect("Fallo al generar cert servidor");

    let mut client = DtlsAgent::new_client(
        cert_client.fingerprint.clone(),
        Some(cert_server.fingerprint.clone()),
    );

    // Usar CERTIFICADO REAL del servidor (DER binario)
    let cert_der = &cert_server.certificate;
    let cert_len = cert_der.len() as u16;

    let mut cert_msg = vec![0x16, 0x0b];
    cert_msg.extend_from_slice(b"Certificate");
    cert_msg.extend_from_slice(&cert_len.to_be_bytes());
    cert_msg.extend_from_slice(cert_der);

    let result = client
        .validate_certificate_message(&cert_msg)
        .expect("Validación debe completarse");

    assert!(
        result,
        "Validación debe tener éxito con certificado correcto"
    );
    assert!(
        client.fingerprint_verified,
        "fingerprint_verified debe ser true"
    );
}

/// Test: Validación de certificados REALES con fingerprint incorrecto
/// Verifica que la validación falla cuando el cliente espera un fingerprint DIFERENTE
/// del que se computa del certificado recibido. Simula un ataque MITM donde alguien
/// intenta usar un certificado distinto.
#[test]
fn test_dtls_certificate_validation_with_mismatched_fingerprint() {
    let cert_client = CertificateInfo::generate().expect("Fallo al generar cert cliente");
    let cert_server = CertificateInfo::generate().expect("Fallo al generar cert servidor");
    let cert_attacker = CertificateInfo::generate().expect("Fallo al generar cert atacante");

    // Cliente espera fingerprint del servidor LEGÍTIMO
    let mut client = DtlsAgent::new_client(
        cert_client.fingerprint.clone(),
        Some(cert_server.fingerprint.clone()),
    );

    // Cliente recibe certificado del ATACANTE (fingerprint diferente)
    let cert_der = &cert_attacker.certificate;
    let cert_len = cert_der.len() as u16;

    let mut cert_msg = vec![0x16, 0x0b];
    cert_msg.extend_from_slice(b"Certificate");
    cert_msg.extend_from_slice(&cert_len.to_be_bytes());
    cert_msg.extend_from_slice(cert_der);

    let result = client
        .validate_certificate_message(&cert_msg)
        .expect("Validación debe completarse");

    // Validación debe FALLAR
    assert!(!result, "Validación debe fallar con certificado incorrecto");
    assert!(
        !client.fingerprint_verified,
        "fingerprint_verified debe ser false"
    );
}

/// Test: Derivación de master_secret idéntico entre ambos peers
/// Verifica que cuando dos agentes intercambian randoms correctamente,
/// ambos derivan el MISMO master_secret usando HKDF-SHA256 (RFC 3711).
/// Este secret es crítico para encriptación/desencriptación SRTP bidireccional.
#[test]
fn test_dtls_master_secret_derivation_from_randoms() {
    let cert_client = CertificateInfo::generate().expect("Fallo al generar cert cliente");
    let cert_server = CertificateInfo::generate().expect("Fallo al generar cert servidor");

    let mut client = DtlsAgent::new_client(cert_client.fingerprint.clone(), None);
    let mut server = DtlsAgent::new_server(cert_server.fingerprint.clone(), None);

    // Los randoms iniciales de cada agent son únicos
    let client_random = client.client_random.clone();
    let server_random = server.server_random.clone();

    // Simular intercambio de randoms en el handshake
    client.server_random = server_random.clone();
    server.client_random = client_random.clone();

    // Marcar fingerprints como verificados (en handshake real, sucede en cert validation)
    client.fingerprint_verified = true;
    server.fingerprint_verified = true;

    // Ambos derivan master_secret usando los MISMOS randoms
    let client_secret = client
        .compute_master_secret()
        .expect("Cliente debe derivar master_secret");
    let server_secret = server
        .compute_master_secret()
        .expect("Servidor debe derivar master_secret");

    // CRÍTICO: Ambos deben derivar IDÉNTICO master_secret
    assert_eq!(
        client_secret, server_secret,
        "Ambos peers deben derivar IDÉNTICO master_secret"
    );
    assert_eq!(client_secret.len(), 32, "Master secret debe tener 32 bytes");
}

/// Test: Pipeline completo del handshake DTLS
/// Verifica la cadena completa: inicialización → intercambio de randoms →
/// validación de certificados → derivación de master_secret.
/// Simula un handshake real entre cliente y servidor.
#[test]
fn test_dtls_handshake_complete_flow() {
    let cert_client = CertificateInfo::generate().expect("Fallo al generar cert cliente");
    let cert_server = CertificateInfo::generate().expect("Fallo al generar cert servidor");

    let mut client = DtlsAgent::new_client(
        cert_client.fingerprint.clone(),
        Some(cert_server.fingerprint.clone()),
    );
    let mut server = DtlsAgent::new_server(
        cert_server.fingerprint.clone(),
        Some(cert_client.fingerprint.clone()),
    );

    let client_random = client.client_random.clone();
    let server_random = server.server_random.clone();
    client.server_random = server_random.clone();
    server.client_random = client_random.clone();

    // Cliente valida certificado REAL del servidor
    let cert_server_der = &cert_server.certificate;
    let cert_server_len = cert_server_der.len() as u16;
    let mut cert_msg_server = vec![0x16, 0x0b];
    cert_msg_server.extend_from_slice(b"Certificate");
    cert_msg_server.extend_from_slice(&cert_server_len.to_be_bytes());
    cert_msg_server.extend_from_slice(cert_server_der);

    let client_validation = client
        .validate_certificate_message(&cert_msg_server)
        .expect("Validación cliente debe completarse");
    assert!(
        client_validation,
        "Cliente debe validar fingerprint del servidor"
    );

    // Servidor valida certificado REAL del cliente
    let cert_client_der = &cert_client.certificate;
    let cert_client_len = cert_client_der.len() as u16;
    let mut cert_msg_client = vec![0x16, 0x0b];
    cert_msg_client.extend_from_slice(b"Certificate");
    cert_msg_client.extend_from_slice(&cert_client_len.to_be_bytes());
    cert_msg_client.extend_from_slice(cert_client_der);

    let server_validation = server
        .validate_certificate_message(&cert_msg_client)
        .expect("Validación servidor debe completarse");
    assert!(
        server_validation,
        "Servidor debe validar fingerprint del cliente"
    );

    // PASO 3: Derivar master_secret
    let client_secret = client
        .compute_master_secret()
        .expect("Cliente debe derivar master_secret");
    let server_secret = server
        .compute_master_secret()
        .expect("Servidor debe derivar master_secret");

    // Validaciones finales
    assert_eq!(
        client_secret, server_secret,
        "Master secrets deben ser idénticos"
    );
    assert_eq!(client_secret.len(), 32, "Master secret debe tener 32 bytes");
    assert!(
        client.fingerprint_verified,
        "Cliente debe tener fingerprint verificado"
    );
    assert!(
        server.fingerprint_verified,
        "Servidor debe tener fingerprint verificado"
    );
}
