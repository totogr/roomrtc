//! Pruebas de integración: Negociación de SDP (Session Description Protocol)
//!
//! Estos tests verifican que:
//! - Se genera SDP válido (oferta y respuesta) para ambos peers
//! - El SDP contiene campos requeridos según RFC 8829 (WebRTC)
//! - ICE credentials (ufrag, pwd) se generan correctamente
//! - Fingerprints DTLS se incluyen en el SDP
//! - Las credenciales se pueden extraer correctamente del SDP

use roomrtc::certificate::CertificateInfo;
use roomrtc::config::SdpConfig;
use roomrtc::protocols::ice::IceAgent;
use roomrtc::sdp::sdp_utils::{generar_sdp_answer, generar_sdp_local};
use roomrtc::utils::parse_sdp_ice;
use std::net::Ipv4Addr;

/// Test: Generación de SDP oferta y respuesta con campos válidos
/// Verifica que se puede generar Session Description Protocol (SDP) válido
/// tanto para oferta como para respuesta, con todos los campos requeridos
/// (credenciales ICE, fingerprints DTLS, información de media).
#[test]
fn test_sdp_offer_answer_generation_with_valid_fields() {
    // Setup Peer A
    let cert_info_a = CertificateInfo::generate().expect("Fallo al generar cert A");
    let ice_a = IceAgent::new_with_host_candidates(
        std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        &[6006],
        true, // controlador
    );

    // Setup Peer B
    let cert_info_b = CertificateInfo::generate().expect("Fallo al generar cert B");
    let mut ice_b = IceAgent::new_with_host_candidates(
        std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        &[6007],
        true,
    );

    // Generar ofertas y respuestas SDP
    let sdp_offer = generar_sdp_local(
        &ice_a,
        "127.0.0.1",
        6004,
        6006,
        &cert_info_a.fingerprint,
        &SdpConfig::default(),
    )
    .expect("Fallo al generar oferta");

    let _parsed_b = parse_sdp_ice(&sdp_offer);
    let sdp_answer = generar_sdp_answer(
        &sdp_offer,
        &mut ice_b,
        "127.0.0.1",
        6004,
        6007,
        &cert_info_b.fingerprint,
        &SdpConfig::default(),
    )
    .expect("Fallo al generar respuesta");

    // Validaciones
    assert!(!sdp_offer.is_empty(), "La oferta no debe estar vacía");
    assert!(!sdp_answer.is_empty(), "La respuesta no debe estar vacía");
    assert!(
        sdp_offer.contains("a=fingerprint"),
        "Oferta debe contener fingerprint"
    );
    assert!(
        sdp_answer.contains("a=fingerprint"),
        "Respuesta debe contener fingerprint"
    );
    assert!(
        sdp_offer.contains("a=ice-ufrag"),
        "Oferta debe contener credencial ICE ufrag"
    );
    assert!(
        sdp_offer.contains("a=ice-pwd"),
        "Oferta debe contener credencial ICE pwd"
    );
    assert!(
        sdp_answer.contains("a=ice-ufrag"),
        "Respuesta debe contener credencial ICE ufrag"
    );
    assert!(
        sdp_answer.contains("a=ice-pwd"),
        "Respuesta debe contener credencial ICE pwd"
    );
}

/// Test: Validación de campos obligatorios en SDP (RFC 8829)
/// Verifica que un SDP generado contiene todos los campos requeridos por
/// la especificación WebRTC (RFC 8829): versión, conexión, credenciales ICE,
/// fingerprint, e información de media. También valida extracción de credenciales.
#[test]
fn test_sdp_contains_required_fields() {
    // Generar certificado e ICE agent
    let cert_info = CertificateInfo::generate().expect("Fallo al generar certificado");
    let ice = IceAgent::new_with_host_candidates(
        std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        &[5006],
        true,
    );

    // Generar SDP
    let sdp = generar_sdp_local(
        &ice,
        "127.0.0.1",
        5004,
        5006,
        &cert_info.fingerprint,
        &SdpConfig::default(),
    )
    .expect("Fallo al generar SDP");

    // Validar campos requeridos
    assert!(sdp.contains("v=0"), "Debe tener versión SDP 0");
    assert!(
        sdp.contains("c=IN IP4 127.0.0.1"),
        "Debe tener información de conexión correcta"
    );
    assert!(
        sdp.contains("a=ice-ufrag:"),
        "Debe tener credencial ICE ufrag"
    );
    assert!(sdp.contains("a=ice-pwd:"), "Debe tener credencial ICE pwd");
    assert!(
        sdp.contains("a=fingerprint:sha-256"),
        "Debe tener fingerprint SHA-256"
    );
    assert!(
        sdp.contains("m=video"),
        "Debe tener línea de media de video"
    );

    // Validar extracción de credenciales
    let parsed = parse_sdp_ice(&sdp);
    assert!(parsed.ice_ufrag.is_some(), "Debe poder extraer ufrag");
    assert!(parsed.ice_pwd.is_some(), "Debe poder extraer pwd");

    // Validar fingerprint
    let has_valid_fingerprint = sdp
        .lines()
        .filter(|l| l.starts_with("a=fingerprint:"))
        .all(|l| l.contains("sha-256"));
    assert!(
        has_valid_fingerprint,
        "Todos los fingerprints deben ser SHA-256"
    );
}
