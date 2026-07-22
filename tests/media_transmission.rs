//! Pruebas de integración: Codificación, encriptación y autenticación de media
//!
//! Estos tests verifican la cadena completa de transmisión de media:
//! 1. Codificación H.264: RGB → H.264
//! 2. Decodificación H.264: H.264 → RGB
//! 3. Encriptación SRTP: plaintext → ciphertext
//! 4. Desencriptación SRTP: ciphertext → plaintext
//! 5. Autenticación SRTP: detecta corrupción mediante GCM tag
//! 6. Pipeline completo: RGB → H.264 → SRTP → SRTP → H.264 → RGB
//! 7. Comunicación bidireccional SRTP: A↔B encriptan/desencriptan mutuamente
//! 8. Nonce uniqueness: GCM usa sequence number como nonce

use roomrtc::certificate::CertificateInfo;
use roomrtc::codec::h264::{H264Decoder, H264Encoder};
use roomrtc::protocols::dtls::DtlsAgent;
use roomrtc::protocols::srtp::SrtpContext;

/// Test: Codificación y decodificación H.264 roundtrip
/// Verifica que un frame RGB puede ser codificado a H.264 y luego decodificado
/// de vuelta a RGB con datos válidos (permitiendo pérdida por compresión).
#[test]
fn test_h264_encoding_decoding_roundtrip() {
    // Crear frame de prueba (640x480 RGB)
    let width = 640u32;
    let height = 480u32;
    let frame_data = vec![128u8; (width * height * 3) as usize];

    // Codificar RGB → H.264
    let mut encoder = H264Encoder::new(width, height, 30, 500).expect("Fallo al crear encoder");
    let encoded = encoder
        .encode(&frame_data, width, height)
        .expect("Fallo al codificar frame");

    // Validar que se comprimió
    assert!(
        !encoded.is_empty(),
        "Datos codificados no deben estar vacíos"
    );
    assert!(
        encoded.len() < frame_data.len(),
        "H.264 debe ser más pequeño que RGB sin comprimir"
    );

    // Decodificar H.264 → RGB
    let mut decoder = H264Decoder::new().expect("Fallo al crear decoder");
    let decoded = decoder
        .decode(&encoded)
        .expect("Fallo al decodificar frame");

    // Validar que el frame decodificado tiene dimensiones correctas
    assert_eq!(
        decoded.width, width,
        "Ancho del frame decodificado debe coincidir"
    );
    assert_eq!(
        decoded.height, height,
        "Alto del frame decodificado debe coincidir"
    );
    assert_eq!(
        decoded.data.len(),
        frame_data.len(),
        "Tamaño del frame decodificado debe ser RGB original"
    );
}

/// Test: Validación de autenticación SRTP - Detección de corrupción
/// Verifica que el authentication tag en GCM detecta cuando el ciphertext
/// ha sido modificado (corrupción de datos), fallando la desencriptación.
/// Esto es crítico para detectar ataques o corrupción en tránsito.
#[test]
fn test_srtp_authentication_fails_on_corruption() {
    // Crear contexto SRTP
    let master_secret = b"test_master_secret_32_bytes_long";
    let srtp = SrtpContext::new(master_secret);

    // Encriptar payload
    let payload = b"Test payload";
    let mut encrypted = srtp.encrypt_payload(payload, 1000);

    // Corromper ciphertext
    if !encrypted.is_empty() {
        encrypted[0] ^= 0xFF;
    }

    // Validaciones
    let result = srtp.decrypt_payload(&encrypted, 1000);
    assert!(
        result.is_err(),
        "Decriptación de datos corruptos debe fallar"
    );
}

/// Test: Pipeline completo - Codificación, encriptación, desencriptación, decodificación
/// Verifica la cadena completa de transmisión de media:
/// 1. Toma un frame RGB original
/// 2. Lo codifica a H.264
/// 3. Lo encripta con SRTP
/// 4. Lo desencripta con SRTP
/// 5. Lo decodifica de vuelta a RGB
/// 6. Valida que el resultado final tiene las dimensiones correctas
#[test]
fn test_media_pipeline_encode_encrypt_decrypt_decode() {
    // PASO 1: Crear frame RGB original
    let width = 640u32;
    let height = 480u32;
    let original_rgb = vec![128u8; (width * height * 3) as usize];

    // PASO 2: Codificar RGB → H.264
    let mut encoder = H264Encoder::new(width, height, 30, 500).expect("Fallo al crear encoder");
    let h264_data = encoder
        .encode(&original_rgb, width, height)
        .expect("Fallo al codificar RGB a H.264");

    assert!(!h264_data.is_empty(), "H.264 datos no deben estar vacíos");
    assert!(
        h264_data.len() < original_rgb.len(),
        "H.264 debe estar comprimido"
    );

    // PASO 3: Encriptar H.264 con SRTP
    let master_secret = b"test_master_secret_32_bytes_long";
    let srtp = SrtpContext::new(master_secret);
    let encrypted_h264 = srtp.encrypt_payload(&h264_data, 1000);

    assert!(
        !encrypted_h264.is_empty(),
        "Datos encriptados no deben estar vacíos"
    );
    assert_ne!(
        encrypted_h264, h264_data,
        "Datos encriptados deben diferir de los originales"
    );

    // PASO 4: Desencriptar SRTP
    let decrypted_h264 = srtp
        .decrypt_payload(&encrypted_h264, 1000)
        .expect("Fallo al desencriptar");

    assert_eq!(
        decrypted_h264, h264_data,
        "Datos desencriptados deben coincidir con H.264 original"
    );

    // PASO 5: Decodificar H.264 → RGB
    let mut decoder = H264Decoder::new().expect("Fallo al crear decoder");
    let decoded_rgb = decoder
        .decode(&decrypted_h264)
        .expect("Fallo al decodificar H.264");

    // PASO 6: Validar resultado final
    assert_eq!(
        decoded_rgb.width, width,
        "Ancho del resultado final debe ser correcto"
    );
    assert_eq!(
        decoded_rgb.height, height,
        "Alto del resultado final debe ser correcto"
    );
    assert_eq!(
        decoded_rgb.data.len(),
        original_rgb.len(),
        "Tamaño del resultado final debe coincidir con RGB original"
    );
}

/// Test: Comunicación bidireccional encriptada (A↔B)
/// Verifica que ambos peers pueden encriptar y desencriptar mutuamente,
/// simulando una llamada real donde video fluye en ambas direcciones.
#[test]
fn test_srtp_bidirectional_encrypted_communication() {
    let mut peer_a = create_peer("PeerA", false);
    let mut peer_b = create_peer("PeerB", true);

    // Setup: intercambiar randoms
    let client_random = peer_a.dtls_agent.client_random.clone();
    let server_random = peer_b.dtls_agent.server_random.clone();
    peer_a.dtls_agent.server_random = server_random;
    peer_b.dtls_agent.client_random = client_random;

    peer_a.dtls_agent.fingerprint_verified = true;
    peer_b.dtls_agent.fingerprint_verified = true;
    peer_a.dtls_agent.compute_master_secret().ok();
    peer_b.dtls_agent.compute_master_secret().ok();

    // A → B
    let msg_ab = b"Message from A to B";
    let srtp_a = SrtpContext::new(peer_a.dtls_agent.get_master_secret());
    let enc_ab = srtp_a.encrypt_payload(msg_ab, 1000);
    let srtp_b = SrtpContext::new(peer_b.dtls_agent.get_master_secret());
    let dec_ab = srtp_b.decrypt_payload(&enc_ab, 1000).expect("B decrypts");
    assert_eq!(dec_ab, msg_ab.to_vec());

    // B → A
    let msg_ba = b"Message from B to A";
    let enc_ba = srtp_b.encrypt_payload(msg_ba, 2000);
    let dec_ba = srtp_a.decrypt_payload(&enc_ba, 2000).expect("A decrypts");
    assert_eq!(dec_ba, msg_ba.to_vec());
}

/// Test: Nonce uniqueness - Mismo payload con diferente sequence produce ciphertexts distintos
/// Verifica que el GCM mode usa sequence number como nonce, logrando que
/// el MISMO payload encriptado dos veces resulte en ciphertexts DIFERENTES.
#[test]
fn test_srtp_nonce_uniqueness() {
    let mut peer_a = create_peer("PeerA", false);
    let mut peer_b = create_peer("PeerB", true);

    // Setup: intercambiar randoms
    let client_random = peer_a.dtls_agent.client_random.clone();
    let server_random = peer_b.dtls_agent.server_random.clone();
    peer_a.dtls_agent.server_random = server_random;
    peer_b.dtls_agent.client_random = client_random;

    peer_a.dtls_agent.fingerprint_verified = true;
    peer_b.dtls_agent.fingerprint_verified = true;
    peer_a.dtls_agent.compute_master_secret().ok();
    peer_b.dtls_agent.compute_master_secret().ok();

    // Same payload, different sequence numbers
    let payload = b"Test payload";
    let srtp = SrtpContext::new(peer_a.dtls_agent.get_master_secret());
    let enc1 = srtp.encrypt_payload(payload, 1000);
    let enc2 = srtp.encrypt_payload(payload, 1001);

    // Ciphertexts deben ser diferentes (nonce unique per sequence)
    assert_ne!(
        enc1, enc2,
        "Diferentes sequences deben producir ciphertexts distintos"
    );
}

// Helper para crear peers
struct Peer {
    dtls_agent: DtlsAgent,
}

fn create_peer(_name: &str, is_server: bool) -> Peer {
    let cert_info = CertificateInfo::generate().expect("Failed to generate cert");
    let dtls_agent = if is_server {
        DtlsAgent::new_server(cert_info.fingerprint.clone(), None)
    } else {
        DtlsAgent::new_client(cert_info.fingerprint.clone(), None)
    };

    Peer { dtls_agent }
}
