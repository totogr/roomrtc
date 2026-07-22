//! Módulo DTLS (Datagram Transport Layer Security) para handshake seguro P2P.
use std::time::{Duration, Instant};

/// Rol del agente DTLS: Cliente o Servidor.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DtlsRole {
    Client,
    Server,
}

/// Estado del handshake DTLS.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DtlsHandshakeState {
    Start,
    ClientHelloSent,
    ServerHelloReceived,
    ServerCertReceived,
    ServerHelloDoneReceived,
    ClientKeyExchangeSent,
    FinishedSent,
    FinishedReceived,
    Complete,
}

/// Estructura principal del agente DTLS.
pub struct DtlsAgent {
    pub role: DtlsRole,
    pub state: DtlsHandshakeState,
    pub local_fingerprint: String,
    pub remote_fingerprint: Option<String>,
    pub local_certificate: Option<Vec<u8>>,
    pub remote_certificate: Option<Vec<u8>>,
    pub fingerprint_verified: bool,
    pub master_secret: Vec<u8>, // Master secret for SRTP key derivation
    pub client_random: Vec<u8>, // 32 bytes aleatorios del ClientHello
    pub server_random: Vec<u8>, // 32 bytes aleatorios del ServerHello

    // Retransmission state
    pub last_flight: Option<Vec<u8>>,
    pub last_flight_timestamp: Option<Instant>,
    pub retransmit_count: u32,
}

/// Implementación de métodos para el agente DTLS.
impl DtlsAgent {
    pub fn new_client(local_fingerprint: String, remote_fingerprint: Option<String>) -> Self {
        use rand::Rng;

        // Generar 32 bytes aleatorios para client_random (RFC 3711)
        let mut rng = rand::rng();
        let mut client_random = vec![0u8; 32];
        rng.fill(&mut client_random[..]);

        DtlsAgent {
            role: DtlsRole::Client,
            state: DtlsHandshakeState::Start,
            local_fingerprint,
            remote_fingerprint,
            local_certificate: None,
            remote_certificate: None,
            fingerprint_verified: false,
            master_secret: Vec::new(),
            client_random,
            server_random: Vec::new(), // Se llenará cuando reciba ServerHello
            last_flight: None,
            last_flight_timestamp: None,
            retransmit_count: 0,
        }
    }

    /// Crea un nuevo agente DTLS en modo servidor.
    pub fn new_server(local_fingerprint: String, remote_fingerprint: Option<String>) -> Self {
        use rand::Rng;

        // Generar 32 bytes aleatorios para server_random (RFC 3711)
        let mut rng = rand::rng();
        let mut server_random = vec![0u8; 32];
        rng.fill(&mut server_random[..]);

        DtlsAgent {
            role: DtlsRole::Server,
            state: DtlsHandshakeState::Start,
            local_fingerprint,
            remote_fingerprint,
            local_certificate: None,
            remote_certificate: None,
            fingerprint_verified: false,
            master_secret: Vec::new(),
            client_random: Vec::new(), // Se llenará cuando reciba ClientHello
            server_random,
            last_flight: None,
            last_flight_timestamp: None,
            retransmit_count: 0,
        }
    }

    /// Establece el certificado local en formato DER.
    pub fn set_local_certificate(&mut self, cert_der: Vec<u8>) {
        self.local_certificate = Some(cert_der);
    }

    /// Computa el master_secret usando RFC 3711: HKDF-SHA256 con client_random y server_random.
    /// Los randoms se intercambian durante el handshake DTLS (ClientHello y ServerHello).
    /// El fingerprint debe estar verificado previamente para garantizar autenticidad.
    /// RFC 3711 especifica: master_secret = HKDF(salt, seed) donde seed = client_random || server_random.
    pub fn compute_master_secret(&mut self) -> Result<Vec<u8>, String> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        if !self.fingerprint_verified {
            return Err(format!(
                "No se puede derivar master_secret: fingerprint no verificado (local: {}, remoto: {:?})",
                self.local_fingerprint, self.remote_fingerprint
            ));
        }

        // Verificar que tenemos los randoms (RFC 3711)
        if self.client_random.is_empty() || self.server_random.is_empty() {
            return Err(
                "No se pueden derivar claves: client_random o server_random vacíos (handshake incompleto)"
                    .to_string(),
            );
        }

        // RFC 3711: Combinar client_random y server_random como seed
        // El seed es la concatenación de ambos randoms (64 bytes totales)
        let mut seed = Vec::new();
        seed.extend_from_slice(&self.client_random);
        seed.extend_from_slice(&self.server_random);

        // Usar HKDF-SHA256 como PRF (RFC 5869)
        // RFC 3711 recomienda salt de 14 bytes inicialmente ceros
        let salt = [0u8; 14];
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &seed);

        // Expandir a 32 bytes de master_secret
        let mut master_secret_bytes = [0u8; 32];
        hkdf.expand(b"DTLS_SRTP_MASTER_SECRET", &mut master_secret_bytes)
            .map_err(|e| format!("HKDF expand failed: {}", e))?;

        let master_secret = master_secret_bytes.to_vec();
        self.master_secret = master_secret.clone();

        Ok(master_secret)
    }

    /// Obtiene el master_secret actual.
    pub fn get_master_secret(&self) -> &[u8] {
        &self.master_secret
    }

    /// Extrae el certificado del mensaje Certificate y valida el fingerprint.
    pub fn validate_certificate_message(&mut self, cert_msg: &[u8]) -> Result<bool, String> {
        // Formato del mensaje: 0x16 + 0x0b + "Certificate" + (length | cert_data)
        if cert_msg.len() < 15 {
            return Err("Certificate message too short".to_string());
        }

        let header_len = 2 + 11; // 0x16, 0x0b, "Certificate"
        if cert_msg.len() < header_len + 2 {
            return Err("Sin datos de certificado en el mensaje".to_string());
        }

        // Extrae cert_len (2 bytes, big-endian) y datos del certificado
        let cert_len_bytes = &cert_msg[header_len..header_len + 2];
        let cert_len = u16::from_be_bytes([cert_len_bytes[0], cert_len_bytes[1]]) as usize;

        if cert_len == 0 {
            // Longitud es 0, significa que el fingerprint se incluye en su lugar
            let fingerprint_data = &cert_msg[header_len + 2..];
            let received_fingerprint = String::from_utf8_lossy(fingerprint_data).to_string();

            match &self.remote_fingerprint {
                Some(expected_fp) => {
                    self.fingerprint_verified = received_fingerprint == *expected_fp;
                    Ok(self.fingerprint_verified)
                }
                None => {
                    // Sin fingerprint para verificar
                    self.fingerprint_verified = true;
                    Ok(true)
                }
            }
        } else {
            // Extrae y almacena el certificado
            let cert_data_start = header_len + 2;
            let cert_data_end = cert_data_start + cert_len;

            if cert_msg.len() < cert_data_end {
                return Err("Datos del certificado truncados".to_string());
            }

            let cert_der = cert_msg[cert_data_start..cert_data_end].to_vec();
            self.remote_certificate = Some(cert_der.clone());

            // Verifica el fingerprint haciendo hash del certificado
            self.fingerprint_verified = self.verify_remote_fingerprint(&cert_der)?;
            Ok(self.fingerprint_verified)
        }
    }

    /// Verifica el fingerprint remoto haciendo hash del certificado.
    fn verify_remote_fingerprint(&self, cert_der: &[u8]) -> Result<bool, String> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        let hash = hasher.finalize();

        let computed_fingerprint = format!(
            "sha-256 {}",
            hash.iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(":")
        );

        match &self.remote_fingerprint {
            Some(expected_fp) => {
                let is_match = computed_fingerprint == *expected_fp;
                Ok(is_match)
            }
            None => Ok(true), // No fingerprint to verify
        }
    }

    /// Indica si el handshake DTLS está completo.
    pub fn is_complete(&self) -> bool {
        self.state == DtlsHandshakeState::Complete
    }

    /// Genera un reporte de validación del fingerprint.
    pub fn get_validation_report(&self) -> String {
        if !self.fingerprint_verified {
            return "Fingerprint NOT verified (validation failed or not yet performed)".to_string();
        }

        match (&self.remote_fingerprint, &self.remote_certificate) {
            (Some(expected_fp), Some(_cert)) => {
                format!("✓ Fingerprint verified: {}", expected_fp)
            }
            (Some(expected_fp), None) => {
                format!("✓ Fingerprint verified (from message): {}", expected_fp)
            }
            (None, _) => "Fingerprint verified (no expected fingerprint to check)".to_string(),
        }
    }

    /// Procesa un paquete DTLS entrante y genera una respuesta si es necesario.
    pub fn process_packet(&mut self, buf: &[u8]) -> Result<Option<Vec<u8>>, String> {
        // Allow empty buffer for Client initialization (to send ClientHello)
        if buf.is_empty()
            && !(matches!(self.role, DtlsRole::Client) && self.state == DtlsHandshakeState::Start)
        {
            return Ok(None);
        }

        let result = match self.role {
            DtlsRole::Client => self.process_as_client(buf),
            DtlsRole::Server => self.process_as_server(buf),
        };

        // Handle retransmission state updates
        match &result {
            Ok(Some(response)) => {
                self.last_flight = Some(response.clone());
                self.last_flight_timestamp = Some(Instant::now());
                self.retransmit_count = 0;
            }
            Ok(None) => {
                if !buf.is_empty() {
                    self.last_flight = None;
                    self.last_flight_timestamp = None;
                    self.retransmit_count = 0;
                }
            }
            Err(_) => {
                // Error processing packet
            }
        }

        result
    }

    /// Verifica si es necesario retransmitir el último vuelo de mensajes.
    pub fn check_retransmission(&mut self) -> Option<Vec<u8>> {
        if let (Some(flight), Some(timestamp)) = (&self.last_flight, self.last_flight_timestamp) {
            if self.is_complete() {
                return None;
            }

            // Exponential backoff: 500ms * 2^count
            let timeout_ms = 500 * (1 << self.retransmit_count);
            let timeout_ms = std::cmp::min(timeout_ms, 4000);

            if timestamp.elapsed() > Duration::from_millis(timeout_ms) {
                if self.retransmit_count >= 5 {
                    return None;
                }

                self.retransmit_count += 1;
                self.last_flight_timestamp = Some(Instant::now());
                return Some(flight.clone());
            }
        }
        None
    }

    /// Procesa el paquete como cliente DTLS.
    fn process_as_client(&mut self, buf: &[u8]) -> Result<Option<Vec<u8>>, String> {
        match self.state {
            DtlsHandshakeState::Start => {
                self.state = DtlsHandshakeState::ClientHelloSent;
                let msg = self.build_client_hello();
                Ok(Some(msg))
            }
            DtlsHandshakeState::ClientHelloSent => {
                // Parse multiple messages that might be concatenated in one packet
                let mut pos = 0;
                while pos < buf.len() {
                    if pos + 2 > buf.len() {
                        break;
                    }
                    let msg_type = buf[pos + 1];

                    match msg_type {
                        0x02 => {
                            // ServerHello
                            // Extraer server_random (32 bytes)
                            // Estructura: [0x16(1) + 0x02(1) + "ServerHello"(11) + server_random(32)]
                            // Posición desde pos: 2 + 11 = 13
                            if pos + 45 <= buf.len() {
                                self.server_random = buf[pos + 13..pos + 45].to_vec();
                            }

                            self.state = DtlsHandshakeState::ServerHelloReceived;
                            pos += 45; // 0x16 + 0x02 + "ServerHello" + server_random
                        }
                        0x0b => {
                            // Certificate
                            // Validate the certificate immediately
                            let cert_msg = &buf[pos..];
                            match self.validate_certificate_message(cert_msg) {
                                Ok(_verified) => {
                                    self.state = DtlsHandshakeState::ServerCertReceived;
                                    // Certificate validation stored in self.fingerprint_verified
                                }
                                Err(_e) => {
                                    // Continue anyway, validation will be checked later
                                    self.state = DtlsHandshakeState::ServerCertReceived;
                                }
                            }
                            // Skip the actual certificate message: header (13 bytes) + cert_len (2 bytes) + cert_data
                            if pos + 15 <= buf.len() {
                                let cert_len_bytes = &buf[pos + 13..pos + 15];
                                let cert_len =
                                    u16::from_be_bytes([cert_len_bytes[0], cert_len_bytes[1]])
                                        as usize;
                                pos += 13 + 2 + cert_len; // header + length field + certificate data
                            } else {
                                pos += 13; // Fallback if not enough bytes
                            }
                        }
                        0x0e => {
                            // ServerHelloDone
                            self.state = DtlsHandshakeState::ServerHelloDoneReceived;
                            pos += 16; // 0x16 + 0x0e + "ServerHelloDone" (15 bytes)
                        }
                        _ => {
                            pos += 1; // Skip unknown message
                        }
                    }
                }

                // Once we've processed ServerHelloDone, send ClientCertificate + ClientKeyExchange + Finished
                if self.state == DtlsHandshakeState::ServerHelloDoneReceived {
                    let mut response = Vec::new();
                    response.extend(self.build_client_certificate());
                    response.extend(self.build_client_key_exchange());
                    response.extend(self.build_finished());
                    self.state = DtlsHandshakeState::FinishedSent;
                    Ok(Some(response))
                } else if self.state == DtlsHandshakeState::ServerHelloReceived
                    || self.state == DtlsHandshakeState::ServerCertReceived
                {
                    // Still processing messages, not ready to send yet
                    Ok(None)
                } else {
                    Err(
                        "Expected server messages (ServerHello, Certificate, ServerHelloDone)"
                            .to_string(),
                    )
                }
            }
            DtlsHandshakeState::ClientKeyExchangeSent => {
                // This state should only be reached if we receive a packet after sending ClientKeyExchange
                // which shouldn't happen with the concatenated message approach
                Err(
                    "Unexpected: ClientKeyExchangeSent state reached with packet reception"
                        .to_string(),
                )
            }
            DtlsHandshakeState::FinishedSent => {
                if self.looks_like_finished(buf) {
                    self.state = DtlsHandshakeState::Complete;
                    Ok(None)
                } else {
                    Err("Expected Finished".to_string())
                }
            }
            _ => Err(format!("Invalid state for client: {:?}", self.state)),
        }
    }

    /// Procesa el paquete como servidor DTLS.
    fn process_as_server(&mut self, buf: &[u8]) -> Result<Option<Vec<u8>>, String> {
        match self.state {
            DtlsHandshakeState::Start => {
                if self.looks_like_client_hello(buf) {
                    // Extraer client_random del ClientHello (32 bytes)
                    // Estructura: [0x16(1) + 0x01(1) + "ClientHello"(11) + client_random(32)]
                    // Posición: 2 + 11 = 13
                    if buf.len() >= 45 {
                        self.client_random = buf[13..45].to_vec();
                    }

                    self.state = DtlsHandshakeState::ClientHelloSent;
                    let mut response = Vec::new();
                    response.extend(self.build_server_hello());
                    response.extend(self.build_server_cert());
                    response.extend(self.build_server_hello_done());
                    Ok(Some(response))
                } else {
                    Err("Expected ClientHello".to_string())
                }
            }
            DtlsHandshakeState::ClientHelloSent => {
                // Parse multiple messages that might be concatenated in one packet
                let mut pos = 0;
                let mut found_key_exchange = false;
                let mut found_finished = false;

                while pos < buf.len() {
                    if pos + 2 > buf.len() {
                        break;
                    }
                    let msg_type = buf[pos + 1];

                    match msg_type {
                        0x0b => {
                            // ClientCertificate
                            let cert_msg = &buf[pos..];
                            match self.validate_certificate_message(cert_msg) {
                                Ok(_verified) => {
                                    // Certificate validation stored in self.fingerprint_verified
                                }
                                Err(_e) => {
                                    // Continue anyway
                                }
                            }
                            // Skip the certificate message: header (13 bytes) + cert_len (2 bytes) + cert_data
                            if pos + 15 <= buf.len() {
                                let cert_len_bytes = &buf[pos + 13..pos + 15];
                                let cert_len =
                                    u16::from_be_bytes([cert_len_bytes[0], cert_len_bytes[1]])
                                        as usize;
                                pos += 13 + 2 + cert_len; // header + length field + certificate data
                            } else {
                                pos += 13; // Fallback if not enough bytes
                            }
                        }
                        0x10 => {
                            // ClientKeyExchange
                            found_key_exchange = true;
                            self.state = DtlsHandshakeState::ClientKeyExchangeSent;
                            pos += 17; // 0x16 + 0x10 + "ClientKeyExchange" (16 bytes)
                        }
                        0x14 => {
                            // Finished
                            found_finished = true;
                            self.state = DtlsHandshakeState::FinishedReceived;
                            pos += 9; // 0x16 + 0x14 + "Finished" (8 bytes)
                        }
                        _ => {
                            pos += 1; // Skip unknown message
                        }
                    }
                }

                // If we found both messages, send Finished and complete
                if found_finished && found_key_exchange {
                    let finished = self.build_finished();
                    self.state = DtlsHandshakeState::Complete;
                    Ok(Some(finished))
                } else if found_key_exchange {
                    // Got ClientKeyExchange but no Finished yet
                    Ok(None)
                } else {
                    Err("Expected ClientKeyExchange and/or Finished".to_string())
                }
            }
            DtlsHandshakeState::ClientKeyExchangeSent => {
                // This state should only be reached if we receive Finished separately
                if self.looks_like_finished(buf) {
                    self.state = DtlsHandshakeState::FinishedReceived;
                    let finished = self.build_finished();
                    self.state = DtlsHandshakeState::Complete;
                    Ok(Some(finished))
                } else {
                    Err("Expected Finished".to_string())
                }
            }
            _ => Err(format!("Invalid state for server: {:?}", self.state)),
        }
    }

    /// Construye el mensaje ClientHello para el handshake DTLS.
    fn build_client_hello(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.push(0x16); // DTLS Handshake content type
        msg.push(0x01); // ClientHello type
        msg.extend_from_slice(b"ClientHello");
        // RFC 3711: Incluir client_random (32 bytes) en el mensaje
        msg.extend_from_slice(&self.client_random);
        msg
    }

    /// Construye el mensaje ServerHello para el handshake DTLS.
    fn build_server_hello(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.push(0x16); // DTLS Handshake content type
        msg.push(0x02); // ServerHello type
        msg.extend_from_slice(b"ServerHello");
        // RFC 3711: Incluir server_random (32 bytes) en el mensaje
        msg.extend_from_slice(&self.server_random);
        msg
    }

    /// Construye el mensaje Certificate para el handshake DTLS.
    fn build_server_cert(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.push(0x16); // DTLS Handshake content type
        msg.push(0x0b); // Certificate type
        msg.extend_from_slice(b"Certificate");

        // Si tenemos el certificado, lo enviamos; de lo contrario, enviamos el fingerprint
        if let Some(cert_der) = &self.local_certificate {
            // Envía longitud del certificado (2 bytes, big-endian)
            let cert_len = cert_der.len() as u16;
            msg.extend_from_slice(&cert_len.to_be_bytes());
            // Envía bytes DER del certificado
            msg.extend_from_slice(cert_der);
        } else {
            // Alternativa: envía el fingerprint
            msg.push(0x00);
            msg.push(0x00);
            msg.extend_from_slice(self.local_fingerprint.as_bytes());
        }
        msg
    }

    /// Construye el mensaje ClientCertificate para el handshake DTLS.
    fn build_client_certificate(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.push(0x16); // DTLS Handshake content type
        msg.push(0x0b); // Certificate type (same as server cert)
        msg.extend_from_slice(b"Certificate");

        // El cliente envía su certificado igual que el servidor
        if let Some(cert_der) = &self.local_certificate {
            // Envía longitud del certificado (2 bytes, big-endian)
            let cert_len = cert_der.len() as u16;
            msg.extend_from_slice(&cert_len.to_be_bytes());
            // Envía bytes DER del certificado
            msg.extend_from_slice(cert_der);
        } else {
            // Alternativa: envía certificado de longitud 0
            msg.push(0x00);
            msg.push(0x00);
        }
        msg
    }

    /// Construye el mensaje ServerHelloDone para el handshake DTLS.
    fn build_server_hello_done(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.push(0x16); // DTLS Handshake content type
        msg.push(0x0e); // ServerHelloDone type
        msg.extend_from_slice(b"ServerHelloDone");
        msg
    }

    /// Construye el mensaje ClientKeyExchange para el handshake DTLS.
    fn build_client_key_exchange(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.push(0x16); // DTLS Handshake content type
        msg.push(0x10); // ClientKeyExchange type
        msg.extend_from_slice(b"ClientKeyExchange");
        msg
    }

    /// Construye el mensaje Finished para el handshake DTLS.
    fn build_finished(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.push(0x16); // DTLS Handshake content type
        msg.push(0x14); // Finished type
        msg.extend_from_slice(b"Finished");
        msg
    }

    /// Verifica si el buffer parece un ClientHello.
    fn looks_like_client_hello(&self, buf: &[u8]) -> bool {
        !buf.is_empty() && buf.len() > 5
    }

    /// Verifica si el buffer parece un mensaje Finished.
    fn looks_like_finished(&self, buf: &[u8]) -> bool {
        !buf.is_empty() && buf.len() > 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_handshake() {
        let mut client = DtlsAgent::new_client(
            "sha-256 AA:BB:CC:DD".to_string(),
            Some("sha-256 11:22:33:44".to_string()),
        );

        assert_eq!(client.state, DtlsHandshakeState::Start);

        let hello = client.process_packet(&[]).unwrap().unwrap();
        assert!(!hello.is_empty());
        assert_eq!(client.state, DtlsHandshakeState::ClientHelloSent);

        assert!(client.process_packet(&[1, 2, 3]).is_ok());
        assert_eq!(client.state, DtlsHandshakeState::ServerHelloReceived);
    }

    #[test]
    fn test_server_handshake() {
        let mut server = DtlsAgent::new_server(
            "sha-256 AA:BB:CC:DD".to_string(),
            Some("sha-256 11:22:33:44".to_string()),
        );

        assert_eq!(server.state, DtlsHandshakeState::Start);

        let response = server.process_packet(&[1, 2, 3, 4, 5, 6]).unwrap().unwrap();
        assert!(!response.is_empty());
        assert_eq!(server.state, DtlsHandshakeState::ClientHelloSent);
    }

    #[test]
    fn test_retransmission() {
        let mut client = DtlsAgent::new_client(
            "sha-256 AA:BB:CC:DD".to_string(),
            Some("sha-256 11:22:33:44".to_string()),
        );

        assert!(client.check_retransmission().is_none());
        let hello = client.process_packet(&[]).unwrap().unwrap();
        assert!(client.last_flight.is_some());
        assert_eq!(client.retransmit_count, 0);
        assert!(client.check_retransmission().is_none());

        client.last_flight_timestamp = Some(Instant::now() - Duration::from_secs(1));

        let retransmitted = client.check_retransmission();
        assert!(retransmitted.is_some());
        assert_eq!(retransmitted.unwrap(), hello);
        assert_eq!(client.retransmit_count, 1);
        let _ = client.process_packet(&[0x16, 0x02, 0x00]);
        assert!(client.last_flight.is_none());
    }
}
