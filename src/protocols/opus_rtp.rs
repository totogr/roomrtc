use crate::protocols::rtp_packet::{RtpHeader, RtpParams};

/// Paquetizador RTP para Opus
pub struct OpusRtpPacketizer {
    pub payload_type: u8,
    pub seq: u16,
    pub ssrc: u32,
}

impl OpusRtpPacketizer {
    /// Crear un nuevo paquetizador RTP para Opus
    pub fn new(ssrc: u32, initial_seq: u16) -> Self {
        Self {
            payload_type: 111,
            seq: initial_seq,
            ssrc,
        }
    }

    /// Paquetizar datos Opus en un paquete RTP
    pub fn packetize(&mut self, opus_data: &[u8], timestamp: u32) -> Vec<u8> {
        // Crear parametros del header RTP
        let rtp_params = RtpParams {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
        };

        // Crear header RTP
        // Marker bit tipicamente es false para audio (sin limites de frames como video)
        let header = RtpHeader::new(
            rtp_params,
            false, // marker
            self.payload_type,
            self.seq,
            timestamp,
            self.ssrc,
        );

        // Incrementar sequence number para el proximo paquete
        self.seq = self.seq.wrapping_add(1);

        // Construir paquete RTP completo: header (12 bytes) + payload Opus
        let rtp_header_len = 12;
        let mut packet = Vec::with_capacity(rtp_header_len + opus_data.len());
        packet.extend_from_slice(&header.to_bytes());
        packet.extend_from_slice(opus_data);

        packet
    }

    /// Obtener el sequence number actual
    pub fn sequence(&self) -> u16 {
        self.seq
    }

    /// Obtener el SSRC
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }
}

/// Despaquetizador RTP para Opus
pub struct OpusRtpDepacketizer;

impl OpusRtpDepacketizer {
    /// Crear un nuevo despaquetizador RTP para Opus
    pub fn new() -> Self {
        Self
    }

    /// Extraer payload Opus de un paquete RTP
    /// El payload RTP de Opus es simple - son solo los datos del frame Opus despues del header RTP.
    pub fn depacketize(&self, _header: &RtpHeader, payload: &[u8]) -> Vec<u8> {
        // Para Opus, el payload es simplemente el frame Opus
        // No se necesita procesamiento adicional
        payload.to_vec()
    }
}

impl Default for OpusRtpDepacketizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packetizer_creation() {
        let packetizer = OpusRtpPacketizer::new(54321, 0);
        assert_eq!(packetizer.payload_type, 111);
        assert_eq!(packetizer.ssrc(), 54321);
        assert_eq!(packetizer.sequence(), 0);
    }

    #[test]
    fn test_packetize_simple() {
        let mut packetizer = OpusRtpPacketizer::new(12345, 100);

        // Simulate a small Opus frame (50 bytes)
        let opus_frame = vec![0xAB; 50];
        let timestamp = 0;

        let rtp_packet = packetizer.packetize(&opus_frame, timestamp);

        // RTP packet should be 12 (header) + 50 (payload) = 62 bytes
        assert_eq!(rtp_packet.len(), 62);

        // Check RTP header fields
        let version = rtp_packet[0] >> 6;
        assert_eq!(version, 2);

        let payload_type = rtp_packet[1] & 0x7F;
        assert_eq!(payload_type, 111);

        let seq = u16::from_be_bytes([rtp_packet[2], rtp_packet[3]]);
        assert_eq!(seq, 100);

        let ts = u32::from_be_bytes([rtp_packet[4], rtp_packet[5], rtp_packet[6], rtp_packet[7]]);
        assert_eq!(ts, 0);

        let ssrc =
            u32::from_be_bytes([rtp_packet[8], rtp_packet[9], rtp_packet[10], rtp_packet[11]]);
        assert_eq!(ssrc, 12345);

        // Check payload
        assert_eq!(&rtp_packet[12..], &opus_frame[..]);
    }

    #[test]
    fn test_sequence_incrementing() {
        let mut packetizer = OpusRtpPacketizer::new(54321, 0);

        let opus_frame = vec![0; 100];

        // Send multiple packets
        for i in 0..10 {
            let packet = packetizer.packetize(&opus_frame, i * 960);
            let seq = u16::from_be_bytes([packet[2], packet[3]]);
            assert_eq!(seq, i as u16);
        }

        assert_eq!(packetizer.sequence(), 10);
    }

    #[test]
    fn test_sequence_wrapping() {
        let mut packetizer = OpusRtpPacketizer::new(54321, 65535);

        let opus_frame = vec![0; 50];

        // Should wrap from 65535 to 0
        let packet1 = packetizer.packetize(&opus_frame, 0);
        let seq1 = u16::from_be_bytes([packet1[2], packet1[3]]);
        assert_eq!(seq1, 65535);

        let packet2 = packetizer.packetize(&opus_frame, 960);
        let seq2 = u16::from_be_bytes([packet2[2], packet2[3]]);
        assert_eq!(seq2, 0); // Wrapped

        assert_eq!(packetizer.sequence(), 1);
    }

    #[test]
    fn test_timestamp_incrementing() {
        let mut packetizer = OpusRtpPacketizer::new(54321, 0);

        let opus_frame = vec![0; 100];

        // Timestamp should increment by frame size (960 for 20ms @ 48kHz)
        for i in 0..5 {
            let timestamp = i * 960;
            let packet = packetizer.packetize(&opus_frame, timestamp);
            let ts = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
            assert_eq!(ts, timestamp);
        }
    }

    #[test]
    fn test_depacketizer() {
        let depacketizer = OpusRtpDepacketizer::new();

        let opus_frame = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Create a dummy RTP header (not used by depacketizer)
        let rtp_params = RtpParams {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
        };
        let header = RtpHeader::new(rtp_params, false, 111, 0, 0, 12345);

        // Depacketize
        let result = depacketizer.depacketize(&header, &opus_frame);

        assert_eq!(result, opus_frame);
    }

    #[test]
    fn test_roundtrip() {
        let mut packetizer = OpusRtpPacketizer::new(99999, 500);
        let depacketizer = OpusRtpDepacketizer::new();

        let original_opus = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let timestamp = 12345;

        // Packetize
        let rtp_packet = packetizer.packetize(&original_opus, timestamp);

        // Parse header and extract payload
        let header = RtpHeader::from_bytes(&rtp_packet).unwrap();
        let payload = &rtp_packet[12..];

        // Depacketize
        let recovered_opus = depacketizer.depacketize(&header, payload);

        assert_eq!(recovered_opus, original_opus);
        assert_eq!(header.payload_type, 111);
        assert_eq!(header.timestamp, timestamp);
        assert_eq!(header.seq, 500);
        assert_eq!(header.ssrc, 99999);
    }

    #[test]
    fn test_large_opus_frame() {
        let mut packetizer = OpusRtpPacketizer::new(54321, 0);

        // Opus frames can be up to ~1275 bytes in practice
        let large_frame = vec![0xAA; 1000];
        let packet = packetizer.packetize(&large_frame, 0);

        assert_eq!(packet.len(), 12 + 1000);
        assert_eq!(&packet[12..], &large_frame[..]);
    }
}
