//! Módulo para codificación y decodificación de paquetes RTCP (RTP Control Protocol)

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Versión del protocolo RTCP según RFC3550
pub const RTCP_VERSION: u8 = 2;
/// Payload Type de RTCP para Sender Report
pub const PT_SR: u8 = 200;
/// Payload Type de RTCP para Receiver Report
pub const PT_RR: u8 = 201;
/// Payload Type de RTCP para Source Description
pub const PT_SDES: u8 = 202;
/// Payload Type de RTCP para Source Description
pub const PT_BYE: u8 = 203;
/// Payload Type de RTCP para Payload-Specific Feedback Message (PSFB)
pub const PT_PSFB: u8 = 206;
/// Feedback Message Type (FMT) para Picture Loss Indication (PLI)
pub const FMT_PLI: u8 = 1;

/// Marcador de fin de lista de items SDES.
pub const SDES_END: u8 = 0;
/// Tipo de item SDES para CNAME
pub const SDES_CNAME: u8 = 1;

/// Cabecera RTCP común a todos los paquetes (V, P, count, PT, length).
#[derive(Debug)]
pub struct RtcpHeader {
    pub version: u8,
    pub padding: bool,
    pub count: u8,
    pub pt: u8,
    pub length: u16,
}

/// Implementación de métodos para RtcpHeader
impl RtcpHeader {
    /// Serializa la cabecera RTCP a 4 bytes.
    pub fn to_bytes(&self) -> [u8; 4] {
        let mut b = [0u8; 4];
        b[0] = (self.version << 6) | ((self.padding as u8) << 5) | (self.count & 0x1F);
        b[1] = self.pt;
        b[2..4].copy_from_slice(&self.length.to_be_bytes());
        b
    }

    /// Deserializa una cabecera RTCP desde `buf` y
    /// devuelve la cabecera y el tamaño total del paquete RTCP en bytes.
    pub fn from_bytes(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 4 {
            return None;
        }
        let v = buf[0] >> 6;
        if v != RTCP_VERSION {
            return None;
        }
        let padding = (buf[0] & 0x20) != 0;
        let count = buf[0] & 0x1F;
        let pt = buf[1];
        let length = u16::from_be_bytes([buf[2], buf[3]]);
        let bytes = ((length as usize) + 1) * 4;
        if buf.len() < bytes {
            return None;
        }
        Some((
            Self {
                version: v,
                padding,
                count,
                pt,
                length,
            },
            bytes,
        ))
    }
}

/// Bloque report block usado en SR/RR con métricas de recepción.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReportBlock {
    pub ssrc: u32,
    pub fraction_lost: u8,
    pub cumulative_lost: u32,
    pub ext_highest_seq: u32,
    pub jitter: u32,
    pub lsr: u32,
    pub dlsr: u32,
}

/// Implementación de métodos para ReportBlock
impl ReportBlock {
    /// Serializa el ReportBlock a bytes RTCP.
    fn as_bytes_from_ref(&self) -> [u8; 24] {
        let mut b = [0u8; 24];
        b[0..4].copy_from_slice(&self.ssrc.to_be_bytes());
        b[4] = self.fraction_lost;
        let cum = self.cumulative_lost & 0x00FF_FFFF;
        b[5] = ((cum >> 16) & 0xFF) as u8;
        b[6] = ((cum >> 8) & 0xFF) as u8;
        b[7] = (cum & 0xFF) as u8;
        b[8..12].copy_from_slice(&self.ext_highest_seq.to_be_bytes());
        b[12..16].copy_from_slice(&self.jitter.to_be_bytes());
        b[16..20].copy_from_slice(&self.lsr.to_be_bytes());
        b[20..24].copy_from_slice(&self.dlsr.to_be_bytes());
        b
    }
}

/// Paquete RTCP Sender Report SR, sincroniza tiempo NTP/RTP y reporta conteos enviados.
#[derive(Debug, Clone)]
pub struct SenderReport {
    pub ssrc: u32,
    pub ntp_secs: u32,
    pub ntp_frac: u32,
    pub rtp_ts: u32,
    pub packet_count: u32,
    pub byte_count: u32,
    pub reports: Vec<ReportBlock>,
}

/// Implementación de métodos para SenderReport
impl SenderReport {
    /// Serializa el paquete SR a bytes RTCP.
    pub fn to_bytes(&self) -> Vec<u8> {
        let rb_len = self.reports.len() * 24;
        let payload_len = 24 + rb_len;
        let length_words = ((payload_len + 4) / 4) - 1;
        let hdr = RtcpHeader {
            version: RTCP_VERSION,
            padding: false,
            count: self.reports.len() as u8,
            pt: PT_SR,
            length: length_words as u16,
        };
        let mut out = Vec::with_capacity(4 + payload_len);
        out.extend_from_slice(&hdr.to_bytes());
        out.extend_from_slice(&self.ssrc.to_be_bytes());
        out.extend_from_slice(&self.ntp_secs.to_be_bytes());
        out.extend_from_slice(&self.ntp_frac.to_be_bytes());
        out.extend_from_slice(&self.rtp_ts.to_be_bytes());
        out.extend_from_slice(&self.packet_count.to_be_bytes());
        out.extend_from_slice(&self.byte_count.to_be_bytes());
        for rb in &self.reports {
            out.extend_from_slice(&rb.as_bytes_from_ref());
        }
        out
    }
}

/// Paquete RTCP Receiver Report, informa estadísticas de recepción hacia el emisor.
#[derive(Debug)]
pub struct ReceiverReport {
    pub ssrc: u32,
    pub reports: Vec<ReportBlock>,
}

/// Implementación de métodos para ReceiverReport
impl ReceiverReport {
    /// Serializa el paquete RR a bytes RTCP.
    pub fn to_bytes(&self) -> Vec<u8> {
        let rb_len = self.reports.len() * 24;
        let payload_len = 4 + rb_len;
        let length_words = ((payload_len + 4) / 4) - 1;
        let hdr = RtcpHeader {
            version: RTCP_VERSION,
            padding: false,
            count: self.reports.len() as u8,
            pt: PT_RR,
            length: length_words as u16,
        };
        let mut out = Vec::with_capacity(4 + payload_len);
        out.extend_from_slice(&hdr.to_bytes());
        out.extend_from_slice(&self.ssrc.to_be_bytes());
        for rb in &self.reports {
            out.extend_from_slice(&rb.as_bytes_from_ref());
        }
        out
    }
}

/// Item SDES que contiene un tipo y texto descriptivo.
#[derive(Debug, Clone)]
pub struct SdesItem {
    pub typ: u8,
    pub text: String,
}

/// Chunk SDES que agrupa items de descripción para un SSRC.
#[derive(Debug, Clone)]
pub struct SdesChunk {
    pub ssrc: u32,
    pub items: Vec<SdesItem>,
}

/// Implementación de métodos para SdesChunk
impl SdesChunk {
    fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.ssrc.to_be_bytes());
        for it in &self.items {
            v.push(it.typ);
            v.push(it.text.len() as u8);
            v.extend_from_slice(it.text.as_bytes());
        }
        v.push(SDES_END);
        // pad 32-bit
        while (v.len() % 4) != 0 {
            v.push(0);
        }
        v
    }
}

/// Paquete RTCP BYE, indica que un participante está dejando la sesión
#[derive(Debug, Clone)]
pub struct Bye {
    pub ssrcs: Vec<u32>,
    pub reason: Option<String>,
}

/// Implementación de métodos para Bye
impl Bye {
    /// Serializa el paquete BYE a bytes RTCP
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut payload = Vec::new();

        // Agregar SSRCs
        for ssrc in &self.ssrcs {
            payload.extend_from_slice(&ssrc.to_be_bytes());
        }

        // Agregar razón opcional
        if let Some(reason) = &self.reason {
            let reason_bytes = reason.as_bytes();
            let len = reason_bytes.len().min(255);
            payload.push(len as u8);
            payload.extend_from_slice(&reason_bytes[..len]);

            // Padding a 32 bits
            while (payload.len() % 4) != 0 {
                payload.push(0);
            }
        }

        let length_words = ((payload.len() + 4) / 4) - 1;
        let hdr = RtcpHeader {
            version: RTCP_VERSION,
            padding: false,
            count: self.ssrcs.len() as u8,
            pt: PT_BYE,
            length: length_words as u16,
        };

        let mut out = Vec::with_capacity(4 + payload.len());
        out.extend_from_slice(&hdr.to_bytes());
        out.extend_from_slice(&payload);
        out
    }
}

/// Paquete RTCP
/// Picture Loss Indication (PLI)
#[derive(Debug, Clone)]
pub struct PictureLossIndication {
    pub sender_ssrc: u32,
    pub media_ssrc: u32,
}

/// Implementación de métodos para PictureLossIndication
impl PictureLossIndication {
    pub fn to_bytes(&self) -> Vec<u8> {
        let length_words = 2; // (8 bytes payload + 4 bytes header) / 4 - 1 = 2
        let hdr = RtcpHeader {
            version: RTCP_VERSION,
            padding: false,
            count: FMT_PLI, // FMT goes in count field
            pt: PT_PSFB,
            length: length_words,
        };
        let mut out = Vec::with_capacity(12);
        out.extend_from_slice(&hdr.to_bytes());
        out.extend_from_slice(&self.sender_ssrc.to_be_bytes());
        out.extend_from_slice(&self.media_ssrc.to_be_bytes());
        out
    }
}

/// Enum de paquetes RTCP soportados
#[derive(Debug)]
pub enum RtcpPacket {
    SR(SenderReport),
    RR(ReceiverReport),
    SDES(Vec<SdesChunk>),
    BYE(Bye),
    PLI(PictureLossIndication),
}

/// Codifica un paquete RTCP compuesto
pub fn encode_compound(packets: &[RtcpPacket]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in packets {
        match p {
            RtcpPacket::SR(sr) => out.extend_from_slice(&sr.to_bytes()),
            RtcpPacket::RR(rr) => out.extend_from_slice(&rr.to_bytes()),
            RtcpPacket::SDES(chunks) => {
                let mut body = Vec::new();
                for ch in chunks {
                    body.extend_from_slice(&ch.to_bytes());
                }
                let length_words = ((body.len() + 4) / 4) - 1;
                let hdr = RtcpHeader {
                    version: RTCP_VERSION,
                    padding: false,
                    count: chunks.len() as u8,
                    pt: PT_SDES,
                    length: length_words as u16,
                };
                out.extend_from_slice(&hdr.to_bytes());
                out.extend_from_slice(&body);
            }
            RtcpPacket::BYE(bye) => out.extend_from_slice(&bye.to_bytes()),
            RtcpPacket::PLI(pli) => out.extend_from_slice(&pli.to_bytes()),
        }
    }
    out
}

/// Verifica si el buffer contiene un paquete RTCP válido
pub fn is_rtcp(buf: &[u8]) -> bool {
    if buf.len() < 4 {
        return false;
    }
    let v = buf[0] >> 6;
    if v != RTCP_VERSION {
        return false;
    }
    let pt = buf[1];
    matches!(pt, PT_SR | PT_RR | PT_SDES | PT_BYE | 204 | 205 | 206 | 207)
}

/// Decodifica un paquete RTCP compuesto desde el buffer dado
pub fn decode_compound(buf: &[u8]) -> Vec<RtcpPacket> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 4 <= buf.len() {
        if let Some((hdr, bytes)) = RtcpHeader::from_bytes(&buf[off..]) {
            let body = &buf[off + 4..off + bytes];
            match hdr.pt {
                PT_SR => {
                    if body.len() >= 24 {
                        let ssrc = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                        let ntp_secs = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                        let ntp_frac = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
                        let rtp_ts = u32::from_be_bytes([body[12], body[13], body[14], body[15]]);
                        let packet_count =
                            u32::from_be_bytes([body[16], body[17], body[18], body[19]]);
                        let byte_count =
                            u32::from_be_bytes([body[20], body[21], body[22], body[23]]);
                        let mut reports = Vec::new();
                        let mut o = 24usize;
                        for _ in 0..hdr.count {
                            if o + 24 > body.len() {
                                break;
                            }
                            let ssrc_rb = u32::from_be_bytes([
                                body[o],
                                body[o + 1],
                                body[o + 2],
                                body[o + 3],
                            ]);
                            let fraction_lost = body[o + 4];
                            let cumulative_lost = ((body[o + 5] as u32) << 16)
                                | ((body[o + 6] as u32) << 8)
                                | (body[o + 7] as u32);
                            let ext_highest_seq = u32::from_be_bytes([
                                body[o + 8],
                                body[o + 9],
                                body[o + 10],
                                body[o + 11],
                            ]);
                            let jitter = u32::from_be_bytes([
                                body[o + 12],
                                body[o + 13],
                                body[o + 14],
                                body[o + 15],
                            ]);
                            let lsr = u32::from_be_bytes([
                                body[o + 16],
                                body[o + 17],
                                body[o + 18],
                                body[o + 19],
                            ]);
                            let dlsr = u32::from_be_bytes([
                                body[o + 20],
                                body[o + 21],
                                body[o + 22],
                                body[o + 23],
                            ]);
                            reports.push(ReportBlock {
                                ssrc: ssrc_rb,
                                fraction_lost,
                                cumulative_lost,
                                ext_highest_seq,
                                jitter,
                                lsr,
                                dlsr,
                            });
                            o += 24;
                        }
                        out.push(RtcpPacket::SR(SenderReport {
                            ssrc,
                            ntp_secs,
                            ntp_frac,
                            rtp_ts,
                            packet_count,
                            byte_count,
                            reports,
                        }));
                    }
                }
                PT_RR => {
                    if body.len() >= 4 {
                        let ssrc = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                        let mut reports = Vec::new();
                        let mut o = 4usize;
                        for _ in 0..hdr.count {
                            if o + 24 > body.len() {
                                break;
                            }
                            let ssrc_rb = u32::from_be_bytes([
                                body[o],
                                body[o + 1],
                                body[o + 2],
                                body[o + 3],
                            ]);
                            let fraction_lost = body[o + 4];
                            let cumulative_lost = ((body[o + 5] as u32) << 16)
                                | ((body[o + 6] as u32) << 8)
                                | (body[o + 7] as u32);
                            let ext_highest_seq = u32::from_be_bytes([
                                body[o + 8],
                                body[o + 9],
                                body[o + 10],
                                body[o + 11],
                            ]);
                            let jitter = u32::from_be_bytes([
                                body[o + 12],
                                body[o + 13],
                                body[o + 14],
                                body[o + 15],
                            ]);
                            let lsr = u32::from_be_bytes([
                                body[o + 16],
                                body[o + 17],
                                body[o + 18],
                                body[o + 19],
                            ]);
                            let dlsr = u32::from_be_bytes([
                                body[o + 20],
                                body[o + 21],
                                body[o + 22],
                                body[o + 23],
                            ]);
                            reports.push(ReportBlock {
                                ssrc: ssrc_rb,
                                fraction_lost,
                                cumulative_lost,
                                ext_highest_seq,
                                jitter,
                                lsr,
                                dlsr,
                            });
                            o += 24;
                        }
                        out.push(RtcpPacket::RR(ReceiverReport { ssrc, reports }));
                    }
                }
                PT_SDES => {
                    out.push(RtcpPacket::SDES(Vec::new()));
                }
                PT_BYE => {
                    let mut ssrcs = Vec::new();
                    let mut o = 0usize;

                    // Leer SSRCs
                    for _ in 0..hdr.count {
                        if o + 4 > body.len() {
                            break;
                        }
                        let ssrc =
                            u32::from_be_bytes([body[o], body[o + 1], body[o + 2], body[o + 3]]);
                        ssrcs.push(ssrc);
                        o += 4;
                    }

                    // Leer razón opcional
                    let reason = if o < body.len() {
                        let len = body[o] as usize;
                        if o + 1 + len <= body.len() {
                            String::from_utf8_lossy(&body[o + 1..o + 1 + len])
                                .to_string()
                                .into()
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    out.push(RtcpPacket::BYE(Bye { ssrcs, reason }));
                }

                PT_PSFB => {
                    if hdr.count == FMT_PLI && body.len() >= 8 {
                        let sender_ssrc = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                        let media_ssrc = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                        out.push(RtcpPacket::PLI(PictureLossIndication {
                            sender_ssrc,
                            media_ssrc,
                        }));
                    }
                }
                _ => {}
            }
            off += bytes;
        } else {
            break;
        }
    }
    out
}

/// Obtiene el tiempo actual en formato NTP de 64 bits
pub fn now_ntp64() -> (u32, u32) {
    const NTP_UNIX_EPOCH_DIFF: u64 = 2_208_988_800;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    let secs = now.as_secs() + NTP_UNIX_EPOCH_DIFF;
    let frac = ((now.subsec_nanos() as u64) << 32) / 1_000_000_000u64;
    (secs as u32, frac as u32)
}

/// Calcula los 32 bits intermedios (LSR) de una marca de tiempo NTP 64-bit.
pub fn middle_ntp32(secs: u32, frac: u32) -> u32 {
    ((secs & 0xFFFF) << 16) | ((frac >> 16) & 0xFFFF)
}

/// Construye un paquete RTCP compuesto con `SR` + `SDES(CNAME)`
pub fn build_sr_sdes(ssrc: u32, rtp_ts: u32, packets: u32, bytes: u32, cname: &str) -> Vec<u8> {
    let (ntp_s, ntp_f) = now_ntp64();
    let sr = SenderReport {
        ssrc,
        ntp_secs: ntp_s,
        ntp_frac: ntp_f,
        rtp_ts,
        packet_count: packets,
        byte_count: bytes,
        reports: Vec::new(),
    };
    let sdes = SdesChunk {
        ssrc,
        items: vec![SdesItem {
            typ: SDES_CNAME,
            text: cname.to_string(),
        }],
    };
    encode_compound(&[RtcpPacket::SR(sr), RtcpPacket::SDES(vec![sdes])])
}

/// Construye un paquete RTCP BYE con un motivo opcional.
pub fn build_bye(ssrc: u32, reason: Option<&str>) -> Vec<u8> {
    let bye = Bye {
        ssrcs: vec![ssrc],
        reason: reason.map(|r| r.to_string()),
    };
    encode_compound(&[RtcpPacket::BYE(bye)])
}

/// Construye un paquete RTCP PLI
pub fn build_pli(sender_ssrc: u32, media_ssrc: u32) -> Vec<u8> {
    let pli = PictureLossIndication {
        sender_ssrc,
        media_ssrc,
    };
    encode_compound(&[RtcpPacket::PLI(pli)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtcp_header_to_from_bytes_roundtrip() {
        let header = RtcpHeader {
            version: RTCP_VERSION,
            padding: true,
            count: 2,
            pt: PT_SR,
            length: 1,
        };
        let mut packet = header.to_bytes().to_vec();
        packet.extend_from_slice(&[0u8; 4]);

        let (parsed, consumed) = RtcpHeader::from_bytes(&packet).expect("header expected");
        assert_eq!(parsed.version, header.version);
        assert_eq!(parsed.padding, header.padding);
        assert_eq!(parsed.count, header.count);
        assert_eq!(parsed.pt, header.pt);
        assert_eq!(parsed.length, header.length);
        assert_eq!(consumed, packet.len());
    }

    #[test]
    fn report_block_serializes_expected_bytes() {
        let block = ReportBlock {
            ssrc: 0x1122_3344,
            fraction_lost: 0x55,
            cumulative_lost: 0x0123_4567,
            ext_highest_seq: 0x89AB_CDEF,
            jitter: 0x1234_5678,
            lsr: 0x9ABC_DEF0,
            dlsr: 0x1234_5678,
        };

        let bytes = block.as_bytes_from_ref();
        assert_eq!(bytes.len(), 24);
        assert_eq!(
            bytes,
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x12, 0x34,
                0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78,
            ]
        );
    }

    #[test]
    fn middle_ntp32_extracts_expected_bits() {
        let value = middle_ntp32(0x1234_5678, 0x9ABC_DEF0);
        assert_eq!(value, 0x5678_9ABC);
    }

    #[test]
    fn is_rtcp_validates_basic_header() {
        let header = RtcpHeader {
            version: RTCP_VERSION,
            padding: false,
            count: 0,
            pt: PT_RR,
            length: 0,
        };
        let packet = header.to_bytes();
        assert!(is_rtcp(&packet));

        let mut invalid = packet;
        invalid[0] = 0; // version inválida
        assert!(!is_rtcp(&invalid));
    }

    #[test]
    fn encode_decode_roundtrip_for_sender_report() {
        let report = ReportBlock {
            ssrc: 0x0000_0001,
            fraction_lost: 0x01,
            cumulative_lost: 0x0001_0203,
            ext_highest_seq: 0x0004_0506,
            jitter: 0x0007_0809,
            lsr: 0x000A_0B0C,
            dlsr: 0x000D_0E0F,
        };
        let sr = SenderReport {
            ssrc: 0xFFEEDDCC,
            ntp_secs: 1,
            ntp_frac: 2,
            rtp_ts: 3,
            packet_count: 4,
            byte_count: 5,
            reports: vec![report],
        };

        let encoded = encode_compound(&[RtcpPacket::SR(sr.clone())]);
        let decoded = decode_compound(&encoded);

        assert_eq!(decoded.len(), 1);
        match &decoded[0] {
            RtcpPacket::SR(parsed) => {
                assert_eq!(parsed.ssrc, sr.ssrc);
                assert_eq!(parsed.ntp_secs, sr.ntp_secs);
                assert_eq!(parsed.ntp_frac, sr.ntp_frac);
                assert_eq!(parsed.rtp_ts, sr.rtp_ts);
                assert_eq!(parsed.packet_count, sr.packet_count);
                assert_eq!(parsed.byte_count, sr.byte_count);
                assert_eq!(parsed.reports.len(), 1);
                assert_eq!(parsed.reports[0].ssrc, report.ssrc);
                assert_eq!(parsed.reports[0].fraction_lost, report.fraction_lost);
                assert_eq!(
                    parsed.reports[0].cumulative_lost,
                    report.cumulative_lost & 0x00FF_FFFF
                );
            }
            other => panic!("Unexpected packet: {:?}", other),
        }
    }
}
