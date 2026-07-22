//! Estructura de la cabecera RTP y funciones de serializacion/deserializacion.

/// Estructura que representa la cabecera RTP.
#[derive(Debug)]
pub struct RtpHeader {
    pub version: u8,
    pub padding: bool,
    pub extension: bool,
    pub csrc_count: u8,
    pub marker: bool,
    pub payload_type: u8,
    pub seq: u16,
    pub timestamp: u32,
    pub ssrc: u32,
}

/// Parametros para crear una cabecera RTP.
pub struct RtpParams {
    pub version: u8,
    pub padding: bool,
    pub extension: bool,
    pub csrc_count: u8,
}
/// Implementacion de metodos para la estructura RtpHeader.
impl RtpHeader {
    /// Crea una nueva instancia de RtpHeader con los valores proporcionados.
    pub fn new(
        params: RtpParams,
        marker: bool,
        payload_type: u8,
        seq: u16,
        timestamp: u32,
        ssrc: u32,
    ) -> Self {
        RtpHeader {
            version: params.version,       // rtp version, always 2
            padding: params.padding,       // padding flag
            extension: params.extension,   // extension flag
            csrc_count: params.csrc_count, // number of CSRCs
            marker,                        // marker bit -> true for the last packet of a frame
            payload_type,                  // payload type (26 for JPEG)
            seq,                           // sequence number
            timestamp,
            ssrc,
        }
    }

    /// Serializa la cabecera RTP en un arreglo de bytes.
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0] = (self.version << 6)
            | ((self.padding as u8) << 5)
            | ((self.extension as u8) << 4)
            | (self.csrc_count & 0x0F);
        buf[1] = ((self.marker as u8) << 7) | (self.payload_type & 0x7F);
        buf[2..4].copy_from_slice(&self.seq.to_be_bytes());
        buf[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ssrc.to_be_bytes());
        buf
    }

    /// Deserializa un arreglo de bytes en una instancia de RtpHeader.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < 12 {
            return Err("Buffer too small to contain RTP header".to_string());
        }
        let version = buf[0] >> 6;
        let padding = (buf[0] & 0x20) != 0;
        let extension = (buf[0] & 0x10) != 0;
        let csrc_count = buf[0] & 0x0F;
        let marker = (buf[1] & 0x80) != 0;
        let payload_type = buf[1] & 0x7F;
        let seq = u16::from_be_bytes([buf[2], buf[3]]);
        let timestamp = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let ssrc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        Ok(Self {
            version,
            padding,
            extension,
            csrc_count,
            marker,
            payload_type,
            seq,
            timestamp,
            ssrc,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_params() -> RtpParams {
        RtpParams {
            version: 2,
            padding: false,
            extension: true,
            csrc_count: 3,
        }
    }

    #[test]
    fn rtp_header_to_bytes_matches_expected_layout() {
        let header = RtpHeader::new(build_params(), true, 96, u16::MAX, 0x1122_3344, 0x5566_7788);

        let bytes = header.to_bytes();
        assert_eq!(
            bytes,
            [
                0x93, 0xE0, 0xFF, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ]
        );
    }

    #[test]
    fn rtp_header_roundtrip_from_bytes() {
        let header = RtpHeader::new(build_params(), false, 120, 0x3456, 0x0102_0304, 0x0A0B_0C0D);
        let bytes = header.to_bytes();
        let parsed = RtpHeader::from_bytes(&bytes).expect("valid RTP header");

        assert_eq!(parsed.version, header.version);
        assert_eq!(parsed.padding, header.padding);
        assert_eq!(parsed.extension, header.extension);
        assert_eq!(parsed.csrc_count, header.csrc_count);
        assert_eq!(parsed.marker, header.marker);
        assert_eq!(parsed.payload_type, header.payload_type);
        assert_eq!(parsed.seq, header.seq);
        assert_eq!(parsed.timestamp, header.timestamp);
        assert_eq!(parsed.ssrc, header.ssrc);
    }

    #[test]
    fn from_bytes_rejects_short_buffer() {
        let err = RtpHeader::from_bytes(&[0x80, 0x20]).unwrap_err();
        assert!(err.contains("Buffer too small"));
    }
}
