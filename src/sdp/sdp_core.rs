//! Estructura y metodos principales de SDP.

use crate::config::SdpConfig;

/// Estructura principal para la generacion de SDP.
pub struct Sdp<'a> {
    // Session fields
    username: &'a str,
    session_id: u64,
    session_version: u64,
    nettype: &'a str,
    addrtype: &'a str,
    //unicast_address: &'a str,

    // Media fields
    media_types: Vec<&'a str>,
    //ports: Vec<u16>,
    protocols: Vec<&'a str>,
    codecs: Vec<Vec<&'a str>>,
    rtpmaps: Vec<Vec<&'a str>>,
    fmtps: Vec<Vec<&'a str>>,
}

/// Implementacion de metodos para la estructura SDP.
impl<'a> Sdp<'a> {
    /// Metodo para crear una nueva instancia de SDP con valores predefinidos.
    /// Metodo para crear una nueva instancia de SDP con valores predefinidos.
    pub fn new(config: &'a SdpConfig) -> Self {
        let audio_codecs: Vec<&str> = config.audio_codecs.iter().map(|s| s.as_str()).collect();
        let video_codecs: Vec<&str> = config.video_codecs.iter().map(|s| s.as_str()).collect();
        let audio_rtpmap: Vec<&str> = config.audio_rtpmap.iter().map(|s| s.as_str()).collect();
        let video_rtpmap: Vec<&str> = config.video_rtpmap.iter().map(|s| s.as_str()).collect();
        let audio_fmtp: Vec<&str> = config.audio_fmtp.iter().map(|s| s.as_str()).collect();
        let video_fmtp: Vec<&str> = config.video_fmtp.iter().map(|s| s.as_str()).collect();

        Sdp {
            username: &config.username,
            session_id: config.session_id,
            session_version: config.session_version,
            nettype: &config.nettype,
            addrtype: &config.addrtype,
            //unicast_address: UNICAST_ADDRESS,
            media_types: vec![&config.audio_type, &config.video_type],
            //ports: vec![AUDIO_PORT, VIDEO_PORT],
            protocols: vec![&config.audio_protocol, &config.video_protocol],
            codecs: vec![audio_codecs, video_codecs],
            rtpmaps: vec![audio_rtpmap, video_rtpmap],
            fmtps: vec![audio_fmtp, video_fmtp],
        }
    }

    /// Parámetros para construir una sesión SDP.
    pub fn build_sdp_with_ice(&self, params: SdpSessionParams) -> Result<String, String> {
        let mut sdp = String::new();
        sdp.push_str("v=0\r\n");
        sdp.push_str(&format!(
            "o={} {} {} {} {} {}\r\n",
            self.username,
            self.session_id,
            self.session_version,
            self.nettype,
            self.addrtype,
            params.ip_str
        ));
        sdp.push_str("s=-\r\n");
        sdp.push_str(&format!(
            "c={} {} {}\r\n",
            self.nettype, self.addrtype, params.ip_str
        ));
        sdp.push_str("t=0 0\r\n");
        sdp.push_str(&format!("a=ice-ufrag:{}\r\n", params.ufrag));
        sdp.push_str(&format!("a=ice-pwd:{}\r\n", params.pwd));
        if params.is_lite {
            sdp.push_str("a=ice-lite\r\n");
        }

        // Agrega fingerprint y configuración a nivel de sesión (una vez, no por sección de medios)
        if let Some(fp) = params.fingerprint {
            sdp.push_str(&format!("a=fingerprint:{}\r\n", fp));
        }
        if let Some(s) = params.setup {
            sdp.push_str(&format!("a=setup:{}\r\n", s));
        }

        // let ports = [audio_port, video_port]; // We use ports slice passed in arguments
        for (i, media_type) in self.media_types.iter().enumerate() {
            let port = if i < params.ports.len() {
                params.ports[i]
            } else {
                0
            };
            let protocol = &self.protocols[i];
            let codecs = &self.codecs[i];
            let rtpmaps = &self.rtpmaps[i];
            let fmtps = &self.fmtps[i];

            sdp.push_str(&format!(
                "m={} {} {} {}\r\n",
                media_type,
                port,
                protocol,
                codecs.join(" ")
            ));

            for (rtp, fmtp) in rtpmaps.iter().zip(fmtps.iter()) {
                if !rtp.is_empty() {
                    sdp.push_str(&format!("a=rtpmap:{}\r\n", rtp));
                }
                if !fmtp.is_empty() {
                    sdp.push_str(&format!("a=fmtp:{}\r\n", fmtp));
                }
            }

            // Filtrar y agregar candidatos relevantes para este puerto
            for c in params.candidates {
                // Un candidato es relevante si su puerto base (host) coincide con el puerto del media
                // Para host: c.port == port
                // Para srflx: c.rel_port == port
                let is_relevant = if c.typ == "srflx" {
                    c.rel_port == Some(port)
                } else {
                    c.port == port
                };

                if is_relevant {
                    let mut line = format!(
                        "a=candidate:{} {} {} {} {} {} typ {}",
                        c.foundation, c.component_id, c.transport, c.priority, c.ip, c.port, c.typ
                    );
                    if let (Some(raddr), Some(rport)) = (c.rel_addr, c.rel_port) {
                        line.push_str(&format!(" raddr {} rport {}", raddr, rport));
                    }
                    line.push_str("\r\n");
                    sdp.push_str(&line);
                }
            }

            sdp.push_str("a=rtcp-mux\r\n");
            sdp.push_str(&format!("a=mid:{}\r\n", i));
        }

        Ok(sdp)
    }
}

/// Parámetros para la construcción de SDP.
pub struct SdpSessionParams<'a> {
    pub ufrag: &'a str,
    pub pwd: &'a str,
    pub ip_str: &'a str,
    pub ports: &'a [u16],
    pub candidates: &'a [crate::protocols::ice::IceCandidate],
    pub is_lite: bool,
    pub fingerprint: Option<&'a str>,
    pub setup: Option<&'a str>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_sample_sdp(is_lite: bool) -> String {
        let config = SdpConfig::default();
        Sdp::new(&config)
            .build_sdp_with_ice(SdpSessionParams {
                ufrag: "localufrag",
                pwd: "localpwd",
                ip_str: "192.168.0.1",
                ports: &[4000, 5000],
                candidates: &[],
                is_lite,
                fingerprint: None,
                setup: None,
            })
            .expect("SDP válido")
    }

    #[test]
    fn sdp_builder_includes_core_lines() {
        let sdp = build_sample_sdp(false);

        assert!(sdp.contains("v=0\r\n"));
        assert!(sdp.contains("a=ice-ufrag:localufrag\r\n"));
        assert!(sdp.contains("a=ice-pwd:localpwd\r\n"));
        assert!(sdp.contains("m=audio 4000 RTP/AVP"));
        assert!(sdp.contains("m=video 5000 RTP/AVP"));
        assert!(sdp.contains("a=mid:0\r\n"));
        assert!(sdp.contains("a=mid:1\r\n"));
        assert!(!sdp.contains("a=ice-lite\r\n"));
    }

    #[test]
    fn sdp_builder_adds_ice_lite_when_requested() {
        let sdp = build_sample_sdp(true);
        assert!(sdp.contains("a=ice-lite\r\n"));
    }
}
