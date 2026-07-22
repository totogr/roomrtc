//! Utilidades para la generacion y manipulacion de SDP.

use crate::config::SdpConfig;
use crate::protocols::ice::IceAgent;
use crate::sdp::sdp_core::*;
use crate::utils;

/// Parsea el SDP remoto para extraer la IP, puerto del candidato de video y fingerprint DTLS.
/// Retorna: (ip, puerto, fingerprint)
pub fn parse_remote_sdp(sdp: &str) -> Option<(String, u16, Option<String>)> {
    let lines: Vec<&str> = sdp.lines().collect();
    let mut in_video_section = false;
    let mut ip_port: Option<(String, u16)> = None;
    let mut fingerprint: Option<String> = None;

    for line in lines {
        if line.starts_with("a=fingerprint:") && fingerprint.is_none() {
            fingerprint = line.strip_prefix("a=fingerprint:").map(|s| s.to_string());
        }

        if line.starts_with("m=video") {
            in_video_section = true;
            continue;
        }

        if line.starts_with("m=") && !line.starts_with("m=video") {
            in_video_section = false;
        }

        if in_video_section && line.starts_with("a=candidate:") && ip_port.is_none() {
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() >= 6 {
                let ip = parts[4].to_string();
                if let Ok(port) = parts[5].parse::<u16>() {
                    ip_port = Some((ip, port));
                }
            }
        }
    }

    ip_port.map(|(ip, port)| (ip, port, fingerprint))
}

/// Genera un SDP local con las credenciales y puertos especificados.
pub fn generar_sdp_local(
    agent: &IceAgent,
    ip_str: &str,
    audio_port: u16,
    video_port: u16,
    fingerprint: &str,
    config: &SdpConfig,
) -> Result<String, String> {
    let sdp_text = Sdp::new(config)
        .build_sdp_with_ice(SdpSessionParams {
            ufrag: &agent.credentials.ufrag,
            pwd: &agent.credentials.pwd,
            ip_str,
            ports: &[audio_port, video_port],
            candidates: &agent.local_candidates,
            is_lite: false,
            fingerprint: Some(fingerprint),
            setup: Some("actpass"),
        })
        .map_err(|e| format!("Error construyendo SDP: {}", e))?;

    Ok(sdp_text)
}

/// Genera un SDP Answer basado en el SDP remoto y las credenciales y puertos locales.
pub fn generar_sdp_answer(
    remote_sdp: &str,
    agent: &mut IceAgent,
    ip_str: &str,
    audio_port: u16,
    video_port: u16,
    fingerprint: &str,
    config: &SdpConfig,
) -> Result<String, String> {
    // Setear credenciales remotas desde SDP para validar STUN
    let parsed = utils::parse_sdp_ice(remote_sdp);
    let (Some(ru), Some(rp)) = (parsed.ice_ufrag.clone(), parsed.ice_pwd.clone()) else {
        return Err("No se encontraron credenciales ICE en el SDP remoto".to_string());
    };
    agent.set_remote_credentials(ru, rp);
    let sdp_text = Sdp::new(config)
        .build_sdp_with_ice(SdpSessionParams {
            ufrag: &agent.credentials.ufrag,
            pwd: &agent.credentials.pwd,
            ip_str,
            ports: &[audio_port, video_port],
            candidates: &agent.local_candidates,
            is_lite: true, // Answer ice-lite, solo responde binding request
            fingerprint: Some(fingerprint),
            setup: Some("passive"),
        })
        .map_err(|e| format!("Error construyendo SDP Answer: {}", e))?;

    Ok(sdp_text)
}

/// Determina el rol DTLS basándose en el atributo a=setup del SDP local.
/// Retorna Client si es actpass (iniciador), Server si es passive (responder).
pub fn get_dtls_role(sdp: &str) -> crate::protocols::dtls::DtlsRole {
    for line in sdp.lines() {
        if line.contains("a=setup:") {
            if line.contains("actpass") {
                return crate::protocols::dtls::DtlsRole::Client;
            } else if line.contains("passive") {
                return crate::protocols::dtls::DtlsRole::Server;
            }
        }
    }
    crate::protocols::dtls::DtlsRole::Client
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::ice::IceAgent;

    fn sample_agent() -> IceAgent {
        IceAgent::new("locufrag".to_string(), "locpwd".to_string(), true)
    }

    #[test]
    fn generar_sdp_local_includes_credentials_and_ports() {
        let agent = sample_agent();
        let config = SdpConfig::default();
        let sdp = generar_sdp_local(&agent, "198.168.0.1", 50, 52, "sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00", &config).expect("SDP local válido");

        assert!(sdp.contains("a=ice-ufrag:locufrag"));
        assert!(sdp.contains("a=ice-pwd:locpwd"));
        assert!(sdp.contains("m=audio 50"));
        assert!(sdp.contains("m=video 52"));
    }

    #[test]
    fn generar_sdp_answer_usa_credenciales_remotas() {
        let remote_sdp = "v=0\n\
o=- 0 0 IN IP4 192.168.0.1\n\
s=-\n\
a=ice-ufrag:rem123\n\
a=ice-pwd:rempwd456789012345678\n\
a=candidate:1 1 udp 19216801 192.168.0.1 9000 typ host";
        let mut agent = sample_agent();

        let result = generar_sdp_answer(
            &remote_sdp.replace('\n', "\r\n"),
            &mut agent,
            "192.168.0.1",
            60,
            70,
            "sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
            &SdpConfig::default(),
        )
        .expect("SDP answer válido");

        let remote = agent
            .remote_credentials
            .as_ref()
            .expect("Credenciales remotas set");
        assert_eq!(remote.ufrag, "rem123");
        assert_eq!(remote.pwd, "rempwd456789012345678");
        assert!(result.contains("a=ice-lite"));
        assert!(result.contains("m=video 70"));
    }
}
