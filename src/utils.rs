//! Funciones de utilidad para el manejo de SDP y redes.

use crate::protocols::ice::IceCandidate;
use if_addrs::get_if_addrs;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::str::FromStr;

/// Parsea un texto SDP para extraer ICE ufrag, pwd y candidatos.
pub fn parse_sdp_ice(text: &str) -> ParsedSdp {
    let mut result = ParsedSdp::default();

    // Procesar línea por línea el texto SDP proporcionado
    for line in text.lines() {
        let line = line.trim();
        if let Some(suffix) = line.strip_prefix("a=ice-ufrag:") {
            result.ice_ufrag = Some(suffix.trim().to_string());
        } else if let Some(suffix) = line.strip_prefix("a=ice-pwd:") {
            result.ice_pwd = Some(suffix.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("a=candidate:") {
            // Analisis minimo: foundation component_id transport priority ip port typ ...
            let mut toks = rest.split_whitespace();
            let foundation = match toks.next() {
                Some(s) => s.to_string(),
                None => continue,
            };
            let component_id = match toks.next().and_then(|s| s.parse::<u32>().ok()) {
                Some(v) => v,
                None => continue,
            };
            let transport = match toks.next() {
                Some(s) => s.to_uppercase(),
                None => continue,
            };
            let priority = match toks.next().and_then(|s| s.parse::<u32>().ok()) {
                Some(v) => v,
                None => continue,
            };
            let ip_str = match toks.next() {
                Some(s) => s,
                None => continue,
            };
            let port = match toks.next().and_then(|s| s.parse::<u16>().ok()) {
                Some(v) => v,
                None => continue,
            };

            // Se espera el valor "typ" y su valor a continuación
            let _typ_kw = toks.next();
            let typ_val = toks.next().unwrap_or("").to_lowercase();

            if transport != "UDP" {
                continue;
            }
            let ip = match IpAddr::from_str(ip_str) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Construir el candidato ICE y agregarlo a la lista
            let candidate = IceCandidate {
                foundation,
                component_id,
                priority,
                transport: transport.to_string(),
                ip,
                port,
                typ: typ_val,
                rel_addr: None,
                rel_port: None,
                local_preference: 0,
            };
            result.candidates.push(candidate);
        }
    }

    result
}

/// Estructura para almacenar la información parseada del SDP.
#[derive(Default)]
pub struct ParsedSdp {
    pub ice_ufrag: Option<String>,
    pub ice_pwd: Option<String>,
    pub candidates: Vec<IceCandidate>,
}

/// Detecta la dirección IPv4 local válida.
pub fn detect_local_ipv4() -> Result<IpAddr, String> {
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0")
        && sock.connect("8.8.8.8:53").is_ok()
        && let Ok(local_addr) = sock.local_addr()
        && let IpAddr::V4(ipv4) = local_addr.ip()
        && !ipv4.is_unspecified()
        && !ipv4.is_loopback()
    {
        return Ok(IpAddr::V4(ipv4));
    }

    Err("No se pudo detectar una IPv4 local válida".to_string())
}

/// Lista todas las direcciones IPv4 locales válidas.
pub fn list_local_ipv4_addrs() -> Vec<IpAddr> {
    let mut addrs = Vec::new();
    if let Ok(ifaces) = get_if_addrs() {
        for iface in ifaces {
            if let IpAddr::V4(ipv4) = iface.ip() {
                if ipv4.is_loopback() || ipv4.is_unspecified() {
                    continue;
                }
                if addrs.contains(&IpAddr::V4(ipv4)) {
                    continue;
                }
                addrs.push(IpAddr::V4(ipv4));
            }
        }
    }
    addrs
}

/// Asigna un puerto UDP disponible en la IP dada.
pub fn allocate_udp_port(ip: IpAddr) -> Result<u16, String> {
    let addr = SocketAddr::new(ip, 0);
    let sock = UdpSocket::bind(addr).map_err(|e| format!("Bind UDP falló: {}", e))?;
    let local = sock
        .local_addr()
        .map_err(|e| format!("local_addr() falló: {}", e))?;
    Ok(local.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sdp_ice_extracts_credentials_and_udp_candidate() {
        let sdp = "v=0\n\
o=- 0 0 IN IP4 192.168.0.1\n\
s=-\n\
a=ice-ufrag:local123\n\
a=ice-pwd:pwd1234\n\
a=candidate:1 1 udp 2130706431 192.168.0.1 3456 typ host\n\
a=candidate:2 1 tcp 1 10.0.0.1 9 typ host";

        let parsed = parse_sdp_ice(sdp);

        assert_eq!(parsed.ice_ufrag.as_deref(), Some("local123"));
        assert_eq!(parsed.ice_pwd.as_deref(), Some("pwd1234"));
        assert_eq!(parsed.candidates.len(), 1);

        let candidate = &parsed.candidates[0];
        assert_eq!(candidate.transport, "UDP");
        assert_eq!(candidate.ip.to_string(), "192.168.0.1");
        assert_eq!(candidate.port, 3456);
        assert_eq!(candidate.typ, "host");
    }

    #[test]
    fn parse_sdp_ice_ignores_invalid_candidates() {
        let sdp = "a=candidate:1 1 udp 1 not_an_ip 9999 typ host";
        let parsed = parse_sdp_ice(sdp);

        assert!(parsed.ice_ufrag.is_none());
        assert!(parsed.ice_pwd.is_none());
        assert!(parsed.candidates.is_empty());
    }
}
