//! Módulo ICE (Interactive Connectivity Establishment) para establecimiento de conectividad P2P.

use crate::utils::list_local_ipv4_addrs;
use rand::distr::Alphanumeric;
use rand::{Rng, rng};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::str;
use std::time::{Duration, Instant};

pub const STUN_COOKIE: u32 = 0x2112A442;
const TIMEOUT_MS: u64 = 100;

/// Credenciales ICE para la autenticación entre agentes.
#[derive(Debug)]
pub struct IceCredentials {
    pub ufrag: String,
    pub pwd: String,
}

/// Representacion de un candidato ICE.
#[derive(Debug, Clone)]
pub struct IceCandidate {
    pub foundation: String,
    pub component_id: u32, // 1 for RTP (or rtcp-mux), 2 for RTCP
    pub priority: u32,
    pub transport: String,
    pub ip: IpAddr,
    pub port: u16,
    pub typ: String, // host -> LAN; srflx -> IP obtained from STUN; relay -> TURN
    pub rel_addr: Option<IpAddr>,
    pub rel_port: Option<u16>,
    pub local_preference: u32,
}

/// Parámetros para la creación de un candidato ICE.
pub struct IceCandidateParams<'a> {
    pub foundation: String,
    pub component_id: u32,
    pub transport: &'a str,
    pub ip: IpAddr,
    pub port: u16,
    pub typ: &'a str,
    pub local_preference: u32,
    pub rel_addr: Option<IpAddr>,
    pub rel_port: Option<u16>,
}

/// Implementación de métodos para IceCandidate.
impl IceCandidate {
    /// Crea un nuevo candidato ICE con los parámetros dados.
    pub fn new(params: IceCandidateParams) -> Self {
        let priority =
            compute_candidate_priority(params.typ, params.component_id, params.local_preference);
        IceCandidate {
            foundation: params.foundation,
            component_id: params.component_id,
            priority,
            transport: params.transport.to_uppercase(),
            ip: params.ip,
            port: params.port,
            typ: params.typ.to_string(),
            rel_addr: params.rel_addr,
            rel_port: params.rel_port,
            local_preference: params.local_preference,
        }
    }

    /// Crea un candidato ICE de tipo host.
    pub fn host_candidate(
        foundation: String,
        component_id: u32,
        ip: IpAddr,
        port: u16,
        local_preference: u32,
    ) -> Self {
        IceCandidate::new(IceCandidateParams {
            foundation,
            component_id,
            transport: "UDP",
            ip,
            port,
            typ: "host",
            local_preference,
            rel_addr: None,
            rel_port: None,
        })
    }
}

/// Calcula la prioridad de un candidato ICE basado en su tipo, ID de componente y preferencia local.
pub fn compute_candidate_priority(typ: &str, component_id: u32, local_pref: u32) -> u32 {
    let type_pref = candidate_type_preference(typ);
    let comp = component_id.clamp(1, 256);
    (type_pref << 24) + (local_pref << 8) + (256 - comp)
}

/// Calcula la prioridad de un par de candidatos ICE basado en si el agente es controlador.
pub fn compute_pair_priority(controlling: bool, local_prio: u32, remote_prio: u32) -> u64 {
    if controlling {
        ((local_prio as u64) << 32) + (remote_prio as u64)
    } else {
        ((remote_prio as u64) << 32) + (local_prio as u64)
    }
}

/// Retorna la preferencia de tipo de candidato ICE.
fn candidate_type_preference(typ: &str) -> u32 {
    match typ {
        "host" => 126,
        "srflx" => 100,
        "prflx" => 110,
        "relay" => 0,
        _ => 90,
    }
}

/// Agente ICE que maneja la recolección de candidatos, credenciales y chequeos de conectividad.
pub struct IceAgent {
    pub credentials: IceCredentials,
    pub local_candidates: Vec<IceCandidate>,
    pub remote_candidates: Vec<IceCandidate>,
    pub controlling: bool,
    pub selected_candidates: Option<(IceCandidate, IceCandidate)>,
    pub local_sockets: HashMap<(IpAddr, u16), UdpSocket>,
    pub remote_credentials: Option<IceCredentials>,
    foundation_counter: u32,
}

/// Par de candidatos ICE (local y remoto) con su prioridad calculada.
#[derive(Debug, Clone)]
pub struct CandidatePair {
    pub local: IceCandidate,
    pub remote: IceCandidate,
    pub priority: u64,
}

/// Implementación de métodos para el agente ICE.
impl IceAgent {
    /// Crea un nuevo agente ICE con las credenciales dadas.
    pub fn new(ufrag: String, pwd: String, controlling: bool) -> Self {
        IceAgent {
            credentials: IceCredentials { ufrag, pwd },
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            controlling,
            selected_candidates: None,
            local_sockets: HashMap::new(),
            remote_credentials: None,
            foundation_counter: 0,
        }
    }

    /// Genera credenciales ICE aleatorias (ufrag, pwd)
    pub fn generate_credentials() -> IceCredentials {
        let ufrag: String = rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect();
        let pwd: String = rng()
            .sample_iter(&Alphanumeric)
            .take(24)
            .map(char::from)
            .collect();
        IceCredentials { ufrag, pwd }
    }

    /// Crea un nuevo agente ICE con nuevas credenciales y agrega candidatos host para los puertos dados.
    pub fn new_with_host_candidates(ip: IpAddr, ports: &[u16], controlling: bool) -> Self {
        let creds = Self::generate_credentials();
        let mut agent = IceAgent::new(creds.ufrag, creds.pwd, controlling);
        let mut cand_index = 0;
        let mut addrs = list_local_ipv4_addrs();
        if !addrs.contains(&ip) {
            addrs.push(ip);
        }
        if addrs.is_empty() {
            addrs.push(ip);
        }
        for addr in addrs {
            for &p in ports {
                match UdpSocket::bind((addr, p)) {
                    Ok(sock) => {
                        let foundation = agent.next_foundation("host");
                        let local_pref = IceAgent::local_preference_for_index(cand_index);
                        let c = Self::gather_host_candidate(foundation, addr, p, local_pref);
                        cand_index = cand_index.saturating_add(1);
                        let _ = sock.set_read_timeout(Some(Duration::from_millis(TIMEOUT_MS)));
                        agent.local_sockets.insert((addr, p), sock);
                        agent.add_local_candidate(c);
                    }
                    Err(_) => {
                        continue;
                    }
                }
            }
        }
        agent
    }

    /// Establece las credenciales remotas para el agente ICE.
    pub fn set_remote_credentials(&mut self, ufrag: String, pwd: String) {
        self.remote_credentials = Some(IceCredentials { ufrag, pwd });
    }

    /// Reinicia el agente ICE para una nueva conexión (limpia candidatos y credenciales remotas)
    pub fn reset_for_new_connection(&mut self) {
        self.remote_candidates.clear();
        self.remote_credentials = None;
        self.selected_candidates = None;
    }

    /// Recolecta un candidato host para la IP y puerto dados.
    pub fn gather_host_candidate(
        foundation: String,
        ip: IpAddr,
        port: u16,
        local_preference: u32,
    ) -> IceCandidate {
        IceCandidate::host_candidate(foundation, 1, ip, port, local_preference)
    }

    /// Recolecta candidatos server-reflexive usando un servidor STUN.
    pub fn gather_srflx_candidates(&mut self, stun_server: SocketAddr) -> Vec<String> {
        let mut logs = Vec::new();
        let keys: Vec<(IpAddr, u16)> = self.local_sockets.keys().cloned().collect();
        let mut new_candidates = Vec::new();

        for (local_ip, local_port) in keys {
            if let Some(sock) = self.local_sockets.get(&(local_ip, local_port)) {
                let mut txid = [0u8; 12];
                rng().fill(&mut txid);
                let req = build_stun_binding_request(&txid, None);

                // Enviar Binding Request al servidor STUN
                if let Err(e) = sock.send_to(&req, stun_server) {
                    logs.push(format!("Error enviando STUN a {}: {}", stun_server, e));
                    continue;
                }

                let mut buf = [0u8; 1500];
                let start = Instant::now();
                let timeout = Duration::from_millis(TIMEOUT_MS); // Esperar hasta TIMEOUT_MS por respuesta

                loop {
                    if Instant::now() - start > timeout {
                        logs.push(format!(
                            "Timeout esperando STUN response en {}:{}",
                            local_ip, local_port
                        ));
                        break;
                    }

                    // Usamos peek o recv con timeout corto si es posible, pero aquí el socket ya tiene timeout
                    // Asumimos que el socket tiene un read timeout configurado en new_with_host_candidates
                    match sock.recv_from(&mut buf) {
                        Ok((n, src)) => {
                            if src == stun_server
                                && let Some(mapped_addr) =
                                    parse_stun_success_response(&buf[..n], &txid)
                            {
                                logs.push(format!(
                                    "STUN éxito: {}:{} -> {}",
                                    local_ip, local_port, mapped_addr
                                ));

                                // Crear candidato srflx
                                let foundation = self.next_foundation("srflx");
                                // Prioridad srflx suele ser menor que host pero mayor que relay
                                // Usamos la misma local_preference base para mantener coherencia
                                // En realidad deberíamos buscar el candidato host correspondiente para obtener su local_pref
                                // Por simplicidad, calculamos una basada en el puerto o similar, o buscamos el host.

                                // Buscamos el host candidate para copiar su local_pref
                                let local_pref = self
                                    .local_candidates
                                    .iter()
                                    .find(|c| {
                                        c.ip == local_ip && c.port == local_port && c.typ == "host"
                                    })
                                    .map(|c| c.local_preference)
                                    .unwrap_or(65535);

                                let c = IceCandidate::new(IceCandidateParams {
                                    foundation,
                                    component_id: 1, // component 1 (RTP)
                                    transport: "UDP",
                                    ip: mapped_addr.ip(),
                                    port: mapped_addr.port(),
                                    typ: "srflx",
                                    local_preference: local_pref,
                                    rel_addr: Some(local_ip),
                                    rel_port: Some(local_port),
                                });
                                new_candidates.push(c);
                                break; // Éxito, salir del loop de recepción
                            }
                        }
                        Err(_) => {
                            // Timeout o error de lectura, seguir intentando hasta timeout total
                            continue;
                        }
                    }
                }
            }
        }

        for c in new_candidates {
            self.add_local_candidate(c);
        }

        logs
    }

    /// Agrega un candidato local al agente ICE.
    pub fn add_local_candidate(&mut self, candidate: IceCandidate) {
        self.local_candidates.push(candidate);
    }

    /// Agrega un candidato remoto al agente ICE.
    pub fn add_remote_candidate(&mut self, candidate: IceCandidate) {
        self.remote_candidates.push(candidate);
    }

    /// Reemplaza la lista de candidatos remotos del agente ICE.
    pub fn replace_remote_candidates(&mut self, candidates: Vec<IceCandidate>) {
        self.remote_candidates = candidates;
    }

    /// Genera todos los pares de candidatos posibles entre locales y remotos, ordenados por prioridad.
    pub fn candidate_pairs(&self) -> Vec<CandidatePair> {
        let mut pairs = Vec::new();
        for local in &self.local_candidates {
            for remote in &self.remote_candidates {
                if local.component_id != remote.component_id {
                    continue;
                }
                let priority =
                    compute_pair_priority(self.controlling, local.priority, remote.priority);
                pairs.push(CandidatePair {
                    local: local.clone(),
                    remote: remote.clone(),
                    priority,
                });
            }
        }
        pairs.sort_by(|a, b| b.priority.cmp(&a.priority));
        pairs
    }

    /// Ejecuta check de conectividad: Binding Request -> Success Response
    pub fn connectivity_check(
        &mut self,
        local: &IceCandidate,
        remote: &IceCandidate,
    ) -> Result<bool, std::io::Error> {
        let key = (local.ip, local.port);
        let sock = self
            .local_sockets
            .get(&key)
            .and_then(|s| s.try_clone().ok())
            .ok_or_else(|| std::io::Error::other("sin socket local"))?;
        let remote_sa = SocketAddr::new(remote.ip, remote.port);

        let mut txid = [0u8; 12];
        rng().fill(&mut txid);

        // USERNAME debe ser "local_ufrag:remote_ufrag"
        let username = self
            .remote_credentials
            .as_ref()
            .map(|rc| format!("{}:{}", self.credentials.ufrag, rc.ufrag));
        let req = build_stun_binding_request(&txid, username.as_deref());

        let rto = Duration::from_millis(TIMEOUT_MS);
        let max_retx = 2;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut buf = [0u8; 1500];

        for _ in 0..max_retx {
            sock.send_to(&req, remote_sa)?;
            let start = Instant::now();
            while Instant::now() - start < rto {
                match sock.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        if let Some(req_in) = parse_stun_binding_request(&buf[..n]) {
                            let resp = build_stun_success_response(&req_in.txid, src);
                            let _ = sock.send_to(&resp, src);
                            continue;
                        }
                        if src == remote_sa
                            && parse_stun_success_response(&buf[..n], &txid).is_some()
                        {
                            let local_c = local.clone();
                            let remote_c = remote.clone();
                            self.selected_candidates = Some((local_c, remote_c));
                            return Ok(true);
                        }
                    }
                    Err(_e) => {
                        // timeout parcial; seguir intentando hasta rto
                    }
                }
                if Instant::now() > deadline {
                    break;
                }
            }
            if Instant::now() > deadline {
                break;
            }
        }
        Ok(false)
    }

    /// Obtiene un clon del socket asociado a un puerto local
    pub fn socket_for_port(&self, port: u16) -> Option<UdpSocket> {
        self.local_sockets
            .iter()
            .find(|((_, p), _)| *p == port)
            .and_then(|(_, s)| s.try_clone().ok())
    }

    /// Obtiene un clon del socket asociado a un candidato ICE
    pub fn socket_for_candidate(&self, candidate: &IceCandidate) -> Option<UdpSocket> {
        self.local_sockets
            .get(&(candidate.ip, candidate.port))
            .and_then(|s| s.try_clone().ok())
    }

    /// Genera el siguiente valor de foundation único.
    fn next_foundation(&mut self, prefix: &str) -> String {
        self.foundation_counter = self.foundation_counter.wrapping_add(1);
        format!("{}-{}", prefix, self.foundation_counter)
    }

    /// Calcula la preferencia local basada en el índice del candidato.
    fn local_preference_for_index(index: usize) -> u32 {
        const MAX_PREF: u32 = 65_535;
        MAX_PREF.saturating_sub(index as u32)
    }
}

/// Construye una solicitud STUN Binding con el ID de transacción y nombre de usuario opcional.
pub fn build_stun_binding_request(txid: &[u8; 12], username: Option<&str>) -> Vec<u8> {
    let mut attrs = Vec::new();

    if let Some(name) = username {
        let name_bytes = name.as_bytes();
        let padded_len = (name_bytes.len() + 3) & !3;
        attrs.extend_from_slice(&0x0006u16.to_be_bytes()); // USERNAME
        attrs.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        attrs.extend_from_slice(name_bytes);
        // padding a 32-bit boundary
        attrs.extend(std::iter::repeat_n(0, padded_len - name_bytes.len()));
    }

    let mut req = Vec::with_capacity(20 + attrs.len());
    req.extend_from_slice(&0x0001u16.to_be_bytes());
    req.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    req.extend_from_slice(&STUN_COOKIE.to_be_bytes());
    req.extend_from_slice(txid);
    req.extend_from_slice(&attrs);
    req
}

/// Parsea una solicitud STUN Binding
/// Estructura mínima de un STUN Binding Request parseado
pub struct StunBindingRequest {
    pub txid: [u8; 12],
    pub username: Option<String>,
}

/// Parsea STUN Binding Request y extrae TXID y USERNAME (si existe)
pub fn parse_stun_binding_request(buf: &[u8]) -> Option<StunBindingRequest> {
    if buf.len() < 20 {
        return None;
    }
    let typ = u16::from_be_bytes([buf[0], buf[1]]);
    if typ != 0x0001 {
        return None;
    }
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != STUN_COOKIE {
        return None;
    }
    if buf.len() < 20 + len {
        return None;
    }
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&buf[8..20]);

    let mut username: Option<String> = None;
    let mut off = 20;
    while off + 4 <= 20 + len {
        let at = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let al = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
        off += 4;
        if off + al > buf.len() {
            return None;
        }
        if at == 0x0006 {
            // USERNAME
            if let Ok(s) = str::from_utf8(&buf[off..off + al]) {
                username = Some(s.to_string());
            }
        }
        off += (al + 3) & !3; // padding 32-bit
    }

    Some(StunBindingRequest { txid, username })
}

/// Verifica si el buffer contiene un mensaje STUN válido
pub fn is_stun_message(buf: &[u8]) -> bool {
    if buf.len() < 20 {
        return false;
    }
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    cookie == STUN_COOKIE
}

/// Construye una respuesta STUN Binding Success con el ID de transacción y la dirección fuente dada.
pub fn build_stun_success_response(txid: &[u8; 12], src: SocketAddr) -> Vec<u8> {
    // Solo IPv4 soportado
    let (ip, port) = match src {
        SocketAddr::V4(v4) => (v4.ip().octets(), v4.port()),
        _ => return Vec::new(),
    };

    // Atributo XOR-MAPPED-ADDRESS (type=0x0020, length=8)
    let mut attr = Vec::with_capacity(12);
    // Type
    attr.extend_from_slice(&0x0020u16.to_be_bytes());
    // Length
    attr.extend_from_slice(&8u16.to_be_bytes());
    // Value: 0x00 | family=0x01 | x-port | x-address
    attr.push(0x00);
    attr.push(0x01); // IPv4
    let xport = port ^ ((STUN_COOKIE >> 16) as u16);
    attr.extend_from_slice(&xport.to_be_bytes());
    let cookie_bytes = STUN_COOKIE.to_be_bytes();
    for i in 0..4 {
        attr.push(ip[i] ^ cookie_bytes[i]);
    }

    // Header (20 bytes)
    let mut resp = Vec::with_capacity(32);
    resp.extend_from_slice(&0x0101u16.to_be_bytes()); // Success Response
    resp.extend_from_slice(&(attr.len() as u16).to_be_bytes());
    resp.extend_from_slice(&STUN_COOKIE.to_be_bytes());
    resp.extend_from_slice(txid);
    // Attrs
    resp.extend_from_slice(&attr);
    resp
}

/// Parsea una respuesta STUN Binding Success y extrae la dirección XOR-MAPPED-ADDRESS
pub fn parse_stun_success_response(buf: &[u8], expect_txid: &[u8; 12]) -> Option<SocketAddr> {
    if buf.len() < 20 {
        return None;
    }
    let typ = u16::from_be_bytes([buf[0], buf[1]]);
    if typ != 0x0101 {
        return None;
    }
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != STUN_COOKIE {
        return None;
    }
    if &buf[8..20] != expect_txid {
        return None;
    }
    if buf.len() < 20 + len {
        return None;
    }
    let mut off = 20;
    while off + 4 <= 20 + len {
        let at = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let al = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
        off += 4;
        if at == 0x0020 && al >= 8 {
            // XOR-MAPPED-ADDRESS
            if off + al > buf.len() {
                return None;
            }
            let family = buf[off + 1];
            if family != 0x01 {
                return None;
            }
            let xport = u16::from_be_bytes([buf[off + 2], buf[off + 3]]);
            let port = xport ^ ((STUN_COOKIE >> 16) as u16);
            let cookie_bytes = STUN_COOKIE.to_be_bytes();
            let mut ipb = [0u8; 4];
            for i in 0..4 {
                ipb[i] = buf[off + 4 + i] ^ cookie_bytes[i];
            }
            let sa = SocketAddr::from((std::net::Ipv4Addr::from(ipb), port));
            return Some(sa);
        }
        // 32-bit padding
        off += (al + 3) & !3;
    }
    None
}

/// Resultado de intentar checks ICE sobre una lista de candidatos
pub struct IceCheckResult {
    pub ok: bool,
    pub sock_tx: Option<UdpSocket>,
    pub sock_rx: Option<UdpSocket>,
    pub local_ufrag: Option<String>,
    pub remote_ufrag: Option<String>,
    pub chosen: Option<IceCandidate>,
}

/// Módulo de pruebas para ICE
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ice_credentials_creation() {
        let credentials = IceCredentials {
            ufrag: "ufrag123".to_string(),
            pwd: "pwd123".to_string(),
        };

        assert_eq!(credentials.ufrag, "ufrag123");
        assert_eq!(credentials.pwd, "pwd123");
    }

    #[test]
    fn test_ice_creation() {
        let agent = IceAgent::new("ufrag123".to_string(), "pwd123".to_string(), true);

        assert_eq!(agent.credentials.ufrag, "ufrag123");
        assert_eq!(agent.credentials.pwd, "pwd123");
        assert!(agent.controlling);
        assert!(agent.local_candidates.is_empty());
        assert!(agent.remote_candidates.is_empty());
        assert!(agent.selected_candidates.is_none());
        assert!(agent.remote_credentials.is_none());
    }
}
