//! Handlers para acciones del usuario en RoomRtcApp

use super::{RoomRtcApp, media};
use crate::camera::CameraHandler;
use crate::protocols::ice::{IceCandidate, IceCheckResult};
use crate::sdp::sdp_utils::{generar_sdp_answer, generar_sdp_local, parse_remote_sdp};
use crate::utils;
use std::sync::{Arc, Mutex};

/// Implementación de handlers para RoomRtcApp
impl RoomRtcApp {
    /// Handler para iniciar la cámara
    pub fn handle_start_camera(&mut self) {
        self.add_log("Iniciando cámara");
        match CameraHandler::new(
            self.config.camera.resolution_width,
            self.config.camera.resolution_height,
            self.config.camera.framerate,
        ) {
            Ok(cam) => {
                self.camera = Some(Arc::new(Mutex::new(cam)));
                self.add_log("Cámara iniciada correctamente");
            }
            Err(e) => {
                let msg = format!("Error al iniciar cámara: {}", e);
                self.add_log(&msg);
            }
        }
    }

    /// Handler para crear SDP Offer
    pub fn handle_create_offer(&mut self) {
        self.add_log("Generando SDP Offer");
        self.add_log(&format!(
            "Fingerprint que se incluirá en SDP: {}",
            self.local_fingerprint
        ));
        match (&self.ice, &self.local_ip, self.audio_port, self.video_port) {
            (Some(agent), Some(ip), Some(a_port), Some(v_port)) => {
                match generar_sdp_local(
                    agent,
                    ip,
                    a_port,
                    v_port,
                    &self.local_fingerprint,
                    &self.config.sdp,
                ) {
                    Ok(sdp) => {
                        self.local_sdp = sdp;
                        self.add_log("SDP Offer creado");
                    }
                    Err(err) => {
                        let msg = format!("Error creando Offer: {}", err);
                        self.add_log(&msg);
                    }
                }
            }
            _ => {
                self.add_log("ICE no inicializado (IP/puertos faltantes)");
            }
        }
    }

    /// Handler para crear SDP Answer
    pub fn handle_create_answer(&mut self) {
        if self.remote_sdp.is_empty() {
            self.add_log("No hay SDP remoto para responder.");
            return;
        }

        if let Ok(mut active) = self.connection_active.lock() {
            *active = true;
        }

        // Extrae y almacena fingerprint remoto desde el SDP antes de iniciar el receptor.
        if let Some((_, _, fingerprint)) = parse_remote_sdp(&self.remote_sdp) {
            match fingerprint {
                Some(fp) => {
                    self.remote_fingerprint = Some(fp.clone());
                    self.add_log(&format!(
                        "Remote fingerprint extraído en crear answer: {}",
                        fp
                    ));
                }
                None => {
                    self.remote_fingerprint = None;
                    self.add_log("Advertencia: No hay fingerprint en el SDP remoto");
                }
            }
        } else {
            self.remote_fingerprint = None;
            self.add_log("Error: No se pudo parsear el SDP remoto para crear answer");
        }

        let mut logs_to_add: Vec<String> = Vec::new();

        match (
            &mut self.ice,
            &self.local_ip,
            self.audio_port,
            self.video_port,
        ) {
            (Some(agent), Some(ip), Some(a_port), Some(v_port)) => {
                agent.controlling = false;
                match generar_sdp_answer(
                    &self.remote_sdp,
                    agent,
                    ip,
                    a_port,
                    v_port,
                    &self.local_fingerprint,
                    &self.config.sdp,
                ) {
                    Ok(answer) => {
                        self.local_sdp = answer;

                        if let Some(sock_rx) = agent.socket_for_port(v_port) {
                            if !self.receiving_started {
                                let dtls_role =
                                    crate::sdp::sdp_utils::get_dtls_role(&self.local_sdp);
                                let mux_config = super::multiplexer::MultiplexerConfig {
                                    recv_timeout_ms: self.config.multiplexer.recv_timeout_ms,
                                    buffer_size: self.config.multiplexer.buffer_size,
                                };
                                media::start_receiving_on_socket(
                                    sock_rx,
                                    self.remote_frame.clone(),
                                    self.logs.clone(),
                                    self.rtcp_logs.clone(),
                                    self.camera.clone(),
                                    self.audio_muted.clone(),
                                    self.sending_started.clone(),
                                    Some(agent.credentials.ufrag.clone()),
                                    agent.remote_credentials.as_ref().map(|r| r.ufrag.clone()),
                                    self.connection_active.clone(),
                                    self.cleanup_flag.clone(),
                                    None,
                                    None,
                                    self.local_fingerprint.clone(),
                                    self.local_certificate.clone(),
                                    self.remote_fingerprint.clone(),
                                    dtls_role,
                                    self.config.rtp.clone(),
                                    self.config.media.clone(),
                                    self.config.data_channel.clone(),
                                    mux_config,
                                    self.shared_dc_manager.clone(),
                                );
                                self.receiving_started = true;
                            } else {
                                logs_to_add.push(
                                    "Recepción ya iniciada; no se crea segundo receptor"
                                        .to_string(),
                                );
                            }
                        } else {
                            logs_to_add.push(
                                "No se pudo obtener socket local de video para recibir (Answer)"
                                    .to_string(),
                            );
                        }
                    }
                    Err(err) => {
                        self.add_log(&format!("Error creando Answer: {}", err));
                    }
                }
            }
            _ => {
                self.add_log("ICE no inicializado");
            }
        }

        for m in logs_to_add {
            self.add_log(&m);
        }
    }

    /// Handler para procesar SDP remoto
    pub fn handle_paste_remote_sdp(&mut self) {
        self.add_log("Intentando conectar");

        if let Ok(mut active) = self.connection_active.lock() {
            *active = true;
        }

        // Extraer y almacenar fingerprint remoto desde el SDP
        if let Some((_, _, fingerprint)) = parse_remote_sdp(&self.remote_sdp) {
            if let Some(fp) = fingerprint {
                self.remote_fingerprint = Some(fp.clone());
                self.add_log(&format!("Fingerprint remoto establecido desde SDP: {}", fp));
            } else {
                self.add_log("Advertencia: No se encontró fingerprint remoto en el SDP");
                self.remote_fingerprint = None;
            }
        } else {
            self.add_log("Error parseando SDP para fingerprint");
        }

        // Checkear si ICE está inicializado
        if let Some(v_port) = self.video_port {
            // Construir lista de candidatos desde SDP remoto
            let candidates = self.build_candidates_from_sdp();
            if !candidates.is_empty() {
                self.add_log(&format!("Probando {} candidatos", candidates.len()));
                let res = self.start_ice_checks_for_list(v_port, &candidates);

                if res.ok {
                    if let Some(ch) = res.chosen.as_ref() {
                        self.add_log(&format!(
                            "ICE check exitoso con candidato {}:{}",
                            ch.ip, ch.port
                        ));
                    }

                    // Iniciar receptor en socket obtenido y configurado por ICE
                    if let Some(sock_rx) = res.sock_rx {
                        if !self.receiving_started {
                            let dtls_role = crate::sdp::sdp_utils::get_dtls_role(&self.local_sdp);
                            let mux_config = super::multiplexer::MultiplexerConfig {
                                recv_timeout_ms: self.config.multiplexer.recv_timeout_ms,
                                buffer_size: self.config.multiplexer.buffer_size,
                            };

                            let remote_ip = res.chosen.as_ref().map(|c| c.ip.to_string());
                            let remote_port = res.chosen.as_ref().map(|c| c.port);

                            media::start_receiving_on_socket(
                                sock_rx,
                                self.remote_frame.clone(),
                                self.logs.clone(),
                                self.rtcp_logs.clone(),
                                self.camera.clone(),
                                self.audio_muted.clone(),
                                self.sending_started.clone(),
                                res.local_ufrag,
                                res.remote_ufrag,
                                self.connection_active.clone(),
                                self.cleanup_flag.clone(),
                                remote_ip,
                                remote_port,
                                self.local_fingerprint.clone(),
                                self.local_certificate.clone(),
                                self.remote_fingerprint.clone(),
                                dtls_role,
                                self.config.rtp.clone(),
                                self.config.media.clone(),
                                self.config.data_channel.clone(),
                                mux_config,
                                self.shared_dc_manager.clone(),
                            );
                            self.receiving_started = true;
                            self.add_log("ReceiverRunner spawned after ICE success");
                        } else {
                            self.add_log("ReceiverRunner ya iniciado");
                        }
                    } else {
                        self.add_log("Error: ICE exitoso pero sin socket RX");
                    }
                } else {
                    self.add_log("ICE check falló para todos los candidatos");
                }
            } else {
                self.add_log("No se encontraron candidatos UDP válidos en el SDP remoto");
            }
        } else {
            self.add_log("ICE no inicializado (falta puerto de video)");
        }
    }

    /// Construye una lista de candidatos (UDP/component=1)
    fn build_candidates_from_sdp(&self) -> Vec<IceCandidate> {
        let parsed = utils::parse_sdp_ice(&self.remote_sdp);
        let mut list: Vec<IceCandidate> = Vec::new();
        for c in parsed.candidates {
            if c.component_id != 1 {
                continue;
            }
            if c.transport.to_uppercase() != "UDP" {
                continue;
            }
            if list.iter().any(|x| x.ip == c.ip && x.port == c.port) {
                continue;
            }
            list.push(c);
        }
        list
    }

    /// Itera candidatos y retorna el primero que funcione, con sockets y credenciales asociadas
    fn start_ice_checks_for_list(
        &mut self,
        _component_port: u16,
        remote_candidates: &[IceCandidate],
    ) -> IceCheckResult {
        let mut log_msgs: Vec<String> = Vec::new();
        let res = if let Some(agent) = self.ice.as_mut() {
            let parsed = utils::parse_sdp_ice(&self.remote_sdp);
            if let (Some(ru), Some(rp)) = (parsed.ice_ufrag.clone(), parsed.ice_pwd.clone()) {
                agent.set_remote_credentials(ru, rp);
            }
            agent.replace_remote_candidates(remote_candidates.to_vec());

            let pairs = agent.candidate_pairs();

            let mut best_result = IceCheckResult {
                ok: false,
                sock_tx: None,
                sock_rx: None,
                local_ufrag: None,
                remote_ufrag: None,
                chosen: None,
            };
            for pair in pairs {
                log_msgs.push(format!(
                    "ICE check par {} (local {}:{}, remoto {}:{})",
                    pair.priority, pair.local.ip, pair.local.port, pair.remote.ip, pair.remote.port
                ));
                let ok = agent
                    .connectivity_check(&pair.local, &pair.remote)
                    .unwrap_or(false);
                if ok {
                    let sock_tx = agent.socket_for_candidate(&pair.local);
                    let sock_rx = agent.socket_for_candidate(&pair.local);
                    best_result = IceCheckResult {
                        ok: true,
                        sock_tx,
                        sock_rx,
                        local_ufrag: Some(agent.credentials.ufrag.clone()),
                        remote_ufrag: agent.remote_credentials.as_ref().map(|r| r.ufrag.clone()),
                        chosen: Some(pair.remote.clone()),
                    };
                    break;
                }
            }
            best_result
        } else {
            IceCheckResult {
                ok: false,
                sock_tx: None,
                sock_rx: None,
                local_ufrag: None,
                remote_ufrag: None,
                chosen: None,
            }
        };
        for msg in log_msgs {
            self.add_log(&msg);
        }
        res
    }

    /// Handler para colgar la llamada
    pub fn handle_hang_up(&mut self) {
        if let (Some(agent), Some(v_port)) = (&self.ice, self.video_port)
            && let Some(sock) = agent.socket_for_port(v_port)
            && let Some((remote_ip, remote_port, _)) = parse_remote_sdp(&self.remote_sdp)
        {
            media::send_rtcp_bye(&sock, &remote_ip, remote_port, self.config.rtp.default_ssrc);
            self.add_log("RTCP BYE enviado");
        }
    }
}
