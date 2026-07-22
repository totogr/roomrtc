//! Modulo de representacion de la pantalla de llamada.

use crate::app::AppScreen;
use crate::app::RoomRtcApp;
use crate::app::signaling_client::SignalingClient;
use crate::config::AppConfig;
use eframe::egui;
use std::sync::{Arc, Mutex};

pub struct CallApp {
    pub peer: String,
    pub next_screen: Option<AppScreen>,
    pub rtc: RoomRtcApp,
    pub signaling: Arc<Mutex<SignalingClient>>,
    pub initialized: bool,
    pub is_caller: bool,
}

impl CallApp {
    pub fn new(
        peer: String,
        signaling: SignalingClient,
        is_caller: bool,
        config: AppConfig,
    ) -> Self {
        // Wrap signaling en Arc<Mutex> para compartir
        let signaling_arc = Arc::new(Mutex::new(signaling));

        // Crear RoomRtcApp y compartir signaling
        let mut rtc = RoomRtcApp::new(config);
        rtc.signaling = Some(signaling_arc.clone());
        rtc.peer_username = Some(peer.clone());

        Self {
            peer,
            signaling: signaling_arc,
            is_caller,
            next_screen: None,
            rtc,
            initialized: false,
        }
    }

    /// Metodo para procesar mensajes de señalizacion entrantes.
    fn poll_signaling(&mut self) {
        let Ok(sig_guard) = self.signaling.lock() else {
            self.rtc
                .add_log("Error: no se pudo obtener lock de signaling");
            return;
        };

        while let Some(msg) = sig_guard.try_recv() {
            let t = msg.msg_type.as_str();

            match t {
                "SDP" | "OFFER" | "ANSWER" => {
                    let remote_sdp = match msg.fields.get("sdp") {
                        Some(s) => s.clone(),
                        None => {
                            self.rtc.add_log("SDP recibido sin campo 'sdp'");
                            continue;
                        }
                    };

                    self.rtc.remote_sdp = remote_sdp.clone();
                    self.rtc.add_log("SDP remoto recibido");

                    if self.is_caller {
                        self.rtc.add_log("Procesando ANSWER remoto (caller)...");
                        self.rtc.handle_paste_remote_sdp();
                    } else {
                        self.rtc.add_log("Procesando OFFER remoto (callee)...");

                        self.rtc.handle_create_answer();

                        let answer_sdp = self.rtc.local_sdp.clone();
                        sig_guard.send_local_sdp(&self.peer, &answer_sdp);
                        self.rtc.add_log("ANSWER enviado automáticamente");
                    }
                }

                "CALL_ENDED" => {
                    self.rtc.add_log("El peer colgó la llamada");
                    self.rtc.handle_hang_up();
                    self.next_screen = Some(AppScreen::Lobby);
                }

                "OFFER_FILE" => {
                    if let Some(ft) = &mut self.rtc.file_transfer {
                        match ft.on_offer_file(msg) {
                            Ok(event) => {
                                let event_desc = format!("Oferta de archivo recibida: {:?}", event);
                                self.rtc.file_events.push(event);
                                self.rtc.add_log(&event_desc);
                            }
                            Err(e) => {
                                self.rtc
                                    .add_log(&format!("Error procesando OFFER_FILE: {}", e));
                            }
                        }
                    } else {
                        self.rtc.add_log("FileTransferManager no inicializado");
                    }
                }

                "ACCEPT_FILE" => {
                    let stream_id: u16 =
                        match msg.fields.get("stream_id").and_then(|s| s.parse().ok()) {
                            Some(id) => id,
                            None => {
                                self.rtc.add_log("ACCEPT_FILE sin stream_id");
                                continue;
                            }
                        };

                    if let Some(ft) = &mut self.rtc.file_transfer {
                        if let Err(e) = ft.on_accept_file(stream_id) {
                            self.rtc.add_log(&format!("Error enviando archivo: {}", e));
                        } else {
                            self.rtc.add_log("Peer aceptó archivo, enviando datos");
                        }
                    }
                }

                "REJECT_FILE" => {
                    let stream_id: u16 =
                        match msg.fields.get("stream_id").and_then(|s| s.parse().ok()) {
                            Some(id) => id,
                            None => {
                                self.rtc.add_log("REJECT_FILE sin stream_id");
                                continue;
                            }
                        };

                    if let Some(ft) = &mut self.rtc.file_transfer {
                        ft.reject(stream_id);
                        self.rtc.add_log("Peer rechazó la transferencia de archivo");
                    }
                }

                _ => {}
            }
        }
    }
}

/// Implementacion de la interfaz de eframe para CallApp.
impl eframe::App for CallApp {
    /// Metodo principal de actualizacion de la interfaz.
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        if !self.initialized {
            self.initialized = true;

            // Iniciar la camara
            self.rtc.handle_start_camera();

            // Si es el llamador, crear y enviar la oferta automaticamente
            if self.is_caller {
                self.rtc.handle_create_offer();
                let offer = self.rtc.local_sdp.clone();
                if let Ok(sig) = self.signaling.lock() {
                    sig.send_local_sdp(&self.peer, &offer);
                    self.rtc.add_log("Offer enviado automáticamente");
                }
            }
        }

        // Procesar aceptacion/rechazo de archivos pendientes
        if let Some(stream_id) = self.rtc.pending_accept_file.take() {
            if let Ok(sig) = self.signaling.lock() {
                sig.send_accept_file(&self.peer, stream_id);
                self.rtc.add_log(&format!(
                    "ACCEPT_FILE enviado al peer (stream_id: {})",
                    stream_id
                ));
            } else {
                self.rtc
                    .add_log("Error: no se pudo obtener lock de signaling para ACCEPT_FILE");
            }
        }

        if let Some(stream_id) = self.rtc.pending_reject_file.take() {
            if let Ok(sig) = self.signaling.lock() {
                sig.send_reject_file(&self.peer, stream_id, "Rechazado por usuario");
                self.rtc.add_log(&format!(
                    "REJECT_FILE enviado al peer (stream_id: {})",
                    stream_id
                ));
            } else {
                self.rtc
                    .add_log("Error: no se pudo obtener lock de signaling para REJECT_FILE");
            }
        }

        // Procesar mensajes de señalizacion entrantes del servidor
        self.poll_signaling();

        // Verificar si el usuario solicitó colgar
        if self.rtc.user_requested_hangup() {
            self.rtc.add_log("Hangup local detectado");

            // avisar al peer
            if let Ok(sig) = self.signaling.lock() {
                sig.end_call(&self.peer);
            }

            self.rtc.shutdown_call();

            self.next_screen = Some(AppScreen::Lobby);
            return;
        }

        eframe::App::update(&mut self.rtc, ctx, frame);
    }
}
