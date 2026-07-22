//! Módulo raíz de la aplicación eframe para la demo de WebRTC manual.

use crate::app::file_transfer::ReceivedFile;
use crate::app::file_transfer::{FileTransferEvent, FileTransferManager};
use crate::camera::CameraHandler;
use crate::certificate::CertificateInfo;
use crate::config::AppConfig;
use crate::protocols::data_channel::DataChannelManager;
use crate::protocols::ice::IceAgent;
use crate::utils;
use eframe::egui::{ColorImage, TextureHandle};
use eframe::{App, Frame, egui};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};

pub mod call;
pub mod file_transfer;
mod handlers;
pub mod lobby;
use crate::app::logging::{Logger, add_log_to_vec};
mod logging;
pub mod media;
pub mod multiplexer;
pub mod signaling_client;
mod ui;

/// Resultados de diálogos de archivos (abrir/guardar).
enum FileDialogResult {
    SendFile(PathBuf),
    SaveFile {
        path: PathBuf,
        file: ReceivedFile,
        stream_id: u16,
    },
}

/// Pantallas principales de la aplicación.
#[derive(Clone)]
pub enum AppScreen {
    Lobby,
    Call { peer: String },
}

/// Estructura principal de la aplicación RoomRtcApp.
pub struct RoomRtcApp {
    pub config: AppConfig,
    pub local_sdp: String,
    pub remote_sdp: String,

    camera: Option<Arc<Mutex<CameraHandler>>>,
    local_texture: Option<TextureHandle>,

    remote_frame: Arc<Mutex<Option<ColorImage>>>,
    remote_texture: Option<TextureHandle>,

    logs: Arc<Mutex<Vec<String>>>,
    pub rtcp_logs: Arc<Mutex<Vec<String>>>,
    pub hangup_requested: Arc<AtomicBool>,

    // ICE state
    ice: Option<IceAgent>,
    local_ip: Option<String>,
    audio_port: Option<u16>,
    video_port: Option<u16>,

    // DTLS state
    local_fingerprint: String,
    local_certificate: Vec<u8>,
    remote_fingerprint: Option<String>,

    receiving_started: bool,
    sending_started: Arc<Mutex<bool>>,
    connection_active: Arc<Mutex<bool>>,
    cleanup_flag: Arc<Mutex<bool>>,

    // Audio state (micrófono se crea en el thread de audio)
    pub audio_muted: Arc<Mutex<bool>>,

    logger: Logger,
    last_persist: std::time::Instant,

    // File transfer state
    pub file_transfer: Option<FileTransferManager>,
    pub file_events: Vec<FileTransferEvent>,
    pub shared_dc_manager: Arc<Mutex<Option<Arc<Mutex<DataChannelManager>>>>>,

    pub pending_accept_file: Option<u16>,
    pub pending_reject_file: Option<u16>,
    file_dialog_rx: Option<Receiver<Option<FileDialogResult>>>,

    // Signaling (compartido desde CallApp)
    pub signaling: Option<Arc<Mutex<signaling_client::SignalingClient>>>,
    pub peer_username: Option<String>,
}

/// Implementación de la aplicación eframe RoomRtcApp.
impl App for RoomRtcApp {
    /// Método de actualización llamado en cada frame de la aplicación.
    fn update(&mut self, ctx: &egui::Context, frame: &mut Frame) {
        // Persist logs periodically
        if self.last_persist.elapsed() >= std::time::Duration::from_secs(5) {
            self.persist_logs();
            self.last_persist = std::time::Instant::now();
        }

        let dc_opt = {
            let guard = self.shared_dc_manager.lock().ok();
            guard.and_then(|g| g.clone())
        };

        if self.file_transfer.is_none()
            && let Some(dc) = dc_opt
        {
            self.try_init_file_transfer(dc);
        }

        self.poll_file_transfer();

        ui::update(self, ctx, frame);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.persist_logs();
    }
}

/// Implementación de métodos para la estructura RoomRtcApp.
impl RoomRtcApp {
    /// Crea una nueva instancia de RoomRtcApp con la configuración dada.
    pub fn new(config: AppConfig) -> Self {
        let logs = Arc::new(Mutex::new(Vec::new()));
        let rtcp_logs = Arc::new(Mutex::new(Vec::new()));

        // Generar un certificado autofirmado para DTLS
        let (local_fingerprint, local_certificate) = match CertificateInfo::generate() {
            Ok(cert_info) => {
                add_log_to_vec(
                    &logs,
                    &format!(
                        "Certificado generado: {} bytes con fingerprint: {}",
                        cert_info.certificate.len(),
                        cert_info.fingerprint
                    ),
                );
                (cert_info.fingerprint, cert_info.certificate)
            }
            Err(e) => {
                add_log_to_vec(&logs, &format!("Error generando certificado: {}", e));
                (
                    "sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00".to_string(),
                    Vec::new()
                )
            }
        };

        let logger = Logger::new(config.logging.log_file.clone());
        let last_persist = std::time::Instant::now();

        let mut app = RoomRtcApp {
            config,
            local_sdp: String::new(),
            remote_sdp: String::new(),
            camera: None,
            local_texture: None,
            remote_frame: Arc::new(Mutex::new(None)),
            remote_texture: None,
            logs: logs.clone(),
            rtcp_logs,
            hangup_requested: Arc::new(AtomicBool::new(false)),
            ice: None,
            local_ip: None,
            audio_port: None,
            video_port: None,
            local_fingerprint,
            local_certificate,
            remote_fingerprint: None,
            receiving_started: false,
            sending_started: Arc::new(Mutex::new(false)),
            connection_active: Arc::new(Mutex::new(false)),
            cleanup_flag: Arc::new(Mutex::new(false)),
            audio_muted: Arc::new(Mutex::new(false)),
            logger,
            last_persist,
            file_transfer: None,
            file_events: Vec::new(),
            shared_dc_manager: Arc::new(Mutex::new(None)),
            pending_accept_file: None,
            pending_reject_file: None,
            file_dialog_rx: None,
            signaling: None,
            peer_username: None,
        };

        match utils::detect_local_ipv4() {
            Ok(ip) => {
                let ip_str = ip.to_string();
                let audio = utils::allocate_udp_port(ip);
                let video = utils::allocate_udp_port(ip);
                match (audio, video) {
                    (Ok(a_port), Ok(v_port)) => {
                        let mut agent =
                            IceAgent::new_with_host_candidates(ip, &[a_port, v_port], true);

                        // Gather srflx candidates
                        use std::net::ToSocketAddrs;
                        let stun_server = "stun.l.google.com:19302";
                        if let Ok(mut addrs) = stun_server.to_socket_addrs() {
                            if let Some(stun_addr) = addrs.find(|a| a.is_ipv4()) {
                                let logs_vec = agent.gather_srflx_candidates(stun_addr);
                                for log in logs_vec {
                                    add_log_to_vec(&app.logs, &log);
                                }
                            } else {
                                add_log_to_vec(
                                    &app.logs,
                                    "No se pudo resolver la dirección del servidor STUN",
                                );
                            }
                        } else {
                            add_log_to_vec(&app.logs, "Error resolviendo DNS del servidor STUN");
                        }

                        app.local_ip = Some(ip_str);
                        app.audio_port = Some(a_port);
                        app.video_port = Some(v_port);
                        app.ice = Some(agent);
                    }
                    (Err(ea), Err(ev)) => {
                        add_log_to_vec(
                            &app.logs,
                            &format!("ICE init falló (puertos audio/video): {}, {}", ea, ev),
                        );
                    }
                    (Err(ea), _) => {
                        add_log_to_vec(
                            &app.logs,
                            &format!("ICE init falló (puerto audio): {}", ea),
                        );
                    }
                    (_, Err(ev)) => {
                        add_log_to_vec(
                            &app.logs,
                            &format!("ICE init falló (puerto video): {}", ev),
                        );
                    }
                }
            }
            Err(e) => {
                add_log_to_vec(&app.logs, &format!("No se pudo detectar IP local: {}", e));
            }
        }

        app
    }

    /// Realiza el shutdown de la llamada actual, limpiando recursos y estado.
    pub fn shutdown_call(&mut self) {
        self.add_log("Shutdown de llamada iniciado");

        if let Ok(mut a) = self.connection_active.lock() {
            *a = false;
        }
        if let Ok(mut s) = self.sending_started.lock() {
            *s = false;
        }

        if let Some(ft) = &mut self.file_transfer {
            ft.shutdown();
        }
        self.file_transfer = None;
        self.file_events.clear();

        if let Ok(mut dc) = self.shared_dc_manager.lock() {
            *dc = None;
        }

        if let Some(agent) = &mut self.ice {
            agent.reset_for_new_connection();
        }

        self.cleanup_connection();

        self.add_log("Shutdown de llamada completo");
    }

    /// Agrega un mensaje de log al vector de logs.
    pub fn add_log(&self, message: &str) {
        add_log_to_vec(&self.logs, message);
    }

    /// Establece la bandera de colgar llamada.
    pub fn set_hangup_flag(&self) {
        self.hangup_requested.store(true, Ordering::Release);
    }

    /// Verifica si el usuario ha solicitado colgar la llamada.
    pub fn user_requested_hangup(&self) -> bool {
        self.hangup_requested.swap(false, Ordering::AcqRel)
    }

    /// Limpia el estado de la conexión para prepararse para una nueva llamada.
    pub fn cleanup_connection(&mut self) {
        // Borrar campos SDP
        self.local_sdp.clear();
        self.remote_sdp.clear();

        // Borrar fingerprints
        self.remote_fingerprint = None;

        // Borrar frame remoto
        if let Ok(mut frame) = self.remote_frame.lock() {
            *frame = None;
        }

        // No cerrar cámara - mantenerla abierta para la próxima conexión
        // La cámara seguirá proporcionando frames a la visualización de video local

        // Borrar texturas
        self.local_texture = None;
        self.remote_texture = None;

        // Reiniciar agente ICE para nueva conexión
        if let Some(agent) = &mut self.ice {
            agent.reset_for_new_connection();
        }

        // Resetear estado de conexión
        self.receiving_started = false;
        if let Ok(mut s) = self.sending_started.lock() {
            *s = false;
        }
        if let Ok(mut active) = self.connection_active.lock() {
            *active = false;
        }
        if let Ok(mut flag) = self.cleanup_flag.lock() {
            *flag = false;
        }
    }

    /// Persiste los logs en el archivo configurado.
    pub fn persist_logs(&self) {
        self.logger.persist_logs(&self.logs);
    }

    /// Enviar un archivo a través del canal de datos.
    pub fn send_file(&mut self, path: &Path) -> Result<(), String> {
        let stream_id = if let Some(ft) = &mut self.file_transfer {
            ft.send_file(path)?
        } else {
            return Err("FileTransfer no inicializado".into());
        };

        let metadata = if let Some(ft) = &self.file_transfer {
            ft.get_upload_metadata(stream_id)
        } else {
            None
        };

        let Some(metadata) = metadata else {
            return Err("No se pudo obtener metadata del archivo".into());
        };

        // Notificar al peer que queremos enviarle un archivo
        if let (Some(signaling), Some(peer)) = (&self.signaling, &self.peer_username) {
            if let Ok(sig) = signaling.lock() {
                sig.send_offer_file(peer, stream_id, &metadata);
                self.add_log(&format!(
                    "OFFER_FILE enviado para '{}' (stream_id: {}, size: {} bytes)",
                    metadata.name, stream_id, metadata.size
                ));
            } else {
                self.add_log("Error: no se pudo obtener lock de signaling para OFFER_FILE");
            }
        } else {
            self.add_log(&format!(
                "Warning: signaling o peer_username no disponible - signaling: {}, peer: {}",
                self.signaling.is_some(),
                self.peer_username.is_some()
            ));
        }

        Ok(())
    }

    /// Verificar y procesar transferencias de archivos entrantes.
    pub fn poll_file_transfer(&mut self) {
        let Some(ft) = &mut self.file_transfer else {
            return;
        };

        let events = ft.poll_events();
        self.file_events.extend(events);
    }

    /// Inicializa el gestor de transferencia de archivos si no está ya inicializado.
    pub fn try_init_file_transfer(&mut self, dc_manager: Arc<Mutex<DataChannelManager>>) {
        if self.file_transfer.is_none() {
            self.file_transfer = Some(FileTransferManager::new_with_defaults(dc_manager));
            self.add_log("FileTransferManager inicializado");
        }
    }
}

/// Implementación del trait Default para RoomRtcApp.
impl Default for RoomRtcApp {
    /// Método para crear una instancia por defecto de RoomRtcApp.
    fn default() -> Self {
        Self::new(AppConfig::default())
    }
}
