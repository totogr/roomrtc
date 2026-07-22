//! Modulo para manejo de medios RTP/RTCP con ICE y DTLS

use super::logging::{add_log_to_vec, add_rtcp_log};
use super::multiplexer::{self, MultiplexerConfig};
use crate::audio_output::AudioOutput;
use crate::camera::{CameraHandler, RawFrame};
use crate::codec::DecodeThreadMsg;
use crate::codec::decode_thread;
use crate::codec::h264::{DecodedFrame, H264Encoder};
use crate::codec::opus::{OpusDecoder, OpusEncoder};
use crate::codec::rgb_to_rgba_thread;
use crate::config::{DataChannelConfig, MediaConfig, RtpConfig};
use crate::microphone::{AudioFrame, MicrophoneHandler};
use crate::protocols::data_channel::DataChannelManager;
use crate::protocols::dtls::DtlsAgent;
use crate::protocols::h264_rtp::{H264RtpDepacketizer, H264RtpPacketizer};
use crate::protocols::ice;
use crate::protocols::jitter_buffer::JitterBuffer;
use crate::protocols::opus_rtp::{OpusRtpDepacketizer, OpusRtpPacketizer};
use crate::protocols::rtcp::{self, ReceiverReport, ReportBlock};
use crate::protocols::rtcp_receiver::RtcpRecvState;
use crate::protocols::rtp_packet::RtpHeader;
use crate::protocols::srtp::SrtpContext;
use eframe::egui::ColorImage;
use opus::{Application, Channels};
use rand::{Rng, RngCore, rng};
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// Tipo para el manejador compartido de DataChannels
type DataChannelManagerArc = Arc<Mutex<Option<Arc<Mutex<DataChannelManager>>>>>;

/// Mensaje que el hilo de conversión RGB a RGBA envía al receptor.
pub enum RgbaFrameMsg {
    Image {
        image: ColorImage,
        width: u32,
        height: u32,
    },
}

/// Enum de estado de conexion.
#[derive(Debug, Clone, Copy, PartialEq)]
enum IcePhase {
    NotStarted,
    InProgress,
    Complete,
    Failed,
}

/// Enum de estado de DTLS.
#[derive(Debug, Clone, Copy, PartialEq)]
enum DtlsPhase {
    NotStarted,
    InProgress,
    Complete,
}

/// Estrutura para seguimiento de chequeos ICE en progreso
struct IceCheckInProgress {
    txid: [u8; 12],
    _peer_addr: SocketAddr,
    sent_at: Instant,
    attempt_count: u32,
    deadline: Instant,
}

/// Estrutura de estado ICE
struct IceState {
    phase: IcePhase,
    current_check: Option<IceCheckInProgress>,
    ready: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    remote_ip: Option<String>,
    remote_port: Option<u16>,
}

/// Estrutura de estado DTLS
struct DtlsState {
    phase: DtlsPhase,
    ready: Arc<AtomicBool>,
    _failed: Arc<AtomicBool>,
    agent: Option<DtlsAgent>,
    role: Option<crate::protocols::dtls::DtlsRole>,
}

/// Estado general de la conexion
struct ConnectionState {
    ice: IceState,
    dtls: DtlsState,
}

/// Inicia el proceso de envio en un socket UDP.
#[allow(clippy::too_many_arguments)]
pub fn start_sending_on_socket(
    sock: UdpSocket,
    remote_ip: String,
    remote_port: u16,
    camera: Arc<Mutex<CameraHandler>>,
    audio_muted: Arc<Mutex<bool>>,
    logs: Arc<Mutex<Vec<String>>>,
    rtcp_logs: Arc<Mutex<Vec<String>>>,
    sending_started: Arc<Mutex<bool>>,
    connection_active: Arc<Mutex<bool>>,
    master_secret: Vec<u8>,
    rtp_config: RtpConfig,
    media_config: MediaConfig,
    keyframe_request: Arc<AtomicBool>,
) {
    thread::spawn(move || {
        SenderRunner::new(
            sock,
            remote_ip,
            remote_port,
            camera,
            audio_muted,
            logs,
            rtcp_logs,
            sending_started,
            connection_active,
            master_secret,
            rtp_config,
            media_config,
            keyframe_request,
        )
        .run()
    });
}

/// Inicia el proceso de recepcion en un socket UDP.
#[allow(clippy::too_many_arguments)]
pub fn start_receiving_on_socket(
    sock: UdpSocket,
    remote_frame: Arc<Mutex<Option<ColorImage>>>,
    logs: Arc<Mutex<Vec<String>>>,
    rtcp_logs: Arc<Mutex<Vec<String>>>,
    camera_opt: Option<Arc<Mutex<CameraHandler>>>,
    audio_muted: Arc<Mutex<bool>>,
    sending_started: Arc<Mutex<bool>>,
    local_ufrag: Option<String>,
    remote_ufrag: Option<String>,
    connection_active: Arc<Mutex<bool>>,
    cleanup_flag: Arc<Mutex<bool>>,
    remote_ip: Option<String>,
    remote_port: Option<u16>,
    local_fingerprint: String,
    local_certificate: Vec<u8>,
    remote_fingerprint: Option<String>,
    dtls_role: crate::protocols::dtls::DtlsRole,
    rtp_config: RtpConfig,
    media_config: MediaConfig,
    data_channel_config: DataChannelConfig,
    multiplexer_config: MultiplexerConfig,
    shared_dc_manager: Arc<Mutex<Option<Arc<Mutex<DataChannelManager>>>>>,
) {
    thread::spawn(move || {
        if let Some(mut runner) = ReceiverRunner::bootstrap(
            sock,
            remote_frame,
            logs,
            rtcp_logs,
            camera_opt,
            audio_muted,
            sending_started,
            local_ufrag,
            remote_ufrag,
            connection_active,
            cleanup_flag,
            local_fingerprint,
            local_certificate,
            remote_fingerprint,
            dtls_role,
            rtp_config,
            media_config,
            data_channel_config,
            multiplexer_config,
        ) {
            runner.shared_dc_manager = Some(shared_dc_manager.clone());

            // Si se proporciona IP/puerto remotos, inicializar ICE inmediatamente
            if let (Some(ip), Some(port)) = (remote_ip, remote_port) {
                runner.initialize_ice(ip, port);
            }
            runner.run();
        }
    });
}

/// Estructura para el hilo de envio RTP/RTCP.
struct SenderRunner {
    sock: UdpSocket,
    remote_ip: String,
    remote_port: u16,
    camera: Arc<Mutex<CameraHandler>>,
    audio_muted: Arc<Mutex<bool>>,
    logs: Arc<Mutex<Vec<String>>>,
    rtcp_logs: Arc<Mutex<Vec<String>>>,
    h264_encoder: Option<H264Encoder>,
    packetizer: H264RtpPacketizer,
    frame_interval: Duration,
    seq: u16,
    timestamp: u32,
    packets_sent: u32,
    bytes_sent: u32,
    encode_errors: u32,
    last_rtcp_sent: Instant,
    ssrc: u32,
    sending_started: Arc<Mutex<bool>>,
    connection_active: Arc<Mutex<bool>>,
    srtp: Option<SrtpContext>, // Contexto SRTP para cifrado de payload RTP
    rtp_config: RtpConfig,
    media_config: MediaConfig,
    keyframe_request: Arc<AtomicBool>,
    last_fps_time: Instant,
    frames_this_second: u32,
}

/// Implementacion de metodos para SenderRunner.
impl SenderRunner {
    /// Crea una nueva instancia de SenderRunner.
    #[allow(clippy::too_many_arguments)]
    fn new(
        sock: UdpSocket,
        remote_ip: String,
        remote_port: u16,
        camera: Arc<Mutex<CameraHandler>>,
        audio_muted: Arc<Mutex<bool>>,
        logs: Arc<Mutex<Vec<String>>>,
        rtcp_logs: Arc<Mutex<Vec<String>>>,
        sending_started: Arc<Mutex<bool>>,
        connection_active: Arc<Mutex<bool>>,
        master_secret: Vec<u8>,
        rtp_config: RtpConfig,
        media_config: MediaConfig,
        keyframe_request: Arc<AtomicBool>,
    ) -> Self {
        let ssrc = rtp_config.default_ssrc;
        let packetizer =
            H264RtpPacketizer::new(media_config.send_mtu, rtp_config.payload_type, 0, ssrc);

        let srtp = if !master_secret.is_empty() {
            Some(SrtpContext::new(&master_secret))
        } else {
            None
        };

        Self {
            sock,
            remote_ip,
            remote_port,
            camera,
            audio_muted,
            logs,
            rtcp_logs,
            h264_encoder: None,
            packetizer,
            frame_interval: Duration::from_millis(media_config.frame_interval_ms),
            seq: 0,
            timestamp: 0,
            packets_sent: 0,
            bytes_sent: 0,
            encode_errors: 0,
            last_rtcp_sent: Instant::now(),
            ssrc,
            sending_started,
            connection_active,
            srtp,
            rtp_config,
            media_config,
            keyframe_request,
            last_fps_time: Instant::now(),
            frames_this_second: 0,
        }
    }

    /// Ejecuta el bucle principal de envio.
    fn run(mut self) {
        // Iniciar thread de audio (crea su propio micrófono interno)
        let sock_audio = self
            .sock
            .try_clone()
            .expect("Failed to clone socket for audio");
        let remote_ip = self.remote_ip.clone();
        let remote_port = self.remote_port;
        let logs = self.logs.clone();
        let sending_started = self.sending_started.clone();
        let connection_active = self.connection_active.clone();
        let rtp_config = self.rtp_config.clone();
        let media_config = self.media_config.clone();
        let audio_muted = self.audio_muted.clone();

        // Copiar el SRTP context para audio (SrtpContext implementa Copy)
        let srtp_for_audio = self.srtp;

        thread::spawn(move || {
            run_audio_sender(
                sock_audio,
                remote_ip,
                remote_port,
                audio_muted,
                logs,
                sending_started,
                connection_active,
                rtp_config,
                media_config,
                srtp_for_audio,
            );
        });

        add_log_to_vec(&self.logs, "Audio sender thread iniciado");

        // Bucle principal de video
        while self.is_active() {
            if let Some(raw) = {
                if let Ok(mut cam) = self.camera.try_lock() {
                    cam.get_raw_frame()
                } else {
                    None
                }
            } {
                self.process_raw_frame(raw);
            } else {
                thread::sleep(Duration::from_millis(self.media_config.idle_sleep_ms));
            }
        }

        // Enviar RTCP BYE antes de matar el proceso
        self.send_bye();
        add_rtcp_log(&self.rtcp_logs, "Sender detenido y BYE enviado");
    }

    /// Verifica si el sender esta activo.
    fn is_active(&self) -> bool {
        let sending = self.sending_started.lock().map(|g| *g).unwrap_or(false);
        let connection = self.connection_active.lock().map(|g| *g).unwrap_or(false);
        sending && connection
    }

    /// Procesa un frame raw capturado.
    fn process_raw_frame(&mut self, raw: RawFrame) {
        self.frames_this_second += 1;

        let now = Instant::now();
        if now.duration_since(self.last_fps_time).as_secs() >= 1 {
            let fps = self.frames_this_second;

            add_log_to_vec(&self.logs, &format!("FPS TX actuales: {} fps", fps));

            self.frames_this_second = 0;
            self.last_fps_time = now;
        }

        let start = Instant::now();
        let width = raw.width as u32;
        let height = raw.height as u32;

        if !self.ensure_encoder(width, height) {
            return;
        }

        // Verificar si se solicito un keyframe
        if self
            .keyframe_request
            .load(std::sync::atomic::Ordering::Relaxed)
            && let Some(encoder) = &mut self.h264_encoder
        {
            add_log_to_vec(&self.logs, "Forzando Keyframe H.264 por solicitud PLI");
            if let Err(e) = encoder.force_keyframe() {
                add_log_to_vec(&self.logs, &format!("Error forzando keyframe: {}", e));
            }
            self.keyframe_request
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }

        // Usamos el buffer RAW directamente
        let encoder = match self.h264_encoder.as_mut() {
            Some(enc) => enc,
            None => {
                self.encode_errors = self.encode_errors.saturating_add(1);

                if self.encode_errors.is_multiple_of(10) {
                    add_log_to_vec(
                        &self.logs,
                        "Encoder H.264 no inicializado, frame descartado",
                    );
                }

                thread::sleep(Duration::from_millis(33));
                return;
            }
        };

        let encoded = match encoder.encode(&raw.pixels, width, height) {
            Ok(data) => data,
            Err(err) => {
                self.encode_errors = self.encode_errors.saturating_add(1);

                if self.encode_errors.is_multiple_of(10) {
                    add_log_to_vec(&self.logs, &format!("Error codificando H.264: {}", err));
                }

                thread::sleep(Duration::from_millis(33));
                return;
            }
        };

        let (packets, payload) = self.send_rtp_packets(&encoded, width, height);
        self.packets_sent += packets;
        self.bytes_sent += payload;

        self.send_rtcp(self.timestamp);
        self.timestamp = self.timestamp.wrapping_add(self.rtp_config.timestamp_step);

        let elapsed = start.elapsed();
        if elapsed < self.frame_interval {
            thread::sleep(self.frame_interval - elapsed);
        }
    }

    /// Asegura que el encoder H.264 este inicializado.
    fn ensure_encoder(&mut self, width: u32, height: u32) -> bool {
        // Si ya existe, verificar si coincide la resolución
        if let Some(enc) = &self.h264_encoder {
            if enc.enc_width() == width && enc.enc_height() == height {
                return true;
            } else {
                self.h264_encoder = None;
            }
        }

        let fps = (1000 / self.media_config.frame_interval_ms) as u32;

        match H264Encoder::new(width, height, fps, self.media_config.video_bitrate) {
            Ok(enc) => {
                add_log_to_vec(
                    &self.logs,
                    &format!(
                        "Encoder H.264 inicializado ({}x{}, {}fps, {}bps)",
                        width, height, fps, self.media_config.video_bitrate
                    ),
                );
                self.h264_encoder = Some(enc);
                true
            }
            Err(err) => {
                add_log_to_vec(&self.logs, &format!("Error creando encoder H.264: {}", err));
                false
            }
        }
    }

    /// Envía paquetes RTP.
    fn send_rtp_packets(&mut self, encoded: &[u8], width: u32, height: u32) -> (u32, u32) {
        self.packetizer.seq = self.seq;
        let packets = self.packetizer.packetize_frame(encoded, self.timestamp);
        if packets.is_empty() {
            return (0, 0);
        }
        let endpoint = format!("{}:{}", self.remote_ip, self.remote_port);
        let per_pkt_us = if packets.len() > 1 {
            (self.frame_interval.as_micros() / packets.len() as u128)
                .max(self.media_config.min_packet_us as u128) as u64
        } else {
            0
        };
        let payload_bytes =
            self.transmit_packets(&packets, endpoint.as_str(), width, height, per_pkt_us);
        self.seq = self.packetizer.seq;
        (packets.len() as u32, payload_bytes)
    }

    /// Transmite los paquetes RTP, aplicando cifrado si es necesario.
    fn transmit_packets(
        &mut self,
        packets: &[Vec<u8>],
        endpoint: &str,
        width: u32,
        height: u32,
        per_pkt_us: u64,
    ) -> u32 {
        let mut payload_bytes = 0u32;
        for (i, pkt) in packets.iter().enumerate() {
            let seq = self.seq.wrapping_add(i as u16);

            // Cifrar la payload RTP si SRTP está configurado
            let packet_to_send = if let Some(srtp) = &self.srtp {
                self.encrypt_rtp_packet(pkt, seq, srtp)
            } else {
                pkt.clone()
            };

            if let Err(err) = self.sock.send_to(&packet_to_send, endpoint) {
                add_log_to_vec(&self.logs, &format!("Error enviando RTP H.264: {}", err));
            }
            if pkt.len() >= 12 {
                payload_bytes = payload_bytes.saturating_add((pkt.len() - 12) as u32);
            }
            if per_pkt_us > 0 && i + 1 < packets.len() {
                thread::sleep(Duration::from_micros(per_pkt_us));
            }
            if seq.is_multiple_of(self.rtp_config.log_interval) {
                add_log_to_vec(
                    &self.logs,
                    &format!(
                        "Video RTP enviado: {} paquetes, ts={}, {}x{}",
                        seq, self.timestamp, width, height
                    ),
                );
            }
        }
        payload_bytes
    }

    /// Cifrar la payload RTP manteniendo el encabezado intacto.
    fn encrypt_rtp_packet(&self, rtp_packet: &[u8], seq: u16, srtp: &SrtpContext) -> Vec<u8> {
        // El encabezado RTP son los primeros 12 bytes, el resto es la payload
        if rtp_packet.len() < 12 {
            return rtp_packet.to_vec();
        }

        let rtp_header = &rtp_packet[0..12];
        let payload = &rtp_packet[12..];

        // Cifrar la payload
        let encrypted_payload = srtp.encrypt_payload(payload, seq);

        // Combinar encabezado + payload cifrado
        let mut result = rtp_header.to_vec();
        result.extend_from_slice(&encrypted_payload);
        result
    }

    /// Envía un informe RTCP SR.
    fn send_rtcp(&mut self, timestamp: u32) {
        if self
            .last_rtcp_sent
            .elapsed()
            .lt(&Duration::from_secs(self.media_config.periodic_rr_secs))
        {
            return;
        }
        send_rtcp_sr_sdes(
            &self.sock,
            &self.remote_ip,
            self.remote_port,
            self.ssrc,
            timestamp,
            self.packets_sent,
            self.bytes_sent,
        );
        add_rtcp_log(
            &self.rtcp_logs,
            &format!(
                "RTCP SR enviado: pkts={} bytes={}",
                self.packets_sent, self.bytes_sent
            ),
        );
        self.last_rtcp_sent = Instant::now();
    }

    /// Envía un RTCP BYE.
    fn send_bye(&self) {
        send_rtcp_bye(&self.sock, &self.remote_ip, self.remote_port, self.ssrc);
        add_rtcp_log(&self.rtcp_logs, "RTCP BYE enviado desde sender");
    }
}

/// Thread de envío de audio - captura del micrófono, codifica con Opus y envía via RTP
#[allow(clippy::too_many_arguments)]
fn run_audio_sender(
    sock: UdpSocket,
    remote_ip: String,
    remote_port: u16,
    audio_muted: Arc<Mutex<bool>>,
    logs: Arc<Mutex<Vec<String>>>,
    sending_started: Arc<Mutex<bool>>,
    connection_active: Arc<Mutex<bool>>,
    rtp_config: RtpConfig,
    media_config: MediaConfig,
    srtp: Option<SrtpContext>,
) {
    add_log_to_vec(&logs, "Iniciando envío de audio");

    // Log SRTP status
    if srtp.is_some() {
        add_log_to_vec(&logs, "Audio sender: SRTP habilitado para encriptación");
    } else {
        add_log_to_vec(
            &logs,
            "Audio sender: SRTP NO disponible - enviando sin cifrar",
        );
    }

    // Crear micrófono en este thread (cpal Stream no es Send)
    let mut microphone = match MicrophoneHandler::new(media_config.audio_sample_rate) {
        Ok(mic) => {
            add_log_to_vec(&logs, "Micrófono de audio sender inicializado");
            mic
        }
        Err(e) => {
            add_log_to_vec(&logs, &format!("Error inicializando micrófono: {}", e));
            return;
        }
    };

    // Crear encoder Opus
    let mut opus_encoder = match OpusEncoder::new(
        media_config.audio_sample_rate,
        Channels::Mono,
        Application::Voip,
    ) {
        Ok(enc) => {
            add_log_to_vec(&logs, "Opus encoder creado correctamente");
            enc
        }
        Err(e) => {
            add_log_to_vec(&logs, &format!("Error creando Opus encoder: {}", e));
            return;
        }
    };

    // Configurar bitrate
    if let Err(e) = opus_encoder.set_bitrate(media_config.audio_bitrate) {
        add_log_to_vec(&logs, &format!("Error configurando bitrate de Opus: {}", e));
    }

    // Crear paquetizador RTP para Opus
    let mut audio_packetizer = OpusRtpPacketizer::new(rtp_config.audio_ssrc, 0);

    // Buffer para datos codificados
    let mut encoded_buffer = vec![0u8; 4000];

    // Timestamp de audio (incrementa por frame_size)
    let mut audio_timestamp: u32 = 0;
    let frame_size = opus_encoder.frame_size() as u32;

    let audio_interval = Duration::from_millis(media_config.audio_packet_interval_ms);
    let endpoint = format!("{}:{}", remote_ip, remote_port);

    let mut packets_sent = 0u32;
    let mut bytes_sent = 0u32;
    let mut last_rtcp_sent = Instant::now();

    add_log_to_vec(
        &logs,
        &format!(
            "Audio sender configurado: {}Hz, frame_size={}, bitrate={}",
            media_config.audio_sample_rate, frame_size, media_config.audio_bitrate
        ),
    );

    let mut no_samples_count = 0u32;

    loop {
        // Verificar si el sender está activo
        let sending = sending_started.lock().map(|g| *g).unwrap_or(false);
        let active = connection_active.lock().map(|g| *g).unwrap_or(false);
        if !sending || !active {
            add_log_to_vec(&logs, "Audio sender detenido: sending o active es false");
            break;
        }

        // Verificar si está muteado
        let is_muted = audio_muted.lock().map(|g| *g).unwrap_or(false);

        // Si está muteado, no enviar audio - solo esperar y continuar
        if is_muted {
            thread::sleep(audio_interval);
            continue;
        }

        // Obtener samples del micrófono, o usar silencio si no hay disponibles
        let audio_frame = microphone.get_samples().unwrap_or_else(|| {
            no_samples_count += 1;
            if no_samples_count.is_multiple_of(rtp_config.error_log_interval as u32) {
                add_log_to_vec(
                    &logs,
                    &format!(
                        "Micrófono: no samples disponibles, enviando silencio ({} veces)",
                        no_samples_count
                    ),
                );
            }
            // Crear frame de silencio
            AudioFrame {
                samples: vec![0i16; frame_size as usize],
                sample_rate: media_config.audio_sample_rate,
                channels: 1,
            }
        });

        no_samples_count = 0; // Reset counter cuando hay samples reales
        // Codificar con Opus
        match opus_encoder.encode(&audio_frame.samples, &mut encoded_buffer) {
            Ok(encoded_len) => {
                // Paquetizar en RTP
                let rtp_packet =
                    audio_packetizer.packetize(&encoded_buffer[..encoded_len], audio_timestamp);

                // Obtener sequence number actual para SRTP (antes de incrementar)
                let seq = audio_packetizer.sequence().wrapping_sub(1);

                // Encriptar con SRTP si está disponible
                let final_packet = if let Some(srtp_ctx) = &srtp {
                    if rtp_packet.len() >= 12 {
                        let header = &rtp_packet[0..12];
                        let payload = &rtp_packet[12..];
                        let encrypted_payload = srtp_ctx.encrypt_payload(payload, seq);

                        let mut encrypted_packet = header.to_vec();
                        encrypted_packet.extend_from_slice(&encrypted_payload);

                        if packets_sent.is_multiple_of(rtp_config.log_interval as u32) {
                            add_log_to_vec(
                                &logs,
                                &format!(
                                    "Audio RTP ENCRYPTED: seq={} payload_size={} encrypted_size={}",
                                    seq,
                                    payload.len(),
                                    encrypted_payload.len()
                                ),
                            );
                        }
                        encrypted_packet
                    } else {
                        rtp_packet
                    }
                } else {
                    rtp_packet
                };

                if let Err(e) = sock.send_to(&final_packet, &endpoint) {
                    add_log_to_vec(&logs, &format!("Error enviando RTP de audio: {}", e));
                }

                packets_sent += 1;
                bytes_sent += encoded_len as u32;
                audio_timestamp = audio_timestamp.wrapping_add(frame_size);

                // Log periódico
                if packets_sent.is_multiple_of(rtp_config.log_interval as u32) {
                    add_log_to_vec(
                        &logs,
                        &format!(
                            "Audio RTP enviado: {} paquetes, ts={}, muted={}",
                            packets_sent, audio_timestamp, is_muted
                        ),
                    );
                }

                // Enviar RTCP SR periódicamente
                if last_rtcp_sent.elapsed() >= Duration::from_secs(media_config.periodic_rr_secs) {
                    send_rtcp_sr_sdes(
                        &sock,
                        &remote_ip,
                        remote_port,
                        rtp_config.audio_ssrc,
                        audio_timestamp,
                        packets_sent,
                        bytes_sent,
                    );
                    add_log_to_vec(
                        &logs,
                        &format!(
                            "Audio RTCP SR enviado: pkts={} bytes={} ts={}",
                            packets_sent, bytes_sent, audio_timestamp
                        ),
                    );
                    last_rtcp_sent = Instant::now();
                }
            }
            Err(e) => {
                add_log_to_vec(&logs, &format!("Error codificando audio con Opus: {}", e));
            }
        }

        // Esperar intervalo de audio (típicamente 20ms)
        thread::sleep(audio_interval);
    }

    add_log_to_vec(
        &logs,
        &format!("Audio sender detenido. {} paquetes enviados", packets_sent),
    );
}

/// Estructura para el hilo de recepcion RTP/RTCP.
struct ReceiverRunner {
    sock: UdpSocket,
    remote_frame: Arc<Mutex<Option<ColorImage>>>,
    logs: Arc<Mutex<Vec<String>>>,
    rtcp_logs: Arc<Mutex<Vec<String>>>,
    camera_opt: Option<Arc<Mutex<CameraHandler>>>,
    audio_muted: Arc<Mutex<bool>>,
    sending_started: Arc<Mutex<bool>>,
    local_ufrag: Option<String>,
    remote_ufrag: Option<String>,
    local_fingerprint: String,
    local_certificate: Vec<u8>,
    remote_fingerprint: Option<String>,
    packet_counter: u64,
    decoded_frames_count: u64,
    depacketizer: H264RtpDepacketizer,
    rtcp_states: HashMap<u32, RtcpRecvState>,
    reporter_ssrc: u32,
    last_rr_sent: Instant,
    last_remote_addr: Option<SocketAddr>,
    active: Arc<Mutex<bool>>,
    connection_active: Arc<Mutex<bool>>,
    cleanup_flag: Arc<Mutex<bool>>,
    last_packet_time: Instant,
    // Canales de paquetes del multiplexor
    stun_rx: Receiver<multiplexer::DemultiplexedPacket>,
    dtls_rx: Receiver<multiplexer::DemultiplexedPacket>,
    sctp_rx: Receiver<multiplexer::DemultiplexedPacket>,
    rtcp_rx: Receiver<multiplexer::DemultiplexedPacket>,
    rtp_rx: Receiver<multiplexer::DemultiplexedPacket>,
    // Flag para señalizar al multiplexor que pare
    multiplexer_active: Arc<Mutex<bool>>,

    connection_state: ConnectionState,
    srtp_receiver: Option<SrtpContext>, // Contexto SRTP para el descifrado de playload RTP

    // SCTP Data Channels
    data_channel_manager: Option<Arc<Mutex<DataChannelManager>>>,
    data_channel_config: DataChannelConfig,
    shared_dc_manager: Option<DataChannelManagerArc>,

    rtp_config: RtpConfig,
    media_config: MediaConfig,
    jitter_buffer: JitterBuffer,
    audio_jitter_buffer: JitterBuffer,
    keyframe_request: Arc<AtomicBool>,
    last_pli_sent: Instant,

    // Canales para comunicacion con el hilo de conversion RGB a RGBA
    rgb_tx: Sender<DecodedFrame>,
    rgba_rx: Receiver<RgbaFrameMsg>,

    // Canales para comunicacion con el hilo de decodificacion
    au_tx: Sender<Vec<u8>>,
    decoder_rx: Receiver<DecodeThreadMsg>,
    // Audio reception
    audio_output: Option<AudioOutput>,
    opus_decoder: Option<OpusDecoder>,
    audio_depacketizer: OpusRtpDepacketizer,
    // Sincronización audio/video
    video_sync_info: Option<StreamSyncInfo>,
    audio_sync_info: Option<StreamSyncInfo>,
}

/// Información de sincronización de stream (mapeo NTP-RTP de RTCP SR)
#[derive(Debug, Clone)]
struct StreamSyncInfo {
    _ntp_time: chrono::DateTime<chrono::Utc>,
    rtp_timestamp: u32,
    _clock_rate: u32,
}

// StreamSyncInfo no tiene métodos por ahora, se usa solo para almacenar datos

/// Implementacion de metodos para ReceiverRunner.
impl ReceiverRunner {
    /// Crea un decodificador H.264.
    #[allow(clippy::too_many_arguments)]
    fn bootstrap(
        sock: UdpSocket,
        remote_frame: Arc<Mutex<Option<ColorImage>>>,
        logs: Arc<Mutex<Vec<String>>>,
        rtcp_logs: Arc<Mutex<Vec<String>>>,
        camera_opt: Option<Arc<Mutex<CameraHandler>>>,
        audio_muted: Arc<Mutex<bool>>,
        sending_started: Arc<Mutex<bool>>,
        local_ufrag: Option<String>,
        remote_ufrag: Option<String>,
        connection_active: Arc<Mutex<bool>>,
        cleanup_flag: Arc<Mutex<bool>>,
        local_fingerprint: String,
        local_certificate: Vec<u8>,
        remote_fingerprint: Option<String>,
        dtls_role: crate::protocols::dtls::DtlsRole,
        rtp_config: RtpConfig,
        media_config: MediaConfig,
        data_channel_config: DataChannelConfig,
        multiplexer_config: MultiplexerConfig,
    ) -> Option<Self> {
        add_log_to_vec(
            &logs,
            &format!(
                "Thread de recepcion (ICE) iniciado en {}",
                sock.local_addr()
                    .ok()
                    .map(|a| a.to_string())
                    .unwrap_or_default()
            ),
        );

        let mut r = rng();
        let reporter_ssrc = loop {
            let value: u32 = r.random();
            if value != 0 {
                break value;
            }
        };

        // Canales para el hilo de decodificación
        let (au_tx, au_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let (decoder_tx, decoder_rx) = std::sync::mpsc::channel::<DecodeThreadMsg>();

        // Lanzamos el hilo de decodificación
        decode_thread::spawn_decoder_thread(au_rx, decoder_tx);

        // Crea una bandera para el multiplexor (inicia como verdadero, se establecerá como falso cuando el receptor se detenga)
        let multiplexer_active = Arc::new(Mutex::new(true));

        // Clonar socket para el multiplexor
        let sock_for_mux = sock.try_clone().ok()?;

        // Iniciar multiplexor de paquetes con la configuración proporcionada
        let channels = multiplexer::spawn_multiplexer(
            sock_for_mux,
            multiplexer_config,
            multiplexer_active.clone(),
        );

        add_log_to_vec(&logs, "Multiplexor de paquetes iniciado");

        // Canales RGB a RGBA
        let (rgb_tx, rgb_rx) = std::sync::mpsc::channel::<DecodedFrame>();
        let (rgba_tx, rgba_rx) = std::sync::mpsc::channel::<RgbaFrameMsg>();

        // Lanzar hilo RGB a RGBA
        rgb_to_rgba_thread::spawn_rgb_to_rgba_thread(rgb_rx, rgba_tx);

        Some(Self::from_parts(
            sock,
            remote_frame,
            logs,
            rtcp_logs,
            camera_opt,
            audio_muted,
            sending_started,
            local_ufrag,
            remote_ufrag,
            reporter_ssrc,
            connection_active,
            cleanup_flag,
            channels.stun,
            channels.dtls,
            channels.sctp,
            channels.rtcp,
            channels.rtp,
            multiplexer_active,
            local_fingerprint,
            local_certificate,
            remote_fingerprint,
            dtls_role,
            rtp_config.clone(),
            media_config.clone(),
            data_channel_config,
            JitterBuffer::new(20, 3),
            Arc::new(AtomicBool::new(false)),
            rgb_tx,
            rgba_rx,
            au_tx,
            decoder_rx,
        ))
    }

    /// Crea una nueva instancia de ReceiverRunner desde partes.
    fn run(&mut self) {
        loop {
            if !self.is_active() {
                break;
            }

            let mut received_packet = false;

            // Encuesta canal STUN
            if let Ok(pkt) = self.stun_rx.try_recv() {
                self.last_packet_time = Instant::now();
                self.handle_stun_from_channel(pkt);
                received_packet = true;
            }

            // Encuesta canal DTLS
            if let Ok(pkt) = self.dtls_rx.try_recv() {
                self.last_packet_time = Instant::now();
                if self.connection_state.dtls.phase == DtlsPhase::InProgress {
                    self.handle_dtls_from_channel(pkt);
                } else {
                    add_log_to_vec(
                        &self.logs,
                        &format!(
                            "DTLS packet recibido pero DTLS no inicializado: {} bytes",
                            pkt.len
                        ),
                    );
                }
                received_packet = true;
            }

            // Encuesta canal SCTP (solo cuando DTLS esté completo)
            if let Ok(pkt) = self.sctp_rx.try_recv() {
                self.last_packet_time = Instant::now();
                received_packet = true;
                if self.connection_state.dtls.phase == DtlsPhase::Complete {
                    self.handle_sctp_from_channel(pkt);
                } else {
                    add_log_to_vec(
                        &self.logs,
                        &format!(
                            "SCTP packet recibido pero DTLS no completo: {} bytes",
                            pkt.len
                        ),
                    );
                }
            }

            // Encuesta canal RTCP
            if let Ok(pkt) = self.rtcp_rx.try_recv() {
                self.last_packet_time = Instant::now();
                self.handle_rtcp_from_channel(pkt);
                received_packet = true;
            }

            // Encuesta canal RTP
            if let Ok(pkt) = self.rtp_rx.try_recv() {
                self.last_packet_time = Instant::now();
                self.handle_rtp_from_channel(pkt);
                received_packet = true;
            }

            // Drenar transmits SCTP pendientes
            if let Some(ref mut dc_manager) = self.data_channel_manager {
                loop {
                    let packet = match dc_manager.lock() {
                        Ok(mut dc) => dc.poll_transmit(),
                        Err(e) => {
                            add_log_to_vec(
                                &self.logs,
                                &format!("SCTP: Mutex en estado inconsistente: {}", e),
                            );
                            break;
                        }
                    };

                    let Some((data, addr)) = packet else {
                        break;
                    };

                    if let Err(e) = self.sock.send_to(&data, addr) {
                        add_log_to_vec(
                            &self.logs,
                            &format!("SCTP: Error enviando transmisión continua: {}", e),
                        );
                    }
                }
            }

            // Maquina de estados ICE de proceso (no bloqueante)
            if self.connection_state.ice.phase == IcePhase::InProgress {
                self.check_ice_timeouts();
            }

            // Inicializar DTLS despues de completar ICE
            if self.connection_state.ice.phase == IcePhase::Complete
                && self.connection_state.dtls.phase == DtlsPhase::NotStarted
                && let Some(role) = self.connection_state.dtls.role
            {
                self.initialize_dtls(role);
            }

            // Maquina de estados DTLS de proceso (no bloqueante)
            if self.connection_state.dtls.phase == DtlsPhase::InProgress {
                self.process_dtls_packets();
                self.check_dtls_retransmission();
            }

            // Manejar timeouts SCTP
            if self.connection_state.dtls.phase == DtlsPhase::Complete {
                self.handle_sctp_timeouts();
            }

            // Procesar mensajes del hilo de decodificacion
            self.process_decoder_messages();

            // Procesar mensajes del hilo de conversion RGBA
            self.process_rgba_messages();

            // Si no se reciben paquetes, verifique el tiempo de espera y duerma brevemente
            if !received_packet {
                if self.last_packet_time.elapsed()
                    > Duration::from_secs(self.media_config.peer_timeout_secs)
                {
                    add_log_to_vec(&self.logs, "Timeout: Peer no responde, terminando conexión");
                    // Limpio frame remoto
                    if let Ok(mut frame) = self.remote_frame.lock() {
                        *frame = None;
                    }
                    // Marcar la conexion como inactiva
                    if let Ok(mut active) = self.connection_active.lock() {
                        *active = false;
                    }
                    // Detener el hilo del sender
                    if let Ok(mut flag) = self.sending_started.lock() {
                        *flag = false;
                    }
                    // Establecer bandera de limpieza
                    if let Ok(mut flag) = self.cleanup_flag.lock() {
                        *flag = true;
                    }
                    self.stop();
                } else {
                    // Dormir brevemente para evitar largas esperas activas
                    thread::sleep(Duration::from_millis(self.media_config.poll_interval_ms));
                }
            }
        }
        add_log_to_vec(&self.logs, "Receiver detenido");
    }

    /// Procesa los mensajes recibidos del hilo de conversion RGBA.
    fn process_rgba_messages(&mut self) {
        while let Ok(msg) = self.rgba_rx.try_recv() {
            match msg {
                RgbaFrameMsg::Image { image, .. } => {
                    if let Ok(mut guard) = self.remote_frame.lock() {
                        *guard = Some(image);
                    }
                }
            }
        }
    }

    /// Verifica si el receiver esta activo.
    fn is_active(&self) -> bool {
        let active = self.active.lock().map(|g| *g).unwrap_or(false);
        let connection = self.connection_active.lock().map(|g| *g).unwrap_or(false);
        active && connection
    }

    /// Detiene el receiver y el multiplexor.
    fn stop(&mut self) {
        if let Ok(mut active) = self.active.lock() {
            *active = false;
        }
        // Multiplexor de señal para detenerse
        if let Ok(mut mux_active) = self.multiplexer_active.lock() {
            *mux_active = false;
        }

        let _ = self.au_tx.send(Vec::new());
    }

    /// Inicializa el proceso ICE con la IP y puerto remotos.
    fn initialize_ice(&mut self, remote_ip: String, remote_port: u16) {
        self.connection_state.ice.remote_ip = Some(remote_ip.clone());
        self.connection_state.ice.remote_port = Some(remote_port);
        self.connection_state.ice.phase = IcePhase::InProgress;
        add_log_to_vec(
            &self.logs,
            &format!("ICE inicializado: remote={}:{}", remote_ip, remote_port),
        );
        // Enviar la primera solicitud STUN
        self.send_next_ice_check();
    }

    /// Envía la siguiente solicitud de verificación ICE (STUN Binding Request).
    fn send_next_ice_check(&mut self) {
        if let (Some(remote_ip), Some(remote_port)) = (
            &self.connection_state.ice.remote_ip,
            self.connection_state.ice.remote_port,
        ) {
            match remote_ip.parse::<std::net::IpAddr>() {
                Ok(ip) => {
                    let peer_addr = SocketAddr::new(ip, remote_port);

                    // Generar TXID aleatorio para la solicitud STUN
                    let mut rng = rng();
                    let mut txid = [0u8; 12];
                    rng.fill_bytes(&mut txid);

                    // Crear solicitud STUN con credenciales
                    // USERNAME = local_ufrag:remote_ufrag (our ufrag : peer's ufrag)
                    let username = match (&self.local_ufrag, &self.remote_ufrag) {
                        (Some(local), Some(remote)) => Some(format!("{}:{}", local, remote)),
                        _ => None,
                    };

                    let stun_request = ice::build_stun_binding_request(&txid, username.as_deref());

                    // Almacenar el estado de verificación actual
                    self.connection_state.ice.current_check = Some(IceCheckInProgress {
                        txid,
                        _peer_addr: peer_addr,
                        sent_at: Instant::now(),
                        attempt_count: 1,
                        deadline: Instant::now() + Duration::from_millis(500),
                    });

                    // Enviar solicitud STUN
                    if let Err(err) = self.sock.send_to(&stun_request, peer_addr) {
                        add_log_to_vec(
                            &self.logs,
                            &format!("Error enviando STUN request: {}", err),
                        );
                        self.connection_state.ice.phase = IcePhase::Failed;
                        self.connection_state
                            .ice
                            .failed
                            .store(true, std::sync::atomic::Ordering::Release);
                    } else {
                        add_log_to_vec(
                            &self.logs,
                            &format!("STUN request enviado a {} (intento 1)", peer_addr),
                        );
                    }
                }
                Err(_) => {
                    add_log_to_vec(&self.logs, "IP remota inválida para ICE");
                    self.connection_state.ice.phase = IcePhase::Failed;
                    self.connection_state
                        .ice
                        .failed
                        .store(true, std::sync::atomic::Ordering::Release);
                }
            }
        }
    }

    /// Verifica los timeouts de ICE y maneja reintentos o fallos.
    fn check_ice_timeouts(&mut self) {
        let should_retry = if let Some(check) = &self.connection_state.ice.current_check {
            if Instant::now() > check.deadline {
                Some(check.attempt_count)
            } else {
                None
            }
        } else {
            None
        };

        if let Some(attempt_count) = should_retry {
            if attempt_count < 5 {
                // Reintentar con nuevo ID de transaccion
                add_log_to_vec(
                    &self.logs,
                    &format!("STUN timeout, retrying (intento {})", attempt_count + 1),
                );
                self.send_next_ice_check();
            } else {
                // Se excedio el maximo de reintentos
                add_log_to_vec(&self.logs, "STUN: máx intentos excedidos");
                self.connection_state.ice.phase = IcePhase::Failed;
                self.connection_state
                    .ice
                    .failed
                    .store(true, std::sync::atomic::Ordering::Release);
                self.connection_state.ice.current_check = None;
            }
        }
    }

    /// Marca ICE como completado exitosamente.
    fn complete_ice(&mut self) {
        self.connection_state.ice.phase = IcePhase::Complete;
        self.connection_state
            .ice
            .ready
            .store(true, std::sync::atomic::Ordering::Release);
        add_log_to_vec(&self.logs, "ICE completado exitosamente");
    }

    /// Inicializa DTLS con el rol especificado (Cliente o Servidor).
    fn initialize_dtls(&mut self, role: crate::protocols::dtls::DtlsRole) {
        let mut agent = match role {
            crate::protocols::dtls::DtlsRole::Client => DtlsAgent::new_client(
                self.local_fingerprint.clone(),
                self.remote_fingerprint.clone(),
            ),
            crate::protocols::dtls::DtlsRole::Server => DtlsAgent::new_server(
                self.local_fingerprint.clone(),
                self.remote_fingerprint.clone(),
            ),
        };

        // Establecer certificado local en el agente
        if !self.local_certificate.is_empty() {
            agent.set_local_certificate(self.local_certificate.clone());
            add_log_to_vec(
                &self.logs,
                &format!(
                    "Certificado asignado a DtlsAgent: {} bytes",
                    self.local_certificate.len()
                ),
            );
        }

        // Para el rol de Cliente, iniciar el handshake enviando ClientHello
        if matches!(role, crate::protocols::dtls::DtlsRole::Client) {
            match agent.process_packet(&[]) {
                Ok(Some(client_hello)) => {
                    add_log_to_vec(
                        &self.logs,
                        &format!(
                            "DTLS Client: ClientHello generado ({} bytes, estado: {:?})",
                            client_hello.len(),
                            agent.state
                        ),
                    );
                    // Enviar ClientHello al par remoto
                    if let (Some(remote_ip), Some(remote_port)) = (
                        self.connection_state.ice.remote_ip.as_ref(),
                        self.connection_state.ice.remote_port,
                    ) {
                        let addr = format!("{}:{}", remote_ip, remote_port);
                        if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
                            if let Err(e) = self.sock.send_to(&client_hello, socket_addr) {
                                add_log_to_vec(
                                    &self.logs,
                                    &format!("Error enviando ClientHello a {}: {}", socket_addr, e),
                                );
                            } else {
                                add_log_to_vec(
                                    &self.logs,
                                    &format!("ClientHello enviado a {}", socket_addr),
                                );
                            }
                        }
                    }
                }
                Ok(None) => {
                    add_log_to_vec(&self.logs, "DTLS Client: process_packet retornó None");
                }
                Err(e) => {
                    add_log_to_vec(&self.logs, &format!("DTLS Client error al iniciar: {}", e));
                }
            }
        }

        self.connection_state.dtls.agent = Some(agent);
        self.connection_state.dtls.phase = DtlsPhase::InProgress;
        add_log_to_vec(&self.logs, &format!("DTLS inicializado como {:?}", role));
    }

    /// Procesa los paquetes DTLS.
    fn process_dtls_packets(&mut self) {
        if let Ok(pkt) = self.dtls_rx.try_recv() {
            add_log_to_vec(
                &self.logs,
                &format!("DTLS packet recibido: {} bytes", pkt.len),
            );
            if let Some(agent) = &mut self.connection_state.dtls.agent {
                match agent.process_packet(&pkt.buffer[..pkt.len]) {
                    Ok(Some(response)) => {
                        add_log_to_vec(
                            &self.logs,
                            &format!("DTLS response generada: {} bytes", response.len()),
                        );
                        // Enviar respuesta de vuelta al par remoto
                        if let (Some(remote_ip), Some(remote_port)) = (
                            self.connection_state.ice.remote_ip.as_ref(),
                            self.connection_state.ice.remote_port,
                        ) {
                            let addr = format!("{}:{}", remote_ip, remote_port);
                            if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
                                let _ = self.sock.send_to(&response, socket_addr);
                            }
                        }
                    }
                    Ok(None) => {
                        add_log_to_vec(&self.logs, "DTLS packet procesado");
                    }
                    Err(e) => {
                        add_log_to_vec(&self.logs, &format!("DTLS error: {}", e));
                    }
                }

                if agent.is_complete() {
                    self.complete_dtls();
                }
            }
        }
    }

    /// Marca DTLS como completado exitosamente y deriva el master secret para SRTP.
    fn complete_dtls(&mut self) {
        self.connection_state.dtls.phase = DtlsPhase::Complete;
        self.connection_state
            .dtls
            .ready
            .store(true, std::sync::atomic::Ordering::Release);
        add_log_to_vec(&self.logs, "DTLS completado exitosamente");

        // Inicializar SCTP Data Channels tras DTLS completo
        if self.data_channel_config.enable_data_channels && self.data_channel_manager.is_none() {
            self.initialize_sctp_data_channels();
        }

        // Inicializar el contexto SRTP desde el master secret derivado
        if let Some(agent) = &mut self.connection_state.dtls.agent {
            match agent.compute_master_secret() {
                Ok(master_secret) => {
                    add_log_to_vec(
                        &self.logs,
                        &format!(
                            "Master secret derivado de fingerprints (longitud: {} bytes)",
                            master_secret.len()
                        ),
                    );

                    let srtp = SrtpContext::new(&master_secret);
                    self.srtp_receiver = Some(srtp);
                    add_log_to_vec(
                        &self.logs,
                        "SRTP context inicializado para decriptación de RTP",
                    );

                    // Iniciar el remitente solo si tanto ICE como DTLS están completos y tenemos la dirección remota
                    if self.connection_state.ice.phase == IcePhase::Complete
                        && let Some(addr) = self.last_remote_addr
                    {
                        self.start_sender(addr, master_secret);
                    }
                }
                Err(e) => {
                    add_log_to_vec(
                        &self.logs,
                        &format!("Error derivando master secret para SRTP: {}", e),
                    );
                }
            }
        }
    }

    /// Inicializa SCTP Data Channels tras completar DTLS
    fn initialize_sctp_data_channels(&mut self) {
        let is_initiator = matches!(
            self.connection_state.dtls.role,
            Some(crate::protocols::dtls::DtlsRole::Client)
        );

        let dc_manager = Arc::new(Mutex::new(DataChannelManager::new(
            self.data_channel_config.sctp_port,
            is_initiator,
        )));

        // Si somos el initiator, conectar al peer
        if is_initiator {
            let Some(remote_addr) = self.last_remote_addr else {
                add_log_to_vec(
                    &self.logs,
                    "SCTP: No hay dirección remota disponible para conectar",
                );
                return;
            };

            let mut dc = match dc_manager.lock() {
                Ok(dc) => dc,
                Err(e) => {
                    add_log_to_vec(
                        &self.logs,
                        &format!("SCTP: Error obteniendo lock del DataChannelManager: {}", e),
                    );
                    return;
                }
            };

            match dc.connect(remote_addr) {
                Ok(()) => {
                    add_log_to_vec(
                        &self.logs,
                        &format!("SCTP: Iniciando conexión a {}", remote_addr),
                    );
                }
                Err(e) => {
                    add_log_to_vec(&self.logs, &format!("SCTP: Error al conectar: {}", e));
                    return;
                }
            }
        } else {
            add_log_to_vec(
                &self.logs,
                "SCTP: Esperando conexión entrante (modo servidor)",
            );
        }

        self.data_channel_manager = Some(dc_manager.clone());

        if let Some(shared) = &self.shared_dc_manager
            && let Ok(mut slot) = shared.lock()
        {
            *slot = Some(dc_manager.clone());
        }

        add_log_to_vec(
            &self.logs,
            &format!(
                "SCTP Data Channels inicializados (rol: {}, puerto: {})",
                if is_initiator {
                    "initiator"
                } else {
                    "acceptor"
                },
                self.data_channel_config.sctp_port
            ),
        );
    }

    // Manejadores basados ​​en canales para paquetes demultiplexados
    fn handle_stun_from_channel(&mut self, pkt: multiplexer::DemultiplexedPacket) {
        self.last_remote_addr = Some(pkt.src_addr);

        // Primero, verifique si esto es una respuesta a nuestra solicitud STUN (para el rol de iniciador)
        if let Some(check) = &self.connection_state.ice.current_check
            && let Some(_response_addr) =
                ice::parse_stun_success_response(&pkt.buffer[..pkt.len], &check.txid)
        {
            // Obtuvimos una respuesta STUN válida a nuestra solicitud
            add_log_to_vec(
                &self.logs,
                &format!(
                    "STUN response recibida de {} después de {}ms",
                    pkt.src_addr,
                    check.sent_at.elapsed().as_millis()
                ),
            );
            self.complete_ice();
            self.connection_state.ice.current_check = None;
            // Iniciar el remitente solo si DTLS también está completo
            if self.connection_state.dtls.phase == DtlsPhase::Complete
                && let Some(agent) = &self.connection_state.dtls.agent
            {
                let master_secret = agent.get_master_secret().to_vec();
                self.start_sender(pkt.src_addr, master_secret);
            }
            return;
        }

        // De lo contrario, verifique si esto es una solicitud STUN entrante (rol de respondedor)
        if let Some(req) = ice::parse_stun_binding_request(&pkt.buffer[..pkt.len]) {
            let is_valid = match (
                self.local_ufrag.as_ref(),
                self.remote_ufrag.as_ref(),
                req.username.as_ref(),
            ) {
                (Some(local), Some(remote), Some(user)) => user == &format!("{}:{}", remote, local),
                _ => true,
            };
            if is_valid {
                let resp = ice::build_stun_success_response(&req.txid, pkt.src_addr);
                let _ = self.sock.send_to(&resp, pkt.src_addr);
                // Si somos un respondedor y recibimos una solicitud STUN, marcamos ICE como completo
                if self.connection_state.ice.phase == IcePhase::NotStarted {
                    self.complete_ice();
                    // Iniciar el remitente solo si DTLS también está completo
                    if self.connection_state.dtls.phase == DtlsPhase::Complete
                        && let Some(agent) = &self.connection_state.dtls.agent
                    {
                        let master_secret = agent.get_master_secret().to_vec();
                        self.start_sender(pkt.src_addr, master_secret);
                    }
                }
            } else {
                add_log_to_vec(&self.logs, "STUN descartado: USERNAME inválido");
            }
        }
    }

    /// Maneja paquetes DTLS recibidos del canal.
    fn handle_dtls_from_channel(&mut self, pkt: multiplexer::DemultiplexedPacket) {
        self.last_remote_addr = Some(pkt.src_addr);

        let state_before = format!(
            "{:?}",
            self.connection_state.dtls.agent.as_ref().map(|a| a.state)
        );

        add_log_to_vec(
            &self.logs,
            &format!(
                "DTLS packet recibido de {}: {} bytes (state: {})",
                pkt.src_addr, pkt.len, state_before
            ),
        );

        // Procesar paquetes DTLS con agente
        if let Some(agent) = &mut self.connection_state.dtls.agent {
            match agent.process_packet(&pkt.buffer[..pkt.len]) {
                Ok(Some(response)) => {
                    let state_after = format!("{:?}", agent.state);
                    let msg_count = if response.len() > 30 {
                        "múltiples mensajes"
                    } else {
                        "mensaje"
                    };
                    add_log_to_vec(
                        &self.logs,
                        &format!(
                            "DTLS {} generados: {} bytes (nuevo estado: {})",
                            msg_count,
                            response.len(),
                            state_after
                        ),
                    );

                    // Informe de validación del certificado de registro
                    add_log_to_vec(
                        &self.logs,
                        &format!("DTLS: {}", agent.get_validation_report()),
                    );

                    // Enviar respuesta de vuelta al par
                    match self.sock.send_to(&response, pkt.src_addr) {
                        Ok(sent) => {
                            add_log_to_vec(
                                &self.logs,
                                &format!("DTLS enviado a {}: {} bytes", pkt.src_addr, sent),
                            );
                        }
                        Err(e) => {
                            add_log_to_vec(&self.logs, &format!("Error DTLS: {}", e));
                        }
                    }
                }
                Ok(None) => {
                    let state_after = format!("{:?}", agent.state);
                    add_log_to_vec(
                        &self.logs,
                        &format!("DTLS packet procesado (nuevo estado: {})", state_after),
                    );

                    // Registrar el informe de validación del certificado si acaba de ocurrir
                    if agent.remote_certificate.is_some() {
                        add_log_to_vec(
                            &self.logs,
                            &format!("DTLS: {}", agent.get_validation_report()),
                        );
                    }
                }
                Err(e) => {
                    add_log_to_vec(&self.logs, &format!("DTLS error: {}", e));
                }
            }

            if agent.is_complete() {
                self.complete_dtls();
                add_log_to_vec(&self.logs, "DTLS handshake completado exitosamente");
            }
        }
    }

    /// Verifica si hay retransmisiones DTLS necesarias y las envía.
    fn check_dtls_retransmission(&mut self) {
        if let Some(agent) = &mut self.connection_state.dtls.agent
            && let Some(packet) = agent.check_retransmission()
        {
            add_log_to_vec(
                &self.logs,
                &format!(
                    "DTLS retransmisión: {} bytes (intento {})",
                    packet.len(),
                    agent.retransmit_count
                ),
            );

            if let (Some(remote_ip), Some(remote_port)) = (
                self.connection_state.ice.remote_ip.as_ref(),
                self.connection_state.ice.remote_port,
            ) {
                let addr = format!("{}:{}", remote_ip, remote_port);
                if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>()
                    && let Err(e) = self.sock.send_to(&packet, socket_addr)
                {
                    add_log_to_vec(&self.logs, &format!("Error retransmitiendo DTLS: {}", e));
                }
            }
        }
    }

    /// Maneja paquetes SCTP recibidos desde el multiplexor
    fn handle_sctp_from_channel(&mut self, pkt: multiplexer::DemultiplexedPacket) {
        let Some(dc_manager) = &self.data_channel_manager else {
            add_log_to_vec(
                &self.logs,
                &format!(
                    "SCTP packet recibido pero DataChannelManager no inicializado: {} bytes",
                    pkt.len
                ),
            );
            return;
        };

        let mut dc = match dc_manager.lock() {
            Ok(dc) => dc,
            Err(e) => {
                add_log_to_vec(
                    &self.logs,
                    &format!("SCTP: Error obteniendo lock del DataChannelManager: {}", e),
                );
                return;
            }
        };

        // Procesar el datagrama SCTP
        if let Err(e) = dc.handle_datagram(&pkt.buffer[..pkt.len], pkt.src_addr, Instant::now()) {
            add_log_to_vec(
                &self.logs,
                &format!("SCTP: Error procesando datagrama: {}", e),
            );
            return;
        }

        // Enviar respuestas generadas
        while let Some((data, addr)) = dc.poll_transmit() {
            if let Err(e) = self.sock.send_to(&data, addr) {
                add_log_to_vec(
                    &self.logs,
                    &format!("SCTP: Error enviando transmisión: {}", e),
                );
            }
        }
    }

    /// Maneja los timeouts de SCTP
    fn handle_sctp_timeouts(&mut self) {
        let Some(dc_manager) = &self.data_channel_manager else {
            return;
        };

        let mut dc = match dc_manager.lock() {
            Ok(dc) => dc,
            Err(e) => {
                add_log_to_vec(
                    &self.logs,
                    &format!("SCTP: Error obteniendo lock del DataChannelManager: {}", e),
                );
                return;
            }
        };

        // Verificar timeout
        if let Some(deadline) = dc.poll_timeout() {
            let now = Instant::now();

            if now >= deadline {
                dc.handle_timeout(now);

                // Enviar ACKs y retransmisiones generadas por el timeout
                while let Some((data, addr)) = dc.poll_transmit() {
                    if let Err(e) = self.sock.send_to(&data, addr) {
                        add_log_to_vec(
                            &self.logs,
                            &format!("SCTP: Error enviando transmisión de timeout: {}", e),
                        );
                    }
                }
            }
        }

        // Drenar transmisiones pendientes
        while let Some((data, addr)) = dc.poll_transmit() {
            if let Err(e) = self.sock.send_to(&data, addr) {
                add_log_to_vec(
                    &self.logs,
                    &format!("SCTP: Error enviando transmisión: {}", e),
                );
            }
        }
    }

    /// Maneja paquetes RTCP recibidos del canal.
    fn handle_rtcp_from_channel(&mut self, pkt: multiplexer::DemultiplexedPacket) {
        self.last_remote_addr = Some(pkt.src_addr);
        for rtcp_pkt in rtcp::decode_compound(&pkt.buffer[..pkt.len]) {
            match rtcp_pkt {
                rtcp::RtcpPacket::SR(sr) => self.process_sr(sr, pkt.src_addr),
                rtcp::RtcpPacket::RR(rr) => self.process_rr(rr),
                rtcp::RtcpPacket::BYE(_) => {
                    add_rtcp_log(&self.rtcp_logs, "RTCP BYE recibido, deteniendo recepción");
                    // Dejar de enviar
                    if let Ok(mut flag) = self.sending_started.lock() {
                        *flag = false;
                    }
                    // Marcar la conexion como inactiva
                    if let Ok(mut active) = self.connection_active.lock() {
                        *active = false;
                    }
                    // Borrar frame remoto
                    if let Ok(mut frame) = self.remote_frame.lock() {
                        *frame = None;
                    }
                    // Establecer la bandera de limpieza
                    if let Ok(mut flag) = self.cleanup_flag.lock() {
                        *flag = true;
                    }
                    // Dejar de enviar
                    self.stop();
                }
                rtcp::RtcpPacket::SDES(_) => {
                    // Descripción de fuente - registrar si es necesario
                }
                rtcp::RtcpPacket::PLI(_) => {
                    add_rtcp_log(&self.rtcp_logs, "PLI recibido, solicitando Keyframe");
                    self.keyframe_request
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
    }

    /// Maneja paquetes RTP recibidos del canal.
    fn handle_rtp_from_channel(&mut self, pkt: multiplexer::DemultiplexedPacket) {
        if pkt.len < 12 {
            if self
                .packet_counter
                .is_multiple_of(self.rtp_config.log_interval as u64)
            {
                add_log_to_vec(
                    &self.logs,
                    &format!(
                        "Paquete demasiado pequeño ({} bytes) desde {}",
                        pkt.len, pkt.src_addr
                    ),
                );
            }
            return;
        }

        let header = match RtpHeader::from_bytes(&pkt.buffer[..12]) {
            Ok(h) => h,
            Err(err) => {
                if self
                    .packet_counter
                    .is_multiple_of(self.rtp_config.log_interval as u64)
                {
                    add_log_to_vec(
                        &self.logs,
                        &format!("Error parseando cabecera RTP: {}", err),
                    );
                }
                return;
            }
        };

        self.packet_counter = self.packet_counter.saturating_add(1);

        if header.version != 2 {
            return;
        }

        // Determinar tipo de media segun payload type
        if header.payload_type == self.rtp_config.payload_type {
            // Video H.264 (PT=96 or 97)
            self.handle_video_rtp(header, &pkt);
        } else if header.payload_type == self.rtp_config.audio_payload_type {
            // Audio Opus (PT=111)
            self.handle_audio_rtp(header, &pkt);
        }
    }

    /// Maneja paquetes RTP de video (H.264)
    fn handle_video_rtp(&mut self, header: RtpHeader, pkt: &multiplexer::DemultiplexedPacket) {
        if self
            .packet_counter
            .is_multiple_of(self.rtp_config.log_interval as u64)
        {
            add_log_to_vec(
                &self.logs,
                &format!(
                    "Video RTP recibido: {} paquetes, ts={}",
                    self.packet_counter, header.timestamp
                ),
            );
        }

        self.update_rtcp_state(&header);

        // Descifrar payload RTP si se ha inicializado SRTP
        let payload = match self.decrypt_rtp_payload(&pkt.buffer[12..pkt.len], header.seq) {
            Some(decrypted) => decrypted,
            None => return, // Fallo en el descifrado, descartar paquete
        };

        self.jitter_buffer.push(header, payload);

        while let Some((header, payload)) = self.jitter_buffer.pop() {
            if let Some(au) = self.depacketizer.push_rtp(&header, &payload)
                && self.is_active()
            {
                let _ = self.au_tx.send(au);
            }
            self.send_periodic_rr(header.ssrc);
        }
    }

    /// Maneja paquetes RTP de audio (Opus)
    fn handle_audio_rtp(&mut self, header: RtpHeader, pkt: &multiplexer::DemultiplexedPacket) {
        // Inicializar audio output y decoder en el primer paquete de audio
        if self.audio_output.is_none() {
            match AudioOutput::new(self.media_config.audio_sample_rate, 1) {
                Ok(output) => {
                    add_log_to_vec(&self.logs, "Audio output inicializado para recepcion");
                    self.audio_output = Some(output);
                }
                Err(e) => {
                    add_log_to_vec(
                        &self.logs,
                        &format!("Error inicializando audio output: {}", e),
                    );
                    return;
                }
            }
        }

        if self.opus_decoder.is_none() {
            match OpusDecoder::new(self.media_config.audio_sample_rate, Channels::Mono) {
                Ok(decoder) => {
                    add_log_to_vec(&self.logs, "Opus decoder inicializado para recepcion");
                    self.opus_decoder = Some(decoder);
                }
                Err(e) => {
                    add_log_to_vec(
                        &self.logs,
                        &format!("Error inicializando Opus decoder: {}", e),
                    );
                    return;
                }
            }
        }

        // Descifrar payload RTP si se ha inicializado SRTP
        let payload = match self.decrypt_rtp_payload(&pkt.buffer[12..pkt.len], header.seq) {
            Some(decrypted) => decrypted,
            None => {
                add_log_to_vec(
                    &self.logs,
                    &format!("Error decrypting audio RTP payload seq={}", header.seq),
                );
                return; // Fallo en el descifrado, descartar paquete
            }
        };

        // Insertar en jitter buffer de audio
        self.audio_jitter_buffer.push(header, payload);

        // Procesar paquetes del jitter buffer en orden
        while let Some((header, payload)) = self.audio_jitter_buffer.pop() {
            // Despaquetizar RTP Opus
            let opus_data = self.audio_depacketizer.depacketize(&header, &payload);

            // Decodificar Opus a PCM
            if let Some(decoder) = &mut self.opus_decoder {
                let mut pcm_buffer = vec![0i16; self.rtp_config.audio_frame_size as usize];
                match decoder.decode(&opus_data, &mut pcm_buffer, false) {
                    Ok(_decoded_samples) => {
                        // Log A/V sync status periódicamente
                        if header.seq.is_multiple_of(self.rtp_config.log_interval)
                            && let (Some(video_sync), Some(audio_sync)) =
                                (&self.video_sync_info, &self.audio_sync_info)
                        {
                            // Calcular delay A/V usando el timestamp actual de audio
                            // Nota: necesitaríamos el timestamp de video actual para calcular delay preciso
                            // Por ahora solo registramos que tenemos información de sincronización
                            add_log_to_vec(
                                &self.logs,
                                &format!(
                                    "A/V Sync: audio_rtp={} video_baseline={} audio_baseline={}",
                                    header.timestamp,
                                    video_sync.rtp_timestamp,
                                    audio_sync.rtp_timestamp
                                ),
                            );
                        }

                        // Reproducir audio
                        if let Some(output) = &mut self.audio_output
                            && let Err(e) = output.play_samples(&pcm_buffer)
                        {
                            add_log_to_vec(
                                &self.logs,
                                &format!("Error reproduciendo audio: {}", e),
                            );
                        }
                    }
                    Err(e) => {
                        add_log_to_vec(&self.logs, &format!("Error decodificando Opus: {}", e));
                    }
                }
            }
        }
    }

    /// Procesa los mensajes del hilo de decodificación.
    fn process_decoder_messages(&mut self) {
        while let Ok(msg) = self.decoder_rx.try_recv() {
            match msg {
                DecodeThreadMsg::Frame { frame, fps, au_len } => {
                    if let Some(fps_val) = fps {
                        add_log_to_vec(
                            &self.logs,
                            &format!("FPS recibidos (decoder): {}", fps_val),
                        );
                    }

                    // Enviar decodificación RGB a hilo de conversión RGBA
                    let _ = self.rgb_tx.send(frame);

                    self.decoded_frames_count += 1;
                    if self
                        .decoded_frames_count
                        .is_multiple_of(self.rtp_config.log_interval as u64)
                    {
                        add_log_to_vec(
                            &self.logs,
                            &format!(
                                "Frame H.264 decodificado (RGB listo): {} bytes AU (frame #{})",
                                au_len, self.decoded_frames_count
                            ),
                        );
                    }
                }

                DecodeThreadMsg::Error {
                    description,
                    au_len,
                } => {
                    add_log_to_vec(
                        &self.logs,
                        &format!(
                            "Error decodificando H.264 AU ({} bytes): {}",
                            au_len, description
                        ),
                    );

                    // Pedir un PLI
                    if self.last_pli_sent.elapsed() > Duration::from_millis(200)
                        && let Some(remote) = self.last_remote_addr
                    {
                        add_log_to_vec(&self.logs, "Enviando PLI por error de decodificación");
                        let pli = rtcp::build_pli(self.reporter_ssrc, 0);
                        let _ = self.sock.send_to(&pli, remote);
                        self.last_pli_sent = Instant::now();
                    }
                }
            }
        }
    }

    /// Desencripta el payload RTP usando SRTP si está inicializado, de lo contrario utiliza el payload tal como está
    fn decrypt_rtp_payload(&self, encrypted_payload: &[u8], seq: u16) -> Option<Vec<u8>> {
        if let Some(srtp) = &self.srtp_receiver {
            match srtp.decrypt_payload(encrypted_payload, seq) {
                Ok(decrypted) => {
                    if seq.is_multiple_of(self.rtp_config.log_interval) {
                        add_log_to_vec(
                            &self.logs,
                            &format!("RTP payload decriptado exitosamente (seq={})", seq),
                        );
                    }
                    Some(decrypted)
                }
                Err(e) => {
                    if seq.is_multiple_of(self.rtp_config.log_interval) {
                        add_log_to_vec(
                            &self.logs,
                            &format!("Error decriptando RTP payload (seq={}): {}", seq, e),
                        );
                    }
                    None
                }
            }
        } else {
            // No se inicializo SRTP, retornar el payload tal como está
            Some(encrypted_payload.to_vec())
        }
    }

    /// Crea una nueva instancia de ReceiverRunner desde partes.
    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        sock: UdpSocket,
        remote_frame: Arc<Mutex<Option<ColorImage>>>,
        logs: Arc<Mutex<Vec<String>>>,
        rtcp_logs: Arc<Mutex<Vec<String>>>,
        camera_opt: Option<Arc<Mutex<CameraHandler>>>,
        audio_muted: Arc<Mutex<bool>>,
        sending_started: Arc<Mutex<bool>>,
        local_ufrag: Option<String>,
        remote_ufrag: Option<String>,
        reporter_ssrc: u32,
        connection_active: Arc<Mutex<bool>>,
        cleanup_flag: Arc<Mutex<bool>>,
        stun_rx: Receiver<multiplexer::DemultiplexedPacket>,
        dtls_rx: Receiver<multiplexer::DemultiplexedPacket>,
        sctp_rx: Receiver<multiplexer::DemultiplexedPacket>,
        rtcp_rx: Receiver<multiplexer::DemultiplexedPacket>,
        rtp_rx: Receiver<multiplexer::DemultiplexedPacket>,
        multiplexer_active: Arc<Mutex<bool>>,
        local_fingerprint: String,
        local_certificate: Vec<u8>,
        remote_fingerprint: Option<String>,
        dtls_role: crate::protocols::dtls::DtlsRole,
        rtp_config: RtpConfig,
        media_config: MediaConfig,
        data_channel_config: DataChannelConfig,
        jitter_buffer: JitterBuffer,
        keyframe_request: Arc<AtomicBool>,
        rgb_tx: Sender<DecodedFrame>,
        rgba_rx: Receiver<RgbaFrameMsg>,
        au_tx: Sender<Vec<u8>>,
        decoder_rx: Receiver<DecodeThreadMsg>,
    ) -> Self {
        Self {
            sock,
            remote_frame,
            logs,
            rtcp_logs,
            camera_opt,
            audio_muted,
            sending_started,
            local_ufrag,
            remote_ufrag,
            local_fingerprint,
            local_certificate,
            remote_fingerprint,
            packet_counter: 0,
            decoded_frames_count: 0,
            depacketizer: H264RtpDepacketizer::new(),
            rtcp_states: HashMap::new(),
            reporter_ssrc,
            last_rr_sent: Instant::now(),
            last_remote_addr: None,
            active: Arc::new(Mutex::new(true)),
            connection_active,
            cleanup_flag,
            last_packet_time: Instant::now(),
            stun_rx,
            dtls_rx,
            sctp_rx,
            rtcp_rx,
            rtp_rx,
            multiplexer_active,
            connection_state: ConnectionState {
                ice: IceState {
                    phase: IcePhase::NotStarted,
                    current_check: None,
                    ready: Arc::new(AtomicBool::new(false)),
                    failed: Arc::new(AtomicBool::new(false)),
                    remote_ip: None,
                    remote_port: None,
                },
                dtls: DtlsState {
                    phase: DtlsPhase::NotStarted,
                    ready: Arc::new(AtomicBool::new(false)),
                    _failed: Arc::new(AtomicBool::new(false)),
                    agent: None,
                    role: Some(dtls_role),
                },
            },
            srtp_receiver: None,
            data_channel_manager: None,
            data_channel_config,
            rtp_config,
            media_config,
            shared_dc_manager: None,
            jitter_buffer,
            audio_jitter_buffer: JitterBuffer::new(20, 3), // Mismo tamaño que video para sincronización
            keyframe_request,
            last_pli_sent: Instant::now(),
            rgb_tx,
            rgba_rx,
            au_tx,
            decoder_rx,
            // Audio reception (se inicializará cuando se reciban paquetes de audio)
            audio_output: None,
            opus_decoder: None,
            audio_depacketizer: OpusRtpDepacketizer::new(),
            // Inicializar sincronización A/V
            video_sync_info: None,
            audio_sync_info: None,
        }
    }

    /// Inicia el remitente para enviar medios al par remoto.
    fn start_sender(&self, src_addr: SocketAddr, master_secret: Vec<u8>) {
        let should_start = self.sending_started.lock().map(|g| !*g).unwrap_or(false);
        if !should_start {
            return;
        }
        if let Some(cam) = self.camera_opt.as_ref() {
            if let Ok(stx) = self.sock.try_clone() {
                add_log_to_vec(
                    &self.logs,
                    &format!(
                        "STUN recibido de {}, iniciando envío hacia ese par",
                        src_addr
                    ),
                );
                start_sending_on_socket(
                    stx,
                    src_addr.ip().to_string(),
                    src_addr.port(),
                    cam.clone(),
                    self.audio_muted.clone(), // Share audio_muted state with UI
                    self.logs.clone(),
                    self.rtcp_logs.clone(),
                    self.active.clone(),
                    self.connection_active.clone(),
                    master_secret,
                    self.rtp_config.clone(),
                    self.media_config.clone(),
                    self.keyframe_request.clone(),
                );
                if let Ok(mut flag) = self.sending_started.lock() {
                    *flag = true;
                }
            }
        } else {
            add_log_to_vec(&self.logs, "STUN recibido pero no hay cámara para enviar");
        }
    }

    /// Procesa un informe de remitente (SR) recibido.
    fn process_sr(&mut self, sr: rtcp::SenderReport, src_addr: SocketAddr) {
        let mid = rtcp::middle_ntp32(sr.ntp_secs, sr.ntp_frac);
        let state = self
            .rtcp_states
            .entry(sr.ssrc)
            .or_insert_with(|| RtcpRecvState::new(0));
        state.last_sr_mid = Some(mid);
        state.last_sr_arrival = Some(Instant::now());

        // Convertir NTP timestamp a chrono::DateTime
        // NTP epoch es 1900-01-01, UNIX epoch es 1970-01-01, diferencia de 2208988800 segundos
        const NTP_UNIX_EPOCH_DIFF: i64 = 2_208_988_800;
        let unix_secs = (sr.ntp_secs as i64) - NTP_UNIX_EPOCH_DIFF;
        let nanos = ((sr.ntp_frac as u64 * 1_000_000_000) >> 32) as u32;

        let ntp_time =
            chrono::DateTime::from_timestamp(unix_secs, nanos).unwrap_or_else(chrono::Utc::now);

        // Determinar si es video o audio y guardar info de sincronización
        if sr.ssrc == self.rtp_config.default_ssrc {
            // Video stream (SSRC del video)
            self.video_sync_info = Some(StreamSyncInfo {
                _ntp_time: ntp_time,
                rtp_timestamp: sr.rtp_ts,
                _clock_rate: 90000, // H.264 clock rate
            });
            add_rtcp_log(
                &self.rtcp_logs,
                &format!(
                    "Video RTCP SR: ssrc={} rtp_ts={} ntp={} pkts={} bytes={}",
                    sr.ssrc,
                    sr.rtp_ts,
                    ntp_time.format("%H:%M:%S%.3f"),
                    sr.packet_count,
                    sr.byte_count
                ),
            );
        } else if sr.ssrc == self.rtp_config.audio_ssrc {
            // Audio stream (SSRC del audio)
            self.audio_sync_info = Some(StreamSyncInfo {
                _ntp_time: ntp_time,
                rtp_timestamp: sr.rtp_ts,
                _clock_rate: self.rtp_config.audio_clock_rate,
            });
            add_rtcp_log(
                &self.rtcp_logs,
                &format!(
                    "Audio RTCP SR: ssrc={} rtp_ts={} ntp={} pkts={} bytes={}",
                    sr.ssrc,
                    sr.rtp_ts,
                    ntp_time.format("%H:%M:%S%.3f"),
                    sr.packet_count,
                    sr.byte_count
                ),
            );
        } else {
            add_rtcp_log(
                &self.rtcp_logs,
                &format!(
                    "RTCP SR recibido de ssrc={} rtp_ts={} pkts={} bytes={}",
                    sr.ssrc, sr.rtp_ts, sr.packet_count, sr.byte_count
                ),
            );
        }

        if state.received > 0 {
            let mut block = state.build_rr_block();
            block.ssrc = sr.ssrc;
            self.send_rr(src_addr, vec![block]);
        }
    }

    /// Procesa un informe de receptor (RR) recibido.
    fn process_rr(&self, rr: rtcp::ReceiverReport) {
        add_rtcp_log(
            &self.rtcp_logs,
            &format!(
                "RTCP RR recibido de ssrc={} con {} reportes",
                rr.ssrc,
                rr.reports.len()
            ),
        );
    }

    /// Actualiza el estado RTCP basado en la cabecera RTP recibida.
    fn update_rtcp_state(&mut self, header: &RtpHeader) {
        let state = self
            .rtcp_states
            .entry(header.ssrc)
            .or_insert_with(|| RtcpRecvState::new(header.seq));
        state.on_rtp(header, Instant::now());
    }

    /// Envía informes de receptor (RR) periódicos.
    fn send_periodic_rr(&mut self, ssrc: u32) {
        if self
            .last_rr_sent
            .elapsed()
            .lt(&Duration::from_secs(self.media_config.periodic_rr_secs))
        {
            return;
        }
        if let (Some(remote), Some(state)) =
            (self.last_remote_addr, self.rtcp_states.get_mut(&ssrc))
        {
            let mut block = state.build_rr_block();
            block.ssrc = ssrc;
            self.send_rr(remote, vec![block]);
            add_rtcp_log(&self.rtcp_logs, "RTCP RR enviado");
        }
        self.last_rr_sent = Instant::now();
    }

    /// Envía un informe de receptor (RR) al par remoto.
    fn send_rr(&self, remote: SocketAddr, reports: Vec<ReportBlock>) {
        let rr = ReceiverReport {
            ssrc: self.reporter_ssrc,
            reports,
        };
        let bytes = rtcp::encode_compound(&[rtcp::RtcpPacket::RR(rr)]);
        let _ = self.sock.send_to(&bytes, remote);
    }
}

/// Envía un informe de remitente (SR) junto con una descripción de fuente (SDES).
pub fn send_rtcp_sr_sdes(
    sock: &UdpSocket,
    remote_ip: &str,
    remote_port: u16,
    ssrc: u32,
    rtp_ts: u32,
    packets_sent: u32,
    bytes_sent: u32,
) {
    let cname = "roomrtc";
    let bytes = rtcp::build_sr_sdes(ssrc, rtp_ts, packets_sent, bytes_sent, cname);
    let _ = sock.send_to(&bytes, format!("{}:{}", remote_ip, remote_port));
}

/// Envía un informe de despedida (BYE) RTCP al par remoto.
pub fn send_rtcp_bye(sock: &UdpSocket, remote_ip: &str, remote_port: u16, ssrc: u32) {
    let bytes = rtcp::build_bye(ssrc, Some("session end"));
    let _ = sock.send_to(&bytes, format!("{}:{}", remote_ip, remote_port));
}
