//! Aplicacion de configuración y manejo para el sistema de streaming multimedia.

use std::fs;
use std::path::Path;

/// Configuración de la aplicación principal que contiene todas las configuraciones de los componentes
#[derive(Debug, Clone, Default)]
pub struct AppConfig {
    pub camera: CameraConfig,
    pub ui: UiConfig,
    pub rtp: RtpConfig,
    pub ice: IceConfig,
    pub sdp: SdpConfig,
    pub multiplexer: MultiplexerConfig,
    pub media: MediaConfig,
    pub data_channel: DataChannelConfig,
    pub file_transfer: FileTransferConfig,
    pub server: ServerConfig,
    pub logging: LoggingConfig,
    pub tls: TlsConfig,
}

/// Configuración de TLS
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub psk: String,
}

/// Logging configuration
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    pub log_file: String,
}

/// Configuracion de camara
#[derive(Debug, Clone)]
pub struct CameraConfig {
    pub resolution_width: u32,
    pub resolution_height: u32,
    pub framerate: u32,
}

/// Configuracion de UI
#[derive(Debug, Clone)]
pub struct UiConfig {
    pub frame_scaling: f32,
    pub frame_max_width: f32,
    pub frame_max_height: f32,
}

/// Configuracion de RTP
#[derive(Debug, Clone)]
pub struct RtpConfig {
    pub payload_type: u8,
    pub timestamp_step: u32,
    pub log_interval: u16,
    pub error_log_interval: u16,
    pub default_ssrc: u32,
    pub audio_payload_type: u8,
    pub audio_ssrc: u32,
    pub audio_clock_rate: u32,
    pub audio_frame_size: u32,
}

/// Configuracion de ICE
#[derive(Debug, Clone)]
pub struct IceConfig {
    pub timeout_ms: u64,
}

/// Configuracion de SDP
#[derive(Debug, Clone)]
pub struct SdpConfig {
    pub username: String,
    pub session_id: u64,
    pub session_version: u64,
    pub nettype: String,
    pub addrtype: String,
    pub enable_srflx: bool,
    pub audio_type: String,
    pub audio_protocol: String,
    pub audio_codecs: Vec<String>,
    pub audio_rtpmap: Vec<String>,
    pub audio_fmtp: Vec<String>,
    pub video_type: String,
    pub video_protocol: String,
    pub video_codecs: Vec<String>,
    pub video_rtpmap: Vec<String>,
    pub video_fmtp: Vec<String>,
}

/// Configuracion de multiplexor
#[derive(Debug, Clone)]
pub struct MultiplexerConfig {
    pub recv_timeout_ms: u64,
    pub buffer_size: usize,
}

/// Configuracion de procesamiento de media
#[derive(Debug, Clone)]
pub struct MediaConfig {
    pub periodic_rr_secs: u64,
    pub idle_sleep_ms: u64,
    pub frame_interval_ms: u64,
    pub min_packet_us: u64,
    pub send_mtu: usize,
    pub peer_timeout_secs: u64,
    pub poll_interval_ms: u64,
    pub audio_packet_interval_ms: u64,
    pub audio_sample_rate: u32,
    pub audio_bitrate: i32,
    pub video_bitrate: u32,
}

/// Configuracion de SCTP Data Channels
#[derive(Debug, Clone)]
pub struct DataChannelConfig {
    pub sctp_port: u16,
    pub enable_data_channels: bool,
}

/// Configuracion de transferencia de archivos
#[derive(Debug, Clone)]
pub struct FileTransferConfig {
    pub chunk_size_kb: usize,
    pub max_file_size_mb: usize,
    pub max_concurrent_uploads: usize,
    pub max_concurrent_downloads: usize,
    pub enable_integrity_check: bool,
}

/// Configuracion de servidor
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_address: String,
    pub max_clients: usize,
    pub users_file: String,
}

/// Implementaciones de Default para cada estructura de configuración
impl Default for CameraConfig {
    fn default() -> Self {
        Self {
            resolution_width: 1280,
            resolution_height: 720,
            framerate: 30,
        }
    }
}

/// Implementacion de Default para UiConfig
impl Default for UiConfig {
    fn default() -> Self {
        let scaling = 0.5;
        Self {
            frame_scaling: scaling,
            frame_max_width: 1280.0 * scaling,
            frame_max_height: 720.0 * scaling,
        }
    }
}

/// Implementacion de Default para RtpConfig
impl Default for RtpConfig {
    fn default() -> Self {
        Self {
            payload_type: 97,
            timestamp_step: 3_000,
            log_interval: 1000,
            error_log_interval: 10,
            default_ssrc: 12_345,
            audio_payload_type: 111,
            audio_ssrc: 54_321,
            audio_clock_rate: 48_000,
            audio_frame_size: 960,
        }
    }
}

/// Implementacion de Default para IceConfig
impl Default for IceConfig {
    fn default() -> Self {
        Self { timeout_ms: 500 }
    }
}

/// Implementacion de Default para SdpConfig
impl Default for SdpConfig {
    fn default() -> Self {
        Self {
            username: "user".to_string(),
            session_id: 123456789,
            session_version: 1,
            nettype: "IN".to_string(),
            addrtype: "IP4".to_string(),
            enable_srflx: false,
            audio_type: "audio".to_string(),
            audio_protocol: "RTP/AVP".to_string(),
            audio_codecs: vec!["0".to_string(), "111".to_string()],
            audio_rtpmap: vec!["0 PCMU/8000".to_string(), "111 opus/48000/2".to_string()],
            audio_fmtp: vec!["".to_string(), "111 minptime=10;useinbandfec=1".to_string()],
            video_type: "video".to_string(),
            video_protocol: "RTP/AVP".to_string(),
            video_codecs: vec!["96".to_string(), "97".to_string()],
            video_rtpmap: vec!["96 VP8/90000".to_string(), "97 H264/90000".to_string()],
            video_fmtp: vec![
                "".to_string(),
                "97 profile-level-id=42e01f;packetization-mode=1".to_string(),
            ],
        }
    }
}

/// Implementacion de Default para MultiplexerConfig
impl Default for MultiplexerConfig {
    fn default() -> Self {
        Self {
            recv_timeout_ms: 50,
            buffer_size: 65_535,
        }
    }
}

/// Implementacion de Default para DataChannelConfig
impl Default for DataChannelConfig {
    fn default() -> Self {
        Self {
            sctp_port: 5000,
            enable_data_channels: true,
        }
    }
}

/// Implementacion de Default para FileTransferConfig
impl Default for FileTransferConfig {
    fn default() -> Self {
        Self {
            chunk_size_kb: 64,
            max_file_size_mb: 100,
            max_concurrent_uploads: 5,
            max_concurrent_downloads: 10,
            enable_integrity_check: true,
        }
    }
}

/// Implementacion de Default para MediaConfig
impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            periodic_rr_secs: 1,
            idle_sleep_ms: 5,
            frame_interval_ms: 33,
            min_packet_us: 100,
            send_mtu: 1_200,
            peer_timeout_secs: 10,
            poll_interval_ms: 1,
            audio_packet_interval_ms: 20,
            audio_sample_rate: 48_000,
            audio_bitrate: 32_000,
            video_bitrate: 1_000_000,
        }
    }
}

/// Implementacion de Default para ServerConfig
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:7777".to_string(),
            max_clients: 10,
            users_file: "users/users.txt".to_string(),
        }
    }
}

/// Implementacion de Default para LoggingConfig
impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            log_file: "app.log".to_string(),
        }
    }
}

/// Implementacion de Default para TlsConfig
impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            psk: "default_psk".to_string(),
        }
    }
}

/// Implementacion de metodos para AppConfig
impl AppConfig {
    /// Cargar configuración desde el archivo especificado
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content =
            fs::read_to_string(path).map_err(|e| format!("Error reading config file: {}", e))?;
        Self::parse(&content)
    }

    /// Parsear el contenido del archivo de configuración
    fn parse(content: &str) -> Result<Self, String> {
        let mut config = AppConfig::default();
        let mut current_section = String::new();

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            // Omitir líneas vacías y comentarios
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Encabezados de sección
            if line.starts_with('[') && line.ends_with(']') {
                current_section = line[1..line.len() - 1].to_lowercase();
                continue;
            }

            // Pares clave=valor
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                match current_section.as_str() {
                    "camera" => parse_camera_config(&mut config.camera, key, value)
                        .map_err(|e| format!("Line {}: {}", line_num + 1, e))?,
                    "ui" => parse_ui_config(&mut config.ui, key, value)
                        .map_err(|e| format!("Line {}: {}", line_num + 1, e))?,
                    "rtp" => parse_rtp_config(&mut config.rtp, key, value)
                        .map_err(|e| format!("Line {}: {}", line_num + 1, e))?,
                    "ice" => parse_ice_config(&mut config.ice, key, value)
                        .map_err(|e| format!("Line {}: {}", line_num + 1, e))?,
                    "sdp" => parse_sdp_config(&mut config.sdp, key, value)
                        .map_err(|e| format!("Line {}: {}", line_num + 1, e))?,
                    "multiplexer" => parse_multiplexer_config(&mut config.multiplexer, key, value)
                        .map_err(|e| format!("Line {}: {}", line_num + 1, e))?,
                    "media" => parse_media_config(&mut config.media, key, value)
                        .map_err(|e| format!("Line {}: {}", line_num + 1, e))?,
                    "data_channel" => {
                        parse_data_channel_config(&mut config.data_channel, key, value)
                            .map_err(|e| format!("Line {}: {}", line_num + 1, e))?
                    }
                    "file_transfer" => {
                        parse_file_transfer_config(&mut config.file_transfer, key, value)
                            .map_err(|e| format!("Line {}: {}", line_num + 1, e))?
                    }
                    "server" => parse_server_config(&mut config.server, key, value)
                        .map_err(|e| format!("Line {}: {}", line_num + 1, e))?,
                    "logging" => parse_logging_config(&mut config.logging, key, value)
                        .map_err(|e| format!("Line {}: {}", line_num + 1, e))?,
                    "tls" => parse_tls_config(&mut config.tls, key, value)
                        .map_err(|e| format!("Line {}: {}", line_num + 1, e))?,
                    _ => {
                        return Err(format!(
                            "Line {}: Seccion invalida [{}]",
                            line_num + 1,
                            current_section
                        ));
                    }
                }
            } else {
                return Err(format!(
                    "Line {}: Valor invalido para format (expected key=value)",
                    line_num + 1
                ));
            }
        }

        Ok(config)
    }
}

/// Función para parsear la configuración de TLS
fn parse_tls_config(config: &mut TlsConfig, key: &str, value: &str) -> Result<(), String> {
    match key {
        "psk" => {
            config.psk = value.to_string();
        }
        _ => return Err(format!("Clave invalida para tls config: {}", key)),
    }
    Ok(())
}

/// Funciones auxiliares para parsear cada sección de configuración
fn parse_camera_config(config: &mut CameraConfig, key: &str, value: &str) -> Result<(), String> {
    match key {
        "resolution_width" => {
            config.resolution_width = value
                .parse()
                .map_err(|_| format!("Valor invalido para resolution_width: {}", value))?;
        }
        "resolution_height" => {
            config.resolution_height = value
                .parse()
                .map_err(|_| format!("Valor invalido para resolution_height: {}", value))?;
        }
        "framerate" => {
            config.framerate = value
                .parse()
                .map_err(|_| format!("Valor invalido para framerate: {}", value))?;
        }
        _ => return Err(format!("Clave invalida para camera config: {}", key)),
    }
    Ok(())
}

/// Función para parsear la configuración de UI
fn parse_ui_config(config: &mut UiConfig, key: &str, value: &str) -> Result<(), String> {
    match key {
        "frame_scaling" => {
            config.frame_scaling = value
                .parse()
                .map_err(|_| format!("Valor invalido para frame_scaling: {}", value))?;
            // Recalcular dimensiones máximas basadas en el escalado
            config.frame_max_width = 1280.0 * config.frame_scaling;
            config.frame_max_height = 720.0 * config.frame_scaling;
        }
        _ => return Err(format!("Clave invalida para ui config: {}", key)),
    }
    Ok(())
}

/// Función para parsear la configuración de RTP
fn parse_rtp_config(config: &mut RtpConfig, key: &str, value: &str) -> Result<(), String> {
    match key {
        "payload_type" => {
            config.payload_type = value
                .parse()
                .map_err(|_| format!("Valor invalido para payload_type: {}", value))?;
        }
        "timestamp_step" => {
            config.timestamp_step = value
                .parse()
                .map_err(|_| format!("Valor invalido para timestamp_step: {}", value))?;
        }
        "log_interval" => {
            config.log_interval = value
                .parse()
                .map_err(|_| format!("Valor invalido para log_interval: {}", value))?;
        }
        "error_log_interval" => {
            config.error_log_interval = value
                .parse()
                .map_err(|_| format!("Valor invalido para error_log_interval: {}", value))?;
        }
        "default_ssrc" => {
            config.default_ssrc = value
                .parse()
                .map_err(|_| format!("Valor invalido para default_ssrc: {}", value))?;
        }
        "audio_payload_type" => {
            config.audio_payload_type = value
                .parse()
                .map_err(|_| format!("Valor invalido para audio_payload_type: {}", value))?;
        }
        "audio_ssrc" => {
            config.audio_ssrc = value
                .parse()
                .map_err(|_| format!("Valor invalido para audio_ssrc: {}", value))?;
        }
        "audio_clock_rate" => {
            config.audio_clock_rate = value
                .parse()
                .map_err(|_| format!("Valor invalido para audio_clock_rate: {}", value))?;
        }
        "audio_frame_size" => {
            config.audio_frame_size = value
                .parse()
                .map_err(|_| format!("Valor invalido para audio_frame_size: {}", value))?;
        }
        _ => return Err(format!("Clave invalida para rtp config: {}", key)),
    }
    Ok(())
}

/// Función para parsear la configuración de ICE
fn parse_ice_config(config: &mut IceConfig, key: &str, value: &str) -> Result<(), String> {
    match key {
        "timeout_ms" => {
            config.timeout_ms = value
                .parse()
                .map_err(|_| format!("Valor invalido para timeout_ms: {}", value))?;
        }
        _ => return Err(format!("Clave invalida para ice config: {}", key)),
    }
    Ok(())
}

/// Función para parsear la configuración de SDP
fn parse_sdp_config(config: &mut SdpConfig, key: &str, value: &str) -> Result<(), String> {
    match key {
        "username" => config.username = value.to_string(),
        "session_id" => {
            config.session_id = value
                .parse()
                .map_err(|_| format!("Valor invalido para session_id: {}", value))?;
        }
        "session_version" => {
            config.session_version = value
                .parse()
                .map_err(|_| format!("Valor invalido para session_version: {}", value))?;
        }
        "nettype" => config.nettype = value.to_string(),
        "addrtype" => config.addrtype = value.to_string(),
        "enable_srflx" => {
            config.enable_srflx = value
                .parse()
                .map_err(|_| format!("Valor invalido para enable_srflx: {}", value))?;
        }
        "audio_type" => config.audio_type = value.to_string(),
        "audio_protocol" => config.audio_protocol = value.to_string(),
        "audio_codecs" => {
            config.audio_codecs = value.split(',').map(|s| s.trim().to_string()).collect();
        }
        "audio_rtpmap" => {
            config.audio_rtpmap = value.split(',').map(|s| s.trim().to_string()).collect();
        }
        "audio_fmtp" => {
            config.audio_fmtp = value.split(',').map(|s| s.trim().to_string()).collect();
        }
        "video_type" => config.video_type = value.to_string(),
        "video_protocol" => config.video_protocol = value.to_string(),
        "video_codecs" => {
            config.video_codecs = value.split(',').map(|s| s.trim().to_string()).collect();
        }
        "video_rtpmap" => {
            config.video_rtpmap = value.split(',').map(|s| s.trim().to_string()).collect();
        }
        "video_fmtp" => {
            config.video_fmtp = value.split(',').map(|s| s.trim().to_string()).collect();
        }
        _ => return Err(format!("Clave invalida para sdp config: {}", key)),
    }
    Ok(())
}

/// Función para parsear la configuración de Multiplexer
fn parse_multiplexer_config(
    config: &mut MultiplexerConfig,
    key: &str,
    value: &str,
) -> Result<(), String> {
    match key {
        "recv_timeout_ms" => {
            config.recv_timeout_ms = value
                .parse()
                .map_err(|_| format!("Valor invalido para recv_timeout_ms: {}", value))?;
        }
        "buffer_size" => {
            config.buffer_size = value
                .parse()
                .map_err(|_| format!("Valor invalido para buffer_size: {}", value))?;
        }
        _ => return Err(format!("Clave invalida para multiplexer config: {}", key)),
    }
    Ok(())
}

/// Función para parsear la configuración de Media
fn parse_media_config(config: &mut MediaConfig, key: &str, value: &str) -> Result<(), String> {
    match key {
        "periodic_rr_secs" => {
            config.periodic_rr_secs = value
                .parse()
                .map_err(|_| format!("Valor invalido para periodic_rr_secs: {}", value))?;
        }
        "idle_sleep_ms" => {
            config.idle_sleep_ms = value
                .parse()
                .map_err(|_| format!("Valor invalido para idle_sleep_ms: {}", value))?;
        }
        "frame_interval_ms" => {
            config.frame_interval_ms = value
                .parse()
                .map_err(|_| format!("Valor invalido para frame_interval_ms: {}", value))?;
        }
        "min_packet_us" => {
            config.min_packet_us = value
                .parse()
                .map_err(|_| format!("Valor invalido para min_packet_us: {}", value))?;
        }
        "send_mtu" => {
            config.send_mtu = value
                .parse()
                .map_err(|_| format!("Valor invalido para send_mtu: {}", value))?;
        }
        "peer_timeout_secs" => {
            config.peer_timeout_secs = value
                .parse()
                .map_err(|_| format!("Valor invalido para peer_timeout_secs: {}", value))?;
        }
        "poll_interval_ms" => {
            config.poll_interval_ms = value
                .parse()
                .map_err(|_| format!("Valor invalido para poll_interval_ms: {}", value))?;
        }
        "audio_packet_interval_ms" => {
            config.audio_packet_interval_ms = value
                .parse()
                .map_err(|_| format!("Valor invalido para audio_packet_interval_ms: {}", value))?;
        }
        "audio_sample_rate" => {
            config.audio_sample_rate = value
                .parse()
                .map_err(|_| format!("Valor invalido para audio_sample_rate: {}", value))?;
        }
        "audio_bitrate" => {
            config.audio_bitrate = value
                .parse()
                .map_err(|_| format!("Valor invalido para audio_bitrate: {}", value))?;
        }
        "video_bitrate" => {
            config.video_bitrate = value
                .parse()
                .map_err(|_| format!("Valor invalido para video_bitrate: {}", value))?;
        }
        _ => return Err(format!("Clave invalida para media config: {}", key)),
    }
    Ok(())
}

/// Función para parsear la configuración de Data Channel
fn parse_data_channel_config(
    config: &mut DataChannelConfig,
    key: &str,
    value: &str,
) -> Result<(), String> {
    match key {
        "sctp_port" => {
            config.sctp_port = value
                .parse()
                .map_err(|_| format!("Valor invalido para sctp_port: {}", value))?;
        }
        "enable_data_channels" => {
            config.enable_data_channels = value
                .parse()
                .map_err(|_| format!("Valor invalido para enable_data_channels: {}", value))?;
        }
        _ => return Err(format!("Clave invalida para data_channel config: {}", key)),
    }
    Ok(())
}

/// Función para parsear la configuración de File Transfer
fn parse_file_transfer_config(
    config: &mut FileTransferConfig,
    key: &str,
    value: &str,
) -> Result<(), String> {
    match key {
        "chunk_size_kb" => {
            config.chunk_size_kb = value
                .parse()
                .map_err(|_| format!("Valor invalido para chunk_size_kb: {}", value))?;
        }
        "max_file_size_mb" => {
            config.max_file_size_mb = value
                .parse()
                .map_err(|_| format!("Valor invalido para max_file_size_mb: {}", value))?;
        }
        "max_concurrent_uploads" => {
            config.max_concurrent_uploads = value
                .parse()
                .map_err(|_| format!("Valor invalido para max_concurrent_uploads: {}", value))?;
        }
        "max_concurrent_downloads" => {
            config.max_concurrent_downloads = value
                .parse()
                .map_err(|_| format!("Valor invalido para max_concurrent_downloads: {}", value))?;
        }
        "enable_integrity_check" => {
            config.enable_integrity_check = value
                .parse()
                .map_err(|_| format!("Valor invalido para enable_integrity_check: {}", value))?;
        }
        _ => return Err(format!("Clave invalida para file_transfer config: {}", key)),
    }
    Ok(())
}

/// Función para parsear la configuración del servidor
fn parse_server_config(config: &mut ServerConfig, key: &str, value: &str) -> Result<(), String> {
    match key {
        "bind_address" => {
            config.bind_address = value.to_string();
        }
        "max_clients" => {
            config.max_clients = value
                .parse()
                .map_err(|_| format!("Valor invalido para max_clients: {}", value))?;
        }
        "users_file" => {
            config.users_file = value.to_string();
        }
        _ => return Err(format!("Clave invalida para server config: {}", key)),
    }
    Ok(())
}

/// Función para parsear la configuración de Logging
fn parse_logging_config(config: &mut LoggingConfig, key: &str, value: &str) -> Result<(), String> {
    match key {
        "log_file" => {
            config.log_file = value.to_string();
        }
        _ => return Err(format!("Clave invalida para logging config: {}", key)),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.camera.resolution_width, 1280);
        assert_eq!(config.camera.resolution_height, 720);
        assert_eq!(config.camera.framerate, 30);
        assert_eq!(config.rtp.payload_type, 97);
    }

    #[test]
    fn test_parse_simple_config() {
        let content = r#"
[camera]
resolution_width=1280
resolution_height=720
framerate=60

[rtp]
payload_type=96
"#;
        let config = AppConfig::parse(content).unwrap();
        assert_eq!(config.camera.resolution_width, 1280);
        assert_eq!(config.camera.resolution_height, 720);
        assert_eq!(config.camera.framerate, 60);
        assert_eq!(config.rtp.payload_type, 96);
    }

    #[test]
    fn test_parse_with_comments() {
        let content = r#"
# Comentarios al inicio del archivo
[camera]
# Configuración de la cámara
resolution_width=800
"#;
        let config = AppConfig::parse(content).unwrap();
        assert_eq!(config.camera.resolution_width, 800);
    }
}
