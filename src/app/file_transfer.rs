//! Transferencia de archivos sobre SCTP Data Channels
//!
//! - Divide archivos en chunks y trackea progreso
//! - Checksum SHA-256 para verificar integridad
//! - Múltiples transferencias concurrentes
//! - Serialización binaria simple (sin serde)

use crate::config::FileTransferConfig;
use crate::protocols::data_channel::DataChannelManager;
use crate::protocols::message::Message;
use hex::decode;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Eventos de transferencia de archivos
#[derive(Debug)]
pub enum FileTransferEvent {
    /// El peer ofrece un archivo
    IncomingOffer {
        stream_id: u16,
        metadata: FileMetadata,
    },

    // Inicio de descarga de archivo
    Downloading {
        stream_id: u16,
        metadata: FileMetadata,
    },

    /// Archivo recibido completamente
    Completed { stream_id: u16, file: ReceivedFile },

    /// Transferencia rechazada
    Rejected { stream_id: u16, reason: String },
}

/// Metadata de un archivo a transferir
#[derive(Debug, Clone, PartialEq)]
pub struct FileMetadata {
    pub name: String,
    pub size: u64,
    pub sha256: [u8; 32],
}

impl FileMetadata {
    /// Crea metadata desde un archivo
    pub fn from_file(path: &Path, data: &[u8]) -> Result<Self, String> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| "No se pudo extraer nombre del archivo".to_string())?
            .to_string();

        let size = data.len() as u64;

        // Calcular SHA-256
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&hash[..]);

        Ok(Self { name, size, sha256 })
    }

    /// Serializa metadata a bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let name_bytes = self.name.as_bytes();
        let name_len = name_bytes.len() as u32;

        let mut buf = Vec::with_capacity(4 + name_bytes.len() + 8 + 32);

        // name_len (4 bytes, big-endian)
        buf.extend_from_slice(&name_len.to_be_bytes());

        // name (variable length)
        buf.extend_from_slice(name_bytes);

        // size (8 bytes, big-endian)
        buf.extend_from_slice(&self.size.to_be_bytes());

        // sha256 (32 bytes)
        buf.extend_from_slice(&self.sha256);

        buf
    }

    /// Deserializa metadata desde bytes
    pub fn from_bytes(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < 4 + 8 + 32 {
            return Err("Buffer too short for metadata".to_string());
        }

        // Parse name_len
        let name_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

        if buf.len() < 4 + name_len + 8 + 32 {
            return Err("Buffer too short for name".to_string());
        }

        // Parse name
        let name_bytes = &buf[4..4 + name_len];
        let name = String::from_utf8(name_bytes.to_vec())
            .map_err(|e| format!("Invalid UTF-8 in name: {}", e))?;

        // Parse size
        let size_offset = 4 + name_len;
        let size = u64::from_be_bytes([
            buf[size_offset],
            buf[size_offset + 1],
            buf[size_offset + 2],
            buf[size_offset + 3],
            buf[size_offset + 4],
            buf[size_offset + 5],
            buf[size_offset + 6],
            buf[size_offset + 7],
        ]);

        // Parse sha256
        let sha256_offset = size_offset + 8;
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&buf[sha256_offset..sha256_offset + 32]);

        Ok(Self { name, size, sha256 })
    }
}

/// Estado de una descarga activa
#[derive(Debug)]
struct DownloadState {
    metadata: FileMetadata,
    received_bytes: Vec<u8>,
}

/// Estado de una subida activa
#[derive(Debug)]
struct UploadState {
    #[allow(dead_code)]
    metadata: FileMetadata,
    data: Vec<u8>,
    chunks_sent: usize,
    total_chunks: usize,
}

/// Archivo recibido completo
#[derive(Debug, Clone)]
pub struct ReceivedFile {
    pub metadata: FileMetadata,
    pub data: Vec<u8>,
}

impl ReceivedFile {
    /// Verifica la integridad del archivo con SHA-256
    pub fn verify_integrity(&self) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(&self.data);
        let computed_hash = hasher.finalize();

        computed_hash[..] == self.metadata.sha256
    }
}

/// Manager de alto nivel para transferencia de archivos
pub struct FileTransferManager {
    dc_manager: Arc<Mutex<DataChannelManager>>,
    pending_offers: HashMap<u16, FileMetadata>,
    active_downloads: HashMap<u16, DownloadState>,
    active_uploads: HashMap<u16, UploadState>,
    config: FileTransferConfig,
}

impl FileTransferManager {
    /// Crea un nuevo FileTransferManager con configuración
    pub fn new(dc_manager: Arc<Mutex<DataChannelManager>>, config: FileTransferConfig) -> Self {
        Self {
            dc_manager,
            pending_offers: HashMap::new(),
            active_downloads: HashMap::new(),
            active_uploads: HashMap::new(),
            config,
        }
    }

    /// Crea un nuevo FileTransferManager con configuración por defecto
    pub fn new_with_defaults(dc_manager: Arc<Mutex<DataChannelManager>>) -> Self {
        Self::new(dc_manager, FileTransferConfig::default())
    }

    /// Envía un archivo
    /// Retorna el stream_id asignado o error
    pub fn send_file(&mut self, path: &Path) -> Result<u16, String> {
        // Verificar límite de uploads concurrentes
        if self.active_uploads.len() >= self.config.max_concurrent_uploads {
            return Err(format!(
                "Máximo de uploads concurrentes alcanzado ({})",
                self.config.max_concurrent_uploads
            ));
        }

        // Leer archivo completo
        let data = std::fs::read(path).map_err(|e| format!("Error leyendo archivo: {}", e))?;

        // Verificar límite de tamaño
        let max_size_bytes = self.config.max_file_size_mb * 1024 * 1024;
        if data.len() > max_size_bytes {
            return Err(format!(
                "Archivo demasiado grande: {} MB (máximo: {} MB)",
                data.len() / (1024 * 1024),
                self.config.max_file_size_mb
            ));
        }

        // Crear metadata
        let metadata = FileMetadata::from_file(path, &data)?;
        let channel_name = metadata.name.clone();

        // Crear canal dedicado
        let stream_id = {
            let mut dc = self
                .dc_manager
                .lock()
                .map_err(|e| format!("Error lock dc_manager: {}", e))?;
            dc.create_channel(channel_name)?
        };

        let chunk_size = self.chunk_size_bytes();
        let total_chunks = data.len().div_ceil(chunk_size);

        // Registrar upload
        self.active_uploads.insert(
            stream_id,
            UploadState {
                metadata: metadata.clone(),
                data,
                chunks_sent: 0,
                total_chunks,
            },
        );

        Ok(stream_id)
    }

    /// Cierra todas las transferencias y limpia el estado
    pub fn shutdown(&mut self) {
        self.pending_offers.clear();
        self.active_downloads.clear();
        self.active_uploads.clear();

        if let Ok(mut dc) = self.dc_manager.lock() {
            dc.shutdown();
        }
    }

    /// Maneja una oferta de archivo entrante
    pub fn on_offer_file(&mut self, msg: Message) -> Result<FileTransferEvent, String> {
        let stream_id: u16 = msg
            .fields
            .get("stream_id")
            .ok_or("OFFER_FILE sin stream_id")?
            .parse()
            .map_err(|_| "stream_id inválido")?;

        let metadata = FileMetadata {
            name: msg
                .fields
                .get("file_name")
                .ok_or("OFFER_FILE sin file_name")?
                .clone(),
            size: msg
                .fields
                .get("file_size")
                .ok_or("OFFER_FILE sin file_size")?
                .parse()
                .map_err(|_| "file_size inválido")?,
            sha256: decode(
                msg.fields
                    .get("file_sha256")
                    .ok_or("OFFER_FILE sin file_sha256")?,
            )
            .map_err(|_| "sha256 inválido")?
            .try_into()
            .map_err(|_| "sha256 len inválida")?,
        };

        self.pending_offers.insert(stream_id, metadata.clone());

        Ok(FileTransferEvent::IncomingOffer {
            stream_id,
            metadata,
        })
    }

    /// Obtiene la metadata de un upload activo
    pub fn get_upload_metadata(&self, stream_id: u16) -> Option<FileMetadata> {
        self.active_uploads
            .get(&stream_id)
            .map(|u| u.metadata.clone())
    }

    /// Maneja la aceptación de una oferta de archivo
    pub fn on_accept_file(&mut self, stream_id: u16) -> Result<(), String> {
        let chunk_size = self.chunk_size_bytes();

        let upload = self
            .active_uploads
            .get(&stream_id)
            .ok_or("Upload no encontrado")?;

        let data = upload.data.clone();
        let dc_manager = self.dc_manager.clone();

        // Thread en background para no bloquear la UI
        std::thread::spawn(move || {
            use std::time::{Duration, Instant};

            let mut chunks_sent = 0;

            for chunk in data.chunks(chunk_size) {
                // Escribir chunk en SCTP
                match dc_manager.lock() {
                    Ok(mut dc) => {
                        if let Err(e) = dc.send_file_data(stream_id, chunk) {
                            eprintln!("ERROR: No se pudo enviar chunk {}: {}", chunks_sent, e);
                            return;
                        }
                    }
                    Err(_) => {
                        eprintln!("ERROR: No se pudo obtener lock para chunk {}", chunks_sent);
                        return;
                    }
                }

                chunks_sent += 1;

                // Esperar a que el chunk sea transmitido y ACKeado
                // (buffered_amount tiene que bajar antes de enviar el próximo)
                const BUFFER_THRESHOLD: usize = 512;
                const MAX_WAIT_MS: u64 = 5000;

                let wait_start = Instant::now();
                let mut last_buffered = usize::MAX;

                loop {
                    if wait_start.elapsed().as_millis() > MAX_WAIT_MS as u128 {
                        eprintln!(
                            "WARN: Timeout esperando transmisión del chunk {} (5s)",
                            chunks_sent
                        );
                        break;
                    }

                    let buffered = match dc_manager.lock() {
                        Ok(mut dc) => match dc.get_buffered_amount(stream_id) {
                            Ok(amount) => amount,
                            Err(e) => {
                                eprintln!(
                                    "WARN: Error obteniendo buffered_amount: {} - continuando",
                                    e
                                );
                                break;
                            }
                        },
                        Err(_) => {
                            eprintln!(
                                "WARN: Error obteniendo lock para buffered_amount - continuando"
                            );
                            break;
                        }
                    };

                    if last_buffered == usize::MAX
                        || buffered < last_buffered - 100
                        || buffered == 0
                    {
                        last_buffered = buffered;
                    }

                    if buffered < BUFFER_THRESHOLD {
                        break;
                    }

                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        });

        // Ya no trackear el upload porque el thread se encarga
        self.active_uploads.remove(&stream_id);

        Ok(())
    }

    pub fn poll_events(&mut self) -> Vec<FileTransferEvent> {
        let mut events = Vec::new();

        let chunks = {
            let mut dc = match self.dc_manager.lock() {
                Ok(dc) => dc,
                Err(_) => return events,
            };
            dc.poll_file_data()
        };

        for (stream_id, data) in chunks {
            let chunk_limit = self.chunk_size_bytes();

            if let Some(download) = self.active_downloads.get_mut(&stream_id) {
                let remaining = download.metadata.size as usize - download.received_bytes.len();
                let to_take = remaining.min(data.len()).min(chunk_limit);

                download.received_bytes.extend_from_slice(&data[..to_take]);

                if download.received_bytes.len() >= download.metadata.size as usize {
                    let file = ReceivedFile {
                        metadata: download.metadata.clone(),
                        data: download.received_bytes.clone(),
                    };

                    if self.config.enable_integrity_check && !file.verify_integrity() {
                        self.reject(stream_id);
                        continue;
                    }

                    self.active_downloads.remove(&stream_id);

                    events.push(FileTransferEvent::Completed { stream_id, file });
                }
            }
        }

        events
    }

    /// Obtiene el progreso de una subida (porcentaje 0-100)
    pub fn get_upload_progress(&self, stream_id: u16) -> Option<f32> {
        self.active_uploads.get(&stream_id).map(|upload| {
            if upload.total_chunks == 0 {
                100.0
            } else {
                (upload.chunks_sent as f32 / upload.total_chunks as f32) * 100.0
            }
        })
    }

    /// Obtiene el progreso de una descarga (porcentaje 0-100)
    pub fn get_download_progress(&self, stream_id: u16) -> Option<f32> {
        self.active_downloads.get(&stream_id).map(|download| {
            if download.metadata.size == 0 {
                100.0
            } else {
                (download.received_bytes.len() as f32 / download.metadata.size as f32) * 100.0
            }
        })
    }

    /// Retorna el número de descargas activas
    pub fn active_downloads_count(&self) -> usize {
        self.active_downloads.len()
    }

    /// Retorna el número de subidas activas
    pub fn active_uploads_count(&self) -> usize {
        self.active_uploads.len()
    }

    /// Devuelve los stream_ids de descargas activas
    pub fn get_active_download_streams(&self) -> Vec<u16> {
        self.active_downloads.keys().copied().collect()
    }

    /// Obtiene la configuración actual
    pub fn config(&self) -> &FileTransferConfig {
        &self.config
    }

    /// Obtiene el tamaño de chunk configurado en bytes
    pub fn chunk_size_bytes(&self) -> usize {
        self.config.chunk_size_kb * 1024
    }

    /// Acepta una oferta de archivo entrante
    pub fn accept(&mut self, stream_id: u16) {
        if let Some(metadata) = self.pending_offers.remove(&stream_id) {
            self.active_downloads.insert(
                stream_id,
                DownloadState {
                    metadata,
                    received_bytes: Vec::new(),
                },
            );
        }
    }

    /// Obtiene la metadata de una descarga activa
    pub fn get_download_metadata(&self, stream_id: u16) -> Option<FileMetadata> {
        self.active_downloads
            .get(&stream_id)
            .map(|d| d.metadata.clone())
    }

    /// Rechaza una oferta de archivo entrante o cancela una transferencia activa
    pub fn reject(&mut self, stream_id: u16) {
        self.pending_offers.remove(&stream_id);
        self.active_downloads.remove(&stream_id);
        self.active_uploads.remove(&stream_id);

        if let Ok(mut dc) = self.dc_manager.lock() {
            dc.close_stream(stream_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_serialization_roundtrip() {
        let metadata = FileMetadata {
            name: "test.txt".to_string(),
            size: 12345,
            sha256: [42u8; 32],
        };

        let bytes = metadata.to_bytes();
        let decoded = FileMetadata::from_bytes(&bytes).expect("Should decode successfully");

        assert_eq!(metadata, decoded);
    }

    #[test]
    fn test_metadata_from_bytes_too_short() {
        let buf = vec![0u8; 10]; // Too short
        let result = FileMetadata::from_bytes(&buf);

        assert!(result.is_err());
    }

    #[test]
    fn test_received_file_verify_integrity() {
        let data = b"Hello, World!";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&hash[..]);

        let file = ReceivedFile {
            metadata: FileMetadata {
                name: "test.txt".to_string(),
                size: data.len() as u64,
                sha256,
            },
            data: data.to_vec(),
        };

        assert!(file.verify_integrity());
    }

    #[test]
    fn test_received_file_verify_integrity_fails() {
        let data = b"Hello, World!";
        let wrong_hash = [99u8; 32];

        let file = ReceivedFile {
            metadata: FileMetadata {
                name: "test.txt".to_string(),
                size: data.len() as u64,
                sha256: wrong_hash,
            },
            data: data.to_vec(),
        };

        assert!(!file.verify_integrity());
    }

    #[test]
    fn test_default_chunk_size() {
        let config = FileTransferConfig::default();
        assert_eq!(config.chunk_size_kb, 64);
        assert_eq!(config.chunk_size_kb * 1024, 64 * 1024);
    }

    #[test]
    fn test_config_limits() {
        let config = FileTransferConfig::default();
        assert_eq!(config.max_file_size_mb, 100);
        assert_eq!(config.max_concurrent_uploads, 5);
        assert_eq!(config.max_concurrent_downloads, 10);
        assert!(config.enable_integrity_check);
    }
}
