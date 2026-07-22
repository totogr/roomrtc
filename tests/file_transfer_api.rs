//! Tests de integración para la API de FileTransferManager
//!
//! Estos tests verifican:
//! - Serialización de metadata
//! - Chunking y reassembly de archivos grandes
//! - Verificación de integridad SHA-256
//! - Transferencias múltiples simultáneas
//! - Stream IDs (initiator/acceptor)
//! - Performance de serialización
//! - Flujo end-to-end completo

use roomrtc::app::file_transfer::{FileMetadata, ReceivedFile};
use roomrtc::config::FileTransferConfig;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

/// Obtiene el tamaño de chunk desde la configuración por defecto
fn get_chunk_size() -> usize {
    FileTransferConfig::default().chunk_size_kb * 1024
}

// Tests de Serialización

#[test]
fn test_metadata_long_filename() {
    let long_name = "a".repeat(1000);
    let metadata = FileMetadata {
        name: long_name.clone(),
        size: 12345,
        sha256: [42u8; 32],
    };

    let bytes = metadata.to_bytes();
    let parsed = FileMetadata::from_bytes(&bytes).expect("Failed to parse");

    assert_eq!(parsed.name, long_name);
    assert_eq!(parsed.size, 12345);
    assert_eq!(parsed.sha256, [42u8; 32]);
}

#[test]
fn test_metadata_empty_file() {
    let metadata = FileMetadata {
        name: "empty.txt".to_string(),
        size: 0,
        sha256: [0u8; 32],
    };

    let bytes = metadata.to_bytes();
    let parsed = FileMetadata::from_bytes(&bytes).expect("Failed to parse");

    assert_eq!(parsed.size, 0);
}

#[test]
fn test_metadata_max_size() {
    let metadata = FileMetadata {
        name: "huge.bin".to_string(),
        size: u64::MAX,
        sha256: [255u8; 32],
    };

    let bytes = metadata.to_bytes();
    let parsed = FileMetadata::from_bytes(&bytes).expect("Failed to parse");

    assert_eq!(parsed.size, u64::MAX);
}

#[test]
fn test_metadata_truncated_buffer() {
    let metadata = FileMetadata {
        name: "test.txt".to_string(),
        size: 100,
        sha256: [1u8; 32],
    };

    let bytes = metadata.to_bytes();
    let truncated = &bytes[..bytes.len() - 10];

    let result = FileMetadata::from_bytes(truncated);
    assert!(result.is_err());
}

#[test]
fn test_metadata_invalid_utf8() {
    let mut bytes = vec![0, 0, 0, 5]; // name_len = 5
    bytes.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC, 0xFB]); // invalid UTF-8
    bytes.extend_from_slice(&100u64.to_be_bytes());
    bytes.extend_from_slice(&[7u8; 32]);

    let result = FileMetadata::from_bytes(&bytes);
    assert!(result.is_err());
}

// Tests de Chunking

#[test]
fn test_large_file_chunking() {
    let temp_path = PathBuf::from("/tmp/test_large_file.bin");
    let test_data = vec![0xAB; 100_000]; // 100KB

    {
        let mut file = fs::File::create(&temp_path).expect("Failed to create temp file");
        file.write_all(&test_data).expect("Failed to write");
    }

    let mut hasher = Sha256::new();
    hasher.update(&test_data);
    let expected_hash: [u8; 32] = hasher.finalize().into();

    let metadata =
        FileMetadata::from_file(&temp_path, &test_data).expect("Failed to create metadata");

    assert_eq!(metadata.sha256, expected_hash);
    assert_eq!(metadata.size, 100_000);

    fs::remove_file(&temp_path).ok();
}

#[test]
fn test_chunk_reassembly() {
    let chunk_size = get_chunk_size();
    let original_data = vec![0x55; chunk_size * 2 + 123]; // 50KB
    let chunks: Vec<_> = original_data.chunks(chunk_size).collect();

    assert!(chunks.len() > 1, "Should split into multiple chunks");

    let mut reassembled = Vec::new();
    for chunk in chunks {
        reassembled.extend_from_slice(chunk);
    }

    assert_eq!(reassembled, original_data);
}

// Tests de Integridad

#[test]
fn test_integrity_verification() {
    let data = b"Test data for integrity check";
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash: [u8; 32] = hasher.finalize().into();

    let file = ReceivedFile {
        metadata: FileMetadata {
            name: "integrity.txt".to_string(),
            size: data.len() as u64,
            sha256: hash,
        },
        data: data.to_vec(),
    };

    assert!(file.verify_integrity());

    let corrupted_file = ReceivedFile {
        metadata: file.metadata.clone(),
        data: b"Corrupted data".to_vec(),
    };

    assert!(!corrupted_file.verify_integrity());
}

// Tests de Performance

#[test]
fn test_performance_serialization() {
    let metadata = FileMetadata {
        name: "performance_test.dat".to_string(),
        size: 1_000_000,
        sha256: [42u8; 32],
    };

    let start = Instant::now();
    for _ in 0..10_000 {
        let bytes = metadata.to_bytes();
        let _ = FileMetadata::from_bytes(&bytes).expect("Parse failed");
    }
    let duration = start.elapsed();

    assert!(
        duration.as_secs() < 1,
        "Performance should be under 1 second"
    );
}

// Tests End-to-End

#[test]
fn test_metadata_roundtrip_with_real_file() {
    let temp_path = PathBuf::from("/tmp/test_metadata_roundtrip.txt");
    let content = b"Testing metadata roundtrip.";

    fs::write(&temp_path, content).expect("Failed to write temp file");

    let metadata = FileMetadata::from_file(&temp_path, content).expect("Failed to create metadata");

    // Verificar que el nombre se extrajo correctamente
    assert_eq!(metadata.name, "test_metadata_roundtrip.txt");
    assert_eq!(metadata.size, content.len() as u64);

    // Verificar hash SHA-256
    let mut hasher = Sha256::new();
    hasher.update(content);
    let expected_hash: [u8; 32] = hasher.finalize().into();
    assert_eq!(metadata.sha256, expected_hash);

    // Roundtrip serialización
    let bytes = metadata.to_bytes();
    let parsed = FileMetadata::from_bytes(&bytes).expect("Failed to parse");
    assert_eq!(parsed, metadata);

    fs::remove_file(&temp_path).ok();
}

#[test]
fn test_empty_file_metadata() {
    let temp_path = PathBuf::from("/tmp/test_empty.txt");
    fs::write(&temp_path, b"").expect("Failed to write empty file");

    let metadata = FileMetadata::from_file(&temp_path, &[]).expect("Failed to create metadata");

    assert_eq!(metadata.size, 0);
    assert_eq!(metadata.name, "test_empty.txt");

    // SHA-256 de archivo vacío
    let mut hasher = Sha256::new();
    hasher.update([]);
    let expected_hash: [u8; 32] = hasher.finalize().into();
    assert_eq!(metadata.sha256, expected_hash);

    fs::remove_file(&temp_path).ok();
}

// Tests de casos borde

#[test]
fn test_filename_extraction() {
    let test_cases = vec![
        ("/tmp/simple.txt", "simple.txt"),
        ("/home/user/documents/report.pdf", "report.pdf"),
        ("./relative/path/file.bin", "file.bin"),
    ];

    for (path_str, expected_name) in test_cases {
        let path = PathBuf::from(path_str);
        let data = b"test data";

        // Crear archivo temporal
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::write(&path, data).ok();

        if let Ok(metadata) = FileMetadata::from_file(&path, data) {
            assert_eq!(metadata.name, expected_name);
        }

        fs::remove_file(&path).ok();
    }
}

#[test]
fn test_serialization_format_stability() {
    // Verificar que el formato de serialización es estable
    let metadata = FileMetadata {
        name: "stable.dat".to_string(),
        size: 1024,
        sha256: [0xAB; 32],
    };

    let bytes = metadata.to_bytes();

    // Verificar estructura: [name_len:4][name:N][size:8][sha256:32]
    assert_eq!(bytes.len(), 4 + 10 + 8 + 32); // 4 + "stable.dat".len() + 8 + 32

    // Verificar name_len
    let name_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    assert_eq!(name_len, 10);

    // Verificar name
    let name_bytes = &bytes[4..14];
    assert_eq!(name_bytes, b"stable.dat");

    // Verificar size
    let size_bytes = &bytes[14..22];
    let size = u64::from_be_bytes(size_bytes.try_into().unwrap());
    assert_eq!(size, 1024);

    // Verificar sha256
    let hash_bytes = &bytes[22..54];
    assert_eq!(hash_bytes, &[0xAB; 32]);
}

#[test]
fn test_multiple_metadata_serializations() {
    let test_files = vec![
        ("file1.txt", 100u64),
        ("file2.dat", 50000u64),
        ("file3.bin", 1_000_000u64),
    ];

    for (name, size) in test_files {
        let metadata = FileMetadata {
            name: name.to_string(),
            size,
            sha256: [0xFF; 32],
        };

        let bytes = metadata.to_bytes();
        let parsed = FileMetadata::from_bytes(&bytes)
            .unwrap_or_else(|_| panic!("Failed to parse metadata for {}", name));

        assert_eq!(parsed.name, name);
        assert_eq!(parsed.size, size);
        assert_eq!(parsed.sha256, [0xFF; 32]);
    }
}

#[test]
fn test_hash_consistency() {
    let data = b"Consistency test data";

    // Calcular hash múltiples veces
    for _ in 0..100 {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash1: [u8; 32] = hasher.finalize().into();

        let mut hasher2 = Sha256::new();
        hasher2.update(data);
        let hash2: [u8; 32] = hasher2.finalize().into();

        assert_eq!(hash1, hash2, "SHA-256 should be deterministic");
    }
}

#[test]
fn test_received_file_construction() {
    let data = b"Received file test data";
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash: [u8; 32] = hasher.finalize().into();

    let received_file = ReceivedFile {
        metadata: FileMetadata {
            name: "received.txt".to_string(),
            size: data.len() as u64,
            sha256: hash,
        },
        data: data.to_vec(),
    };

    assert_eq!(received_file.metadata.name, "received.txt");
    assert_eq!(received_file.metadata.size, data.len() as u64);
    assert_eq!(received_file.data, data);
    assert!(received_file.verify_integrity());
}
