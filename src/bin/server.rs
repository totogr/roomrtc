//! Aplicacion de servidor para RoomRTC que maneja la señalización entre clientes.

use roomrtc::{
    config::AppConfig,
    protocols::tls,
    signaling_server::{ServerState, handle_client},
};
use std::{
    collections::HashMap,
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
};

/// Función principal que inicia el servidor de señalización.
fn main() {
    // Cargar configuración desde archivo o usar valores por defecto
    let args: Vec<String> = std::env::args().collect();
    let config_path = if args.len() > 1 {
        args[1].clone()
    } else {
        format!("{}/config.conf", env!("CARGO_MANIFEST_DIR"))
    };

    let config = match AppConfig::from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error cargando configuracion desde {}: {}", config_path, e);
            eprintln!("Usando valores por defecto");
            AppConfig::default()
        }
    };

    let listener = match TcpListener::bind(&config.server.bind_address) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "No se pudo iniciar el servidor en {}: {}",
                config.server.bind_address, e
            );
            return;
        }
    };
    println!(
        "Servidor de signaling iniciado en {}",
        config.server.bind_address
    );

    // Estado compartido del servidor

    let tls_key = tls::derive_key_from_psk(&config.tls.psk);

    let state = Arc::new(Mutex::new(ServerState {
        users: ServerState::load_users(&config.server.users_file),
        online: HashMap::new(),
        max_clients: config.server.max_clients,
        users_file: config.server.users_file.clone(),
        tls_key,
    }));

    // Aceptar conexiones entrantes
    for incoming in listener.incoming() {
        match incoming {
            Ok(conn) => {
                let state_clone = Arc::clone(&state);
                thread::spawn(move || handle_client(conn, state_clone));
            }
            Err(e) => {
                eprintln!("Error aceptando conexion entrante: {}", e);
                continue;
            }
        }
    }
}
