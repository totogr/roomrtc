//! M�dulo para manejo de logs con timestamps y almacenamiento en vectores protegidos por mutex.

use chrono::Local;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Arc, Mutex};

const MAX_LOGS: usize = 500; // logs generales
const MAX_RTCP_LOGS: usize = 300; // logs RTCP

/// Estructura para manejar el almacenamiento de logs en un archivo.
pub struct Logger {
    filepath: String,
    last_index: Mutex<usize>,
}

/// Implementacion de metodos para la estructura Logger.
impl Logger {
    /// Crea una nueva instancia de Logger con la ruta del archivo especificada.
    pub fn new(filepath: String) -> Self {
        Logger {
            filepath,
            last_index: Mutex::new(0),
        }
    }

    /// Persiste los logs nuevos del vector protegido por mutex en el archivo.
    pub fn persist_logs(&self, logs: &Arc<Mutex<Vec<String>>>) {
        let logs_guard = match logs.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                eprintln!("Warning: logs mutex poisoned");
                poisoned.into_inner()
            }
        };

        let mut last_index_guard = match self.last_index.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                eprintln!("Warning: last_index mutex poisoned");
                poisoned.into_inner()
            }
        };

        if *last_index_guard >= logs_guard.len() {
            if logs_guard.is_empty() && *last_index_guard > 0 {
                *last_index_guard = 0;
            }
            return;
        }

        let mut file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.filepath)
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Error opening log file '{}': {}", self.filepath, e);
                return;
            }
        };

        for i in *last_index_guard..logs_guard.len() {
            if let Some(log) = logs_guard.get(i)
                && let Err(e) = writeln!(file, "{}", log)
            {
                eprintln!("Error writing to log file: {}", e);
            }
        }

        *last_index_guard = logs_guard.len();
    }
}

/// Agrega un log con timestamp al vector protegido por mutex y lo imprime en consola.
pub fn add_log_to_vec(logs: &Arc<Mutex<Vec<String>>>, message: &str) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    let formatted = format!("[{}] {}", timestamp, message);
    println!("{}", formatted);
    match logs.lock() {
        Ok(mut vec) => {
            if vec.len() >= MAX_LOGS {
                // eliminamos la mitad más vieja
                let drain_count = MAX_LOGS / 2;
                vec.drain(0..drain_count);
            }
            vec.push(formatted);
        }
        Err(_) => {
            eprintln!("Warning: logs mutex envenenado, se continua sin crash");
        }
    }
}

/// Agrega un log RTCP con timestamp al vector protegido por mutex.
pub fn add_rtcp_log(rtcp_logs: &Arc<Mutex<Vec<String>>>, message: &str) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    let formatted = format!("[{}] {}", timestamp, message);
    match rtcp_logs.lock() {
        Ok(mut vec) => {
            if vec.len() >= MAX_RTCP_LOGS {
                let drain_count = MAX_RTCP_LOGS / 2;
                vec.drain(0..drain_count);
            }
            vec.push(formatted);
        }
        Err(_) => {
            eprintln!("Warning: logs mutex envenenado, se continua sin crash");
        }
    }
}
