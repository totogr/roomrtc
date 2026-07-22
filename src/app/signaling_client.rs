//! Implementacion de Signling Client para comunicacion con el servidor de senalizacion.

use crate::app::file_transfer::FileMetadata;
use crate::protocols::message::{Message, build_message, parse_message};
use crate::protocols::tls::{derive_key_from_psk, read_encrypted, write_encrypted};
use hex::encode;
use std::{
    io::BufReader,
    net::TcpStream,
    sync::{Arc, Mutex, mpsc},
    thread,
};

/// Estructura principal del Signaling Client.
#[derive(Clone)]
pub struct SignalingClient {
    // Canal para enviar mensajes al servidor.
    pub tx: mpsc::Sender<Message>,
    // Canal para recibir mensajes del servidor.
    pub rx: Arc<Mutex<mpsc::Receiver<Message>>>,
}

/// Implementacion de metodos para el Signaling Client.
impl SignalingClient {
    /// Metodo para conectar al servidor de senalizacion.
    pub fn connect(addr: &str, psk: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        let mut write_stream = stream.try_clone()?;

        let (to_server_tx, to_server_rx) = mpsc::channel::<Message>();
        let (from_server_tx, from_server_rx) = mpsc::channel::<Message>();
        let from_server_rx = Arc::new(Mutex::new(from_server_rx));

        // Derivar clave TLS desde el PSK
        let key = derive_key_from_psk(psk);
        let key_send = key;
        let key_recv = key;

        // Thread para enviar mensajes
        thread::spawn(move || {
            for msg in to_server_rx {
                let is_file_transfer = msg.msg_type.starts_with("OFFER_FILE")
                    || msg.msg_type.starts_with("ACCEPT_FILE")
                    || msg.msg_type.starts_with("REJECT_FILE");

                if is_file_transfer {
                    println!(
                        "[CLIENT] DEBUG: Procesando mensaje para enviar: {}",
                        msg.msg_type
                    );
                }

                let text = build_message(
                    &msg.msg_type,
                    &msg.fields
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.as_str()))
                        .collect::<Vec<_>>(),
                );

                match write_encrypted(&mut write_stream, &text, &key_send) {
                    Ok(_) => {
                        if is_file_transfer {
                            println!(
                                "[CLIENT] DEBUG: Mensaje {} enviado exitosamente al servidor",
                                msg.msg_type
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("[CLIENT] Error enviando mensaje: {e}");
                        break;
                    }
                }
            }
        });

        // Thread para recibir mensajes
        let read_stream = stream;
        thread::spawn(move || {
            let mut reader = BufReader::new(read_stream);

            loop {
                match read_encrypted(&mut reader, &key_recv) {
                    Ok(raw) => {
                        let is_file_transfer = raw.starts_with("OFFER_FILE")
                            || raw.starts_with("ACCEPT_FILE")
                            || raw.starts_with("REJECT_FILE");

                        if is_file_transfer {
                            println!(
                                "[CLIENT] DEBUG: Mensaje recibido del servidor (raw): {}",
                                raw
                            );
                        }

                        if let Some(msg) = parse_message(&raw) {
                            if is_file_transfer {
                                println!("[CLIENT] DEBUG: Mensaje parseado tipo: {}", msg.msg_type);
                            }
                            let _ = from_server_tx.send(msg);
                        } else if is_file_transfer {
                            println!("[CLIENT] DEBUG: No se pudo parsear el mensaje");
                        }
                    }
                    Err(e) => {
                        match e.kind() {
                            std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted => {
                                // Cierre normal
                            }
                            _ => {
                                eprintln!("[CLIENT] Error leyendo mensaje: {e}");
                            }
                        }

                        break;
                    }
                }
            }
        });

        Ok(SignalingClient {
            tx: to_server_tx,
            rx: from_server_rx,
        })
    }

    /// Abre una conexión, manda REGISTER, lee la respuesta y cierra.
    pub fn register_once(
        addr: &str,
        psk: &str,
        user: &str,
        pass: &str,
    ) -> std::io::Result<Result<(), String>> {
        // Abrimos conexión TCP directa
        let mut stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;

        // Derivamos la misma clave TLS que usa el servidor
        let key = derive_key_from_psk(psk);

        // Construimos y enviamos el mensaje REGISTER
        let msg = build_message("REGISTER", &[("username", user), ("password", pass)]);
        write_encrypted(&mut stream, &msg, &key)?;

        // Leemos una única respuesta
        let mut reader = BufReader::new(stream);
        let raw = read_encrypted(&mut reader, &key)?;

        // Parseamos
        if let Some(msg) = parse_message(&raw) {
            let tipo = msg.msg_type.as_str();
            let campo = msg.fields.get("msg").map(String::as_str);

            match (tipo, campo) {
                ("OK", Some("Registrado")) => Ok(Ok(())),
                ("ERROR", Some(m)) => Ok(Err(m.to_string())),
                ("ERROR", None) => Ok(Err("Error desconocido".into())),
                _ => Ok(Err("Respuesta inesperada del servidor".into())),
            }
        } else {
            Ok(Err("Mensaje inválido del servidor".into()))
        }
    }

    /// Metodo para enviar un mensaje al servidor.
    pub fn send(&self, msg: Message) {
        // Solo loguear mensajes de file transfer
        if msg.msg_type.starts_with("OFFER_FILE")
            || msg.msg_type.starts_with("ACCEPT_FILE")
            || msg.msg_type.starts_with("REJECT_FILE")
        {
            println!(
                "DEBUG SignalingClient: Enviando mensaje tipo: {}",
                msg.msg_type
            );
        }
        let _ = self.tx.send(msg);
    }

    /// Metodo para intentar recibir un mensaje del servidor.
    pub fn try_recv(&self) -> Option<Message> {
        let msg = self.rx.lock().ok()?.try_recv().ok();
        if let Some(ref m) = msg {
            // Solo loguear mensajes de file transfer
            if m.msg_type.starts_with("OFFER_FILE")
                || m.msg_type.starts_with("ACCEPT_FILE")
                || m.msg_type.starts_with("REJECT_FILE")
            {
                println!(
                    "DEBUG SignalingClient: Recibiendo mensaje tipo: {}",
                    m.msg_type
                );
            }
        }
        msg
    }

    /// Metodo para hacer login en el servidor.
    pub fn login(&self, user: &str, pass: &str) {
        self.send(Message {
            msg_type: "LOGIN".into(),
            fields: vec![
                ("username".into(), user.into()),
                ("password".into(), pass.into()),
            ]
            .into_iter()
            .collect(),
        });
    }

    /// Metodo para registrar un nuevo usuario en el servidor.
    pub fn register(&self, user: &str, pass: &str) {
        self.send(Message {
            msg_type: "REGISTER".into(),
            fields: vec![
                ("username".into(), user.into()),
                ("password".into(), pass.into()),
            ]
            .into_iter()
            .collect(),
        });
    }

    /// Metodo para listar usuarios conectados en el servidor.
    pub fn list_users(&self) {
        self.send(Message {
            msg_type: "LIST_USERS".into(),
            fields: Default::default(),
        });
    }

    /// Metodo para invitar a un usuario a una llamada.
    pub fn invite(&self, to: &str) {
        self.send(Message {
            msg_type: "INVITE".into(),
            fields: vec![("to".into(), to.into())].into_iter().collect(),
        });
    }

    /// Metodo para aceptar una llamada entrante.
    pub fn accept_call(&self, from: &str) {
        self.send(Message {
            msg_type: "ACCEPT_CALL".into(),
            fields: vec![("from".into(), from.into())].into_iter().collect(),
        });
    }

    /// Metodo para rechazar una llamada entrante.
    pub fn reject_call(&self, from: &str) {
        self.send(Message {
            msg_type: "REJECT_CALL".into(),
            fields: vec![("from".into(), from.into())].into_iter().collect(),
        });
    }

    /// Metodo para enviar una oferta SDP a otro usuario.
    pub fn send_offer(&self, to: &str, sdp: &str) {
        self.send(Message {
            msg_type: "OFFER".into(),
            fields: vec![("to".into(), to.into()), ("sdp".into(), sdp.into())]
                .into_iter()
                .collect(),
        });
    }

    /// Metodo para enviar una respuesta SDP a otro usuario.
    pub fn send_answer(&self, to: &str, sdp: &str) {
        self.send(Message {
            msg_type: "ANSWER".into(),
            fields: vec![("to".into(), to.into()), ("sdp".into(), sdp.into())]
                .into_iter()
                .collect(),
        });
    }

    /// Metodo para enviar un SDP local a otro usuario.
    pub fn send_local_sdp(&self, to: &str, sdp: &str) {
        self.send(Message {
            msg_type: "SDP".into(),
            fields: vec![("to".into(), to.into()), ("sdp".into(), sdp.into())]
                .into_iter()
                .collect(),
        });
    }

    /// Metodo para finalizar una llamada con otro usuario.
    pub fn end_call(&self, with: &str) {
        self.send(Message {
            msg_type: "END_CALL".into(),
            fields: vec![("with".into(), with.into())].into_iter().collect(),
        });
    }

    /// Metodo para hacer logout del servidor.
    pub fn logout(&self) {
        self.send(Message {
            msg_type: "LOGOUT".into(),
            fields: Default::default(),
        });
    }

    /// Crear una oferta de archivo
    pub fn send_offer_file(&self, to: &str, stream_id: u16, file_metadata: &FileMetadata) {
        self.send(Message {
            msg_type: "OFFER_FILE".into(),
            fields: vec![
                ("to".into(), to.into()),
                ("stream_id".into(), stream_id.to_string()),
                ("file_name".into(), file_metadata.name.clone()),
                ("file_size".into(), file_metadata.size.to_string()),
                ("file_sha256".into(), encode(file_metadata.sha256)),
            ]
            .into_iter()
            .collect(),
        });
    }

    // Crear una aceptación de archivo
    pub fn send_accept_file(&self, to: &str, stream_id: u16) {
        self.send(Message {
            msg_type: "ACCEPT_FILE".into(),
            fields: vec![
                ("to".into(), to.into()),
                ("stream_id".into(), stream_id.to_string()),
            ]
            .into_iter()
            .collect(),
        });
    }

    // Crear un rechazo de archivo
    pub fn send_reject_file(&self, to: &str, stream_id: u16, reason: &str) {
        self.send(Message {
            msg_type: "REJECT_FILE".into(),
            fields: vec![
                ("to".into(), to.into()),
                ("stream_id".into(), stream_id.to_string()),
                ("reason".into(), reason.into()),
            ]
            .into_iter()
            .collect(),
        });
    }
}
