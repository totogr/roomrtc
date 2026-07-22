//! Servidor de signaling WebRTC
//!
//! Módulo que encapsula la lógica del servidor de signaling para que pueda ser
//! reutilizado tanto en src/bin/server.rs como en los tests de integración.

use crate::protocols::message::{build_message, parse_message};
use crate::protocols::tls::{self, TlsKey, read_encrypted, write_encrypted};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, ErrorKind, Write},
    net::TcpStream,
    sync::{Arc, Mutex},
};

/// Estructura que representa un usuario registrado.
#[derive(Clone)]
pub struct User {
    pub username: String,
    pub password: String,
    pub state: String,
}

/// Estado compartido del servidor de signaling.
pub struct ServerState {
    pub users: HashMap<String, User>,
    pub online: HashMap<String, TcpStream>,
    pub max_clients: usize,
    pub users_file: String,
    pub tls_key: TlsKey,
}

/// Implementacion de metodos para el estado del servidor.
impl Default for ServerState {
    fn default() -> Self {
        Self::new("users/users.txt", tls::derive_key_from_psk("default_psk"))
    }
}

/// Implementacion de metodos para el estado del servidor.
impl ServerState {
    /// Carga los usuarios registrados desde un archivo.
    pub fn load_users(users_file: &str) -> HashMap<String, User> {
        let mut users = HashMap::new();

        if let Ok(file) = File::open(users_file) {
            for line in BufReader::new(file).lines().map_while(Result::ok) {
                let clean = line.trim();

                if clean.is_empty() {
                    continue;
                }

                let parts: Vec<_> = clean.split(',').map(|s| s.trim()).collect();

                if parts.len() == 2 {
                    users.insert(
                        parts[0].to_string(),
                        User {
                            username: parts[0].to_string(),
                            password: parts[1].to_string(),
                            state: "desconectado".into(),
                        },
                    );
                }
            }
        }

        users
    }

    /// Crea un nuevo estado de servidor con usuarios predefinidos.
    pub fn new_with_users(users: HashMap<String, User>, tls_key: TlsKey) -> Self {
        ServerState {
            users,
            online: HashMap::new(),
            max_clients: 10,
            users_file: String::from("users/users.txt"),
            tls_key,
        }
    }

    /// Crea un nuevo estado de servidor cargando usuarios desde un archivo.
    pub fn new(users_file: &str, tls_key: TlsKey) -> Self {
        ServerState {
            users: Self::load_users(users_file),
            online: HashMap::new(),
            max_clients: 10,
            users_file: String::from(users_file),
            tls_key,
        }
    }

    /// Guarda un nuevo usuario en el archivo y en la memoria.
    fn save_user(&mut self, username: &str, password: &str) {
        if let Some(parent) = std::path::Path::new(&self.users_file).parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            eprintln!("ERROR: No se pudo crear el directorio para usuarios: {}", e);
        }

        let res = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.users_file)
            .and_then(|mut f| writeln!(f, "{username},{password}"));

        if let Err(e) = res {
            eprintln!("ERROR: No se pudo guardar el usuario en archivo: {}", e);
        }

        self.users.insert(
            username.to_string(),
            User {
                username: username.to_string(),
                password: password.to_string(),
                state: "desconectado".into(),
            },
        );
    }

    /// Envía un mensaje a un usuario específico.
    pub fn send(&self, username: &str, msg_type: &str, fields: &[(&str, &str)]) {
        if let Some(stream) = self.online.get(username)
            && let Ok(mut clone) = stream.try_clone()
        {
            let msg = build_message(msg_type, fields);
            let _ = write_encrypted(&mut clone, &msg, &self.tls_key);
        }
    }

    /// Envía un mensaje a todos los usuarios conectados.
    pub fn broadcast(&self, msg_type: &str, fields: &[(&str, &str)]) {
        let msg = build_message(msg_type, fields);

        for stream in self.online.values() {
            if let Ok(mut s) = stream.try_clone() {
                let _ = write_encrypted(&mut s, &msg, &self.tls_key);
            }
        }
    }

    /// Genera un mensaje con la lista de usuarios y sus estados.
    pub fn user_list_message(&self) -> String {
        self.users
            .values()
            .map(|u| format!("{}:{}", u.username, u.state))
            .collect::<Vec<_>>()
            .join(";")
    }
}

/// Maneja la comunicación con un cliente conectado.
pub fn handle_client(mut stream: TcpStream, state: Arc<Mutex<ServerState>>) {
    let addr = match stream.peer_addr() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("No se pudo obtener peer_addr: {}", e);
            return;
        }
    };

    let tls_key = {
        let guard = match state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.tls_key
    };

    let mut current_user: Option<String> = None;

    loop {
        let text_msg = match read_encrypted(&mut stream, &tls_key) {
            Ok(s) => s,
            Err(e)
                if e.kind() == ErrorKind::UnexpectedEof
                    || e.kind() == ErrorKind::ConnectionAborted =>
            {
                if let Some(ref user) = current_user {
                    println!("Cliente desconectado: {user} ({addr})");
                }
                break;
            }

            Err(e) => {
                eprintln!("Error inesperado leyendo mensaje de {:?}: {e}", addr);
                break;
            }
        };

        let msg = match parse_message(&text_msg) {
            Some(m) => m,
            None => continue,
        };

        let msg_type = msg.msg_type.as_str();
        let mut state = match state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        match msg_type {
            // Registro de nuevo usuario
            "REGISTER" => {
                let user = msg.fields.get("username").map(String::as_str);
                let pass = msg.fields.get("password").map(String::as_str);

                if let (Some(u), Some(p)) = (user, pass) {
                    if state.users.contains_key(u) {
                        let _ = write_encrypted(
                            &mut stream,
                            &build_message("ERROR", &[("msg", "Ya existe")]),
                            &tls_key,
                        );
                    } else {
                        state.save_user(u, p);
                        let _ = write_encrypted(
                            &mut stream,
                            &build_message("OK", &[("msg", "Registrado")]),
                            &tls_key,
                        );
                    }
                }
                return;
            }
            // Login de usuario existente
            "LOGIN" => {
                let user = msg.fields.get("username").map(String::as_str);
                let pass = msg.fields.get("password").map(String::as_str);

                if state.online.len() >= state.max_clients {
                    let _ = write_encrypted(
                        &mut stream,
                        &build_message("ERROR", &[("msg", "Servidor lleno")]),
                        &tls_key,
                    );
                    continue;
                }

                if let (Some(u), Some(p)) = (user, pass) {
                    if state.online.contains_key(u) {
                        let _ = write_encrypted(
                            &mut stream,
                            &build_message("ERROR", &[("msg", "Usuario ya conectado")]),
                            &tls_key,
                        );
                        continue;
                    }

                    if let Some(stored) = state.users.get(u) {
                        if stored.password == p {
                            let u_owned = u.to_string();

                            let cloned_stream = match stream.try_clone() {
                                Ok(c) => c,
                                Err(e) => {
                                    eprintln!("ERROR al clonar stream {u_owned}: {e}");
                                    continue;
                                }
                            };

                            state.online.insert(u_owned.clone(), cloned_stream);

                            if let Some(uobj) = state.users.get_mut(&u_owned) {
                                uobj.state = "disponible".into();
                            }

                            current_user = Some(u_owned.clone());

                            let _ = write_encrypted(
                                &mut stream,
                                &build_message("OK", &[("msg", "Login exitoso")]),
                                &tls_key,
                            );

                            let list = state.user_list_message();
                            state.broadcast("USER_LIST", &[("list", &list)]);
                        } else {
                            let _ = write_encrypted(
                                &mut stream,
                                &build_message("ERROR", &[("msg", "Contrasena incorrecta")]),
                                &tls_key,
                            );
                        }
                    } else {
                        let _ = write_encrypted(
                            &mut stream,
                            &build_message("ERROR", &[("msg", "Usuario no existe")]),
                            &tls_key,
                        );
                    }
                }
            }
            // Solicitud de lista de usuarios
            "LIST_USERS" => {
                let list = state.user_list_message();
                let msg = build_message("USER_LIST", &[("list", &list)]);
                let _ = write_encrypted(&mut stream, &msg, &tls_key);
            }
            // Invitación a llamada
            "INVITE" => {
                let from = match &current_user {
                    Some(u) => u.clone(),
                    None => continue,
                };
                let to = match msg.fields.get("to") {
                    Some(s) => s.clone(),
                    None => continue,
                };

                if !state.users.contains_key(&to) {
                    let _ = write_encrypted(
                        &mut stream,
                        &build_message("ERROR", &[("msg", "Usuario no existe")]),
                        &tls_key,
                    );
                    continue;
                }

                if from == to {
                    let _ = write_encrypted(
                        &mut stream,
                        &build_message("ERROR", &[("msg", "No puedes llamarte a ti mismo")]),
                        &tls_key,
                    );
                    continue;
                }

                if let Some(user) = state.users.get_mut(&from) {
                    user.state = "ocupado".into();
                } else {
                    eprintln!(
                        "WARNING: No se encontró al usuario '{from}' para marcarlo como ocupado"
                    );
                }

                if let Some(user) = state.users.get_mut(&to) {
                    user.state = "ocupado".into();
                } else {
                    eprintln!(
                        "WARNING: No se encontró al usuario '{to}' para marcarlo como ocupado"
                    );
                }

                let list = state.user_list_message();
                state.broadcast("USER_LIST", &[("list", &list)]);

                state.send(&to, "INCOMING_CALL", &[("from", &from)]);
            }
            // Aceptación de llamada
            "ACCEPT_CALL" => {
                let accepter = match current_user.clone() {
                    Some(u) => u,
                    None => {
                        eprintln!("WARNING: ACCEPT_CALL recibido sin usuario logueado");
                        continue;
                    }
                };

                let caller = match msg.fields.get("from") {
                    Some(v) => v.clone(),
                    None => continue,
                };

                if accepter == caller {
                    let _ = write_encrypted(
                        &mut stream,
                        &build_message("ERROR", &[("msg", "No podes aceptar tu propia llamada")]),
                        &tls_key,
                    );
                    continue;
                }

                state.send(&caller, "CALL_ACCEPTED", &[("by", &accepter)]);
                state.send(&accepter, "CALL_ESTABLISHED", &[("with", &caller)]);
            }
            // Rechazo de llamada
            "REJECT_CALL" => {
                let rejecter = match current_user.clone() {
                    Some(u) => u,
                    None => {
                        eprintln!("WARNING: REJECT_CALL recibido sin usuario logueado");
                        continue;
                    }
                };

                let caller = match msg.fields.get("from") {
                    Some(v) => v.clone(),
                    None => continue,
                };

                state.send(&caller, "CALL_REJECTED", &[("by", &rejecter)]);

                if let Some(u) = state.users.get_mut(&rejecter) {
                    u.state = "disponible".into();
                } else {
                    eprintln!("WARNING: Usuario '{rejecter}' no encontrado en state.users");
                }

                if let Some(u) = state.users.get_mut(&caller) {
                    u.state = "disponible".into();
                } else {
                    eprintln!("WARNING: Usuario '{caller}' no encontrado en state.users");
                }

                let list = state.user_list_message();
                state.broadcast("USER_LIST", &[("list", &list)]);
            }
            // Mensajes de señalización WebRTC
            "OFFER" | "ANSWER" | "SDP" | "CANDIDATE" => {
                let to = match msg.fields.get("to") {
                    Some(v) => v.clone(),
                    None => continue,
                };

                let mut fields_out = Vec::new();
                for (k, v) in &msg.fields {
                    fields_out.push((k.as_str(), v.as_str()));
                }

                state.send(&to, msg_type, &fields_out);
            }
            // Mensajes de transferencia de archivos
            "OFFER_FILE" | "ACCEPT_FILE" | "REJECT_FILE" => {
                let to = match msg.fields.get("to") {
                    Some(v) => v.clone(),
                    None => {
                        continue;
                    }
                };

                let from = match &current_user {
                    Some(u) => u.clone(),
                    None => {
                        continue;
                    }
                };

                let mut fields_out = Vec::new();
                fields_out.push(("from", from.as_str()));

                for (k, v) in &msg.fields {
                    if k != "to" {
                        fields_out.push((k.as_str(), v.as_str()));
                    }
                }

                state.send(&to, msg_type, &fields_out);
            }
            // Finalización de llamada
            "END_CALL" => {
                let sender = match current_user.clone() {
                    Some(u) => u,
                    None => {
                        eprintln!("WARNING: END_CALL recibido sin usuario logueado");
                        continue;
                    }
                };

                let with = match msg.fields.get("with") {
                    Some(v) => v.clone(),
                    None => continue,
                };

                state.send(&with, "CALL_ENDED", &[("with", &sender)]);

                if let Some(u) = state.users.get_mut(&sender) {
                    u.state = "disponible".into();
                } else {
                    eprintln!("WARNING: Usuario '{sender}' no encontrado en state.users");
                }

                if let Some(u) = state.users.get_mut(&with) {
                    u.state = "disponible".into();
                } else {
                    eprintln!("WARNING: Usuario '{with}' no encontrado en state.users");
                }

                let list = state.user_list_message();
                state.broadcast("USER_LIST", &[("list", &list)]);
            }
            // Logout de usuario
            "LOGOUT" => {
                if let Some(user) = current_user.clone() {
                    if let Some(u) = state.users.get_mut(&user) {
                        u.state = "desconectado".into();
                    } else {
                        eprintln!(
                            "WARNING: Logout recibido pero usuario '{user}' no existe en users"
                        );
                    }
                    state.online.remove(&user);

                    let list = state.user_list_message();
                    state.broadcast("USER_LIST", &[("list", &list)]);
                }
                break;
            }
            _ => {}
        }
    }

    if let Some(user) = current_user {
        println!("Cliente desconectado: {user} ({addr})");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistence_creates_directory() {
        let temp_dir = "temp_users_test";
        let users_file = format!("{}/users.txt", temp_dir);

        // Ensure clean state
        if std::path::Path::new(temp_dir).exists() {
            std::fs::remove_dir_all(temp_dir).unwrap();
        }

        let mut state = ServerState::new(&users_file, tls::derive_key_from_psk("test_psk"));
        state.save_user("testuser", "testpass");

        assert!(std::path::Path::new(temp_dir).exists());
        assert!(std::path::Path::new(&users_file).exists());

        let content = std::fs::read_to_string(&users_file).unwrap();
        assert!(content.contains("testuser,testpass"));

        // Cleanup
        std::fs::remove_dir_all(temp_dir).unwrap();
    }
}
