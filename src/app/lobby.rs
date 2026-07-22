//! Modulo encargado de gestionar la pantalla del lobby de la aplicacion.

use super::signaling_client::SignalingClient;
use crate::app::AppScreen;
use crate::config::AppConfig;
use eframe::egui;
use std::sync::{Arc, Mutex};

/// Estructura principal de la pantalla del lobby.
pub struct LobbyApp {
    pub client: Option<SignalingClient>,
    pub pending_client: Option<SignalingClient>,
    pub username: String,
    pub password: String,
    pub server_addr: String,
    pub users: Arc<Mutex<Vec<(String, String)>>>,
    pub incoming_call: Option<String>,
    pub login_error: Option<String>,
    pub call_error: Option<String>,
    pub register_success: Option<String>,
    pub current_peer: Option<String>,
    pub next_screen: Option<AppScreen>,
    pub is_caller: bool,
    pub tls_psk: String,
}

/// Implementacion de metodos para la estructura LobbyApp.
impl Default for LobbyApp {
    /// Metodo para crear una instancia por defecto de LobbyApp.
    fn default() -> Self {
        Self {
            client: None,
            pending_client: None,
            username: String::new(),
            password: String::new(),
            server_addr: String::new(),
            users: Arc::new(Mutex::new(Vec::new())),
            incoming_call: None,
            login_error: None,
            call_error: None,
            register_success: None,
            current_peer: None,
            next_screen: None,
            is_caller: false,
            tls_psk: String::new(),
        }
    }
}

/// Implementacion de la aplicacion eframe para LobbyApp.
impl eframe::App for LobbyApp {
    /// Metodo principal de actualizacion de la interfaz grafica.
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        // Dibuja el panel central de la aplicacion.
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.client.is_none() {
                self.draw_login(ui);
            } else {
                self.draw_lobby(ui);
            }
        });

        // Procesa los mensajes entrantes del cliente de señalizacion.
        self.poll_messages();

        // Solicita un repintado de la interfaz grafica despues de 200 ms.
        ctx.request_repaint_after(std::time::Duration::from_millis(200));
    }
}

/// Implementacion de metodos adicionales para LobbyApp.
impl LobbyApp {
    /// Crea una nueva instancia de LobbyApp con la configuracion dada.
    pub fn with_config(config: &AppConfig) -> Self {
        LobbyApp {
            server_addr: config.server.bind_address.clone(),
            tls_psk: config.tls.psk.clone(),
            ..Default::default()
        }
    }

    /// Dibuja la pantalla de inicio de sesion.
    fn draw_login(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.heading(egui::RichText::new("Iniciar sesión").size(32.0));
            ui.add_space(10.0);

            ui.label(egui::RichText::new("Servidor:").size(20.0));
            ui.add(
                egui::TextEdit::singleline(&mut self.server_addr)
                    .desired_width(300.0)
                    .font(egui::TextStyle::Heading),
            );
            ui.add_space(10.0);

            ui.label(egui::RichText::new("Usuario:").size(20.0));
            ui.add(
                egui::TextEdit::singleline(&mut self.username)
                    .desired_width(300.0)
                    .font(egui::TextStyle::Heading),
            );
            ui.add_space(10.0);

            ui.label(egui::RichText::new("Contraseña:").size(20.0));
            ui.add(
                egui::TextEdit::singleline(&mut self.password)
                    .desired_width(300.0)
                    .password(true)
                    .font(egui::TextStyle::Heading),
            );
            ui.add_space(10.0);

            if let Some(err) = &self.login_error {
                ui.colored_label(egui::Color32::RED, egui::RichText::new(err).size(18.0));
            }

            if let Some(ok) = &self.register_success {
                ui.colored_label(egui::Color32::GREEN, egui::RichText::new(ok).size(18.0));
            }

            ui.add_space(20.0);

            if ui
                .add_sized([200.0, 40.0], egui::Button::new("Conectar"))
                .clicked()
            {
                if self.username.trim().is_empty() || self.password.trim().is_empty() {
                    self.login_error = Some("Debe completar usuario y contraseña".into());
                } else if let Ok(cli) = SignalingClient::connect(&self.server_addr, &self.tls_psk) {
                    cli.login(&self.username, &self.password);
                    self.pending_client = Some(cli);
                } else {
                    self.login_error = Some("Error al conectar con el servidor".into());
                }
            }

            if ui
                .add_sized([200.0, 40.0], egui::Button::new("Registrar"))
                .clicked()
            {
                if self.username.trim().is_empty() || self.password.trim().is_empty() {
                    self.login_error =
                        Some("Debe completar usuario y contraseña para registrarse".into());
                } else {
                    match SignalingClient::register_once(
                        &self.server_addr,
                        &self.tls_psk,
                        &self.username,
                        &self.password,
                    ) {
                        Ok(Ok(())) => {
                            // Registro exitoso
                            self.register_success =
                                Some("Registro exitoso. Ahora inicia sesión.".into());
                            self.login_error = None;
                        }
                        Ok(Err(msg)) => {
                            // El servidor respondió ERROR con un mensaje de negocio
                            self.login_error = Some(msg);
                            self.register_success = None;
                        }
                        Err(e) => {
                            // Error de IO / conexión / TLS
                            self.login_error =
                                Some(format!("Error al conectar con el servidor: {e}"));
                            self.register_success = None;
                        }
                    }
                }
            }

            ui.add_space(30.0);
        });
    }

    /// Dibuja la pantalla del lobby con la lista de usuarios.
    fn draw_lobby(&mut self, ui: &mut egui::Ui) {
        ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
            ui.add_space(20.0);
            ui.heading(egui::RichText::new("Usuarios Conectados").size(32.0));
            ui.add_space(10.0);

            ui.add_space(10.0);
            ui.separator();
            ui.add_space(10.0);

            if let Some(cli) = &self.client {
                cli.list_users();
            }

            egui::ScrollArea::vertical()
                .max_height(300.0)
                .show(ui, |ui| {
                    let users_guard = match self.users.lock() {
                        Ok(g) => g,
                        Err(poisoned) => {
                            eprintln!("ERROR: users mutex poisoned, usando contenido interno");
                            poisoned.into_inner()
                        }
                    };

                    let users = users_guard.clone();
                    drop(users_guard);

                    for (name, state) in users {
                        if name == self.username {
                            continue;
                        }

                        ui.add_space(5.0);

                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(format!("{name} ({state})")).size(20.0));

                            if state == "disponible"
                                && ui
                                    .add_sized([120.0, 30.0], egui::Button::new("Llamar"))
                                    .clicked()
                                && let Some(cli) = &self.client
                            {
                                self.is_caller = true;
                                self.current_peer = Some(name.clone());
                                cli.invite(&name);
                            }
                        });

                        ui.separator();
                    }
                });

            ui.add_space(20.0);

            if let Some(err) = &self.call_error {
                ui.colored_label(egui::Color32::RED, egui::RichText::new(err).size(18.0));
                ui.add_space(10.0);
            }

            if self.is_caller
                && let Some(peer) = &self.current_peer
            {
                ui.label(
                    egui::RichText::new(format!("Llamando a {peer}..."))
                        .size(20.0)
                        .italics(),
                );
                ui.add_space(10.0);
            }

            if let Some(from_user) = self.incoming_call.clone() {
                ui.separator();
                ui.add_space(10.0);

                ui.label(
                    egui::RichText::new(format!("Llamada entrante de {from_user}")).size(22.0),
                );

                ui.add_space(10.0);

                ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
                    if ui
                        .add_sized([150.0, 40.0], egui::Button::new("Aceptar"))
                        .clicked()
                        && let Some(cli) = &self.client
                    {
                        cli.accept_call(&from_user);
                        self.is_caller = false;
                        self.current_peer = Some(from_user.clone());
                        self.incoming_call = None;
                    }

                    if ui
                        .add_sized([150.0, 40.0], egui::Button::new("Rechazar"))
                        .clicked()
                        && let Some(cli) = &self.client
                    {
                        cli.reject_call(&from_user);
                        self.incoming_call = None;
                    }
                });
            }
        });

        ui.with_layout(egui::Layout::bottom_up(egui::Align::RIGHT), |ui| {
            if ui
                .add_sized([200.0, 40.0], egui::Button::new("Cerrar sesión"))
                .clicked()
            {
                if let Some(cli) = &self.client {
                    cli.logout();
                }

                self.client = None;
                self.pending_client = None;
                self.incoming_call = None;

                if let Ok(mut guard) = self.users.lock() {
                    guard.clear();
                }
            }
        });
    }

    /// Procesa los mensajes entrantes del cliente de señalizacion.
    fn poll_messages(&mut self) {
        let cli_opt = self.pending_client.as_ref();

        if let Some(cli) = cli_opt {
            let mut msgs = Vec::new();
            while let Some(msg) = cli.try_recv() {
                msgs.push(msg);
            }

            for msg in msgs {
                let t = msg.msg_type.as_str();

                match t {
                    // Mensaje de exito en login o registro
                    "OK" => {
                        let data = msg.fields.get("msg").map(|s| s.as_str());

                        if let Some("Login exitoso") = data {
                            self.client = self.pending_client.take();
                            self.login_error = None;
                            self.register_success = None;
                        }
                    }

                    // Mensaje de error en login o registro
                    "ERROR" => {
                        let err = msg
                            .fields
                            .get("msg")
                            .cloned()
                            .unwrap_or("Error desconocido".into());
                        self.login_error = Some(err);
                        self.pending_client = None;
                    }

                    _ => {}
                }
            }
        }

        if let Some(cli) = &self.client {
            let mut msgs = Vec::new();
            while let Some(msg) = cli.try_recv() {
                msgs.push(msg);
            }

            for msg in msgs {
                let t = msg.msg_type.as_str();

                match t {
                    // Actualizacion de la lista de usuarios
                    "USER_LIST" => {
                        if let Some(raw) = msg.fields.get("list") {
                            let mut vec = Vec::new();

                            for entry in raw.split(';') {
                                if let Some((user, state)) = entry.split_once(':') {
                                    vec.push((user.to_string(), state.to_string()));
                                }
                            }

                            if let Ok(mut guard) = self.users.lock() {
                                *guard = vec;
                            }
                        }

                        if let Some(peer) = &self.current_peer
                            && let Ok(guard) = self.users.lock()
                            && let Some((_, state)) = guard.iter().find(|(u, _)| u == peer)
                            && state == "desconectado"
                        {
                            self.current_peer = None;
                            self.is_caller = false;
                            self.incoming_call = None;

                            self.next_screen = None;
                        }
                    }

                    // Mensaje de llamada entrante
                    "INCOMING_CALL" => {
                        if let Some(from) = msg.fields.get("from") {
                            self.incoming_call = Some(from.clone());
                        }
                    }

                    // Mensaje de llamada aceptada
                    "CALL_ACCEPTED" => {
                        if let Some(by) = msg.fields.get("by") {
                            self.current_peer = Some(by.clone());
                            self.is_caller = true;
                            self.next_screen = Some(AppScreen::Call { peer: by.clone() });
                        }
                    }

                    // Mensaje de llamada establecida
                    "CALL_ESTABLISHED" => {
                        if let Some(peer) = msg.fields.get("with") {
                            self.current_peer = Some(peer.clone());
                            self.is_caller = false;
                            self.next_screen = Some(AppScreen::Call { peer: peer.clone() });
                        }
                    }

                    // Mensaje de llamada rechazada
                    "CALL_REJECTED" => {
                        self.call_error = Some("El usuario rechazó la llamada".into());
                        self.incoming_call = None;
                        self.current_peer = None;
                        self.is_caller = false;
                    }

                    // Mensaje de llamada finalizada
                    "CALL_ENDED" => {
                        self.incoming_call = None;
                        self.current_peer = None;
                        self.is_caller = false;
                    }

                    _ => {}
                }
            }
        }
    }

    /// Resetea el estado de la llamada.
    pub fn reset_call_state(&mut self) {
        self.is_caller = false;
        self.current_peer = None;
        self.incoming_call = None;
        self.call_error = None;
        self.next_screen = None;
    }
}
