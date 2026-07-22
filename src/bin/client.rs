//! Main del cliente de RoomRTC, que maneja la aplicación raíz y la navegación entre pantallas.

use eframe::{App, egui};
use roomrtc::app::{AppScreen, call::CallApp, lobby::LobbyApp};
use roomrtc::config::AppConfig;

/// Estructura principal de la aplicación cliente, que maneja la navegación entre pantallas.
pub struct RootApp {
    pub screen: AppScreen,
    pub lobby: LobbyApp,
    pub call: Option<CallApp>,
    pub config: AppConfig,
}

/// Implementación de métodos para RootApp.
impl RootApp {
    /// Crea una nueva instancia de RootApp con la configuración dada.
    pub fn new(config: AppConfig) -> Self {
        let lobby = LobbyApp::with_config(&config);
        Self {
            screen: AppScreen::Lobby,
            lobby,
            call: None,
            config,
        }
    }
}

/// Implementación del trait Default para RootApp.
impl Default for RootApp {
    /// Crea una instancia por defecto de RootApp con configuración por defecto.
    fn default() -> Self {
        Self::new(AppConfig::default())
    }
}

/// Implementación del trait App para RootApp, manejando la actualización y salida de la aplicación.
impl App for RootApp {
    /// Actualiza la aplicación según la pantalla actual (Lobby o Call).
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        match &mut self.screen {
            // Pantalla del Lobby
            AppScreen::Lobby => {
                self.lobby.update(ctx, frame);

                if let Some(AppScreen::Call { peer }) = &self.lobby.next_screen {
                    let signaling = self
                        .lobby
                        .client
                        .as_ref()
                        .expect("Lobby debe tener client conectado")
                        .clone();

                    let is_caller = self.lobby.is_caller;

                    self.call = Some(CallApp::new(
                        peer.clone(),
                        signaling,
                        is_caller,
                        self.config.clone(),
                    ));

                    self.screen = AppScreen::Call { peer: peer.clone() };
                    self.lobby.next_screen = None;
                }
            }
            // Pantalla de la llamada
            AppScreen::Call { .. } => {
                if let Some(call) = &mut self.call {
                    call.update(ctx, frame);

                    if let Some(AppScreen::Lobby) = &call.next_screen {
                        self.screen = AppScreen::Lobby;
                        self.call = None;
                        self.lobby.reset_call_state();
                    }
                }
            }
        }
    }

    /// Maneja la limpieza al salir de la aplicación.
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        match &mut self.screen {
            AppScreen::Lobby => {
                if let Some(cli) = &self.lobby.client {
                    cli.logout();
                }
            }

            AppScreen::Call { .. } => {
                if let Some(call) = &mut self.call {
                    call.rtc.persist_logs();
                    if let Ok(sig) = call.signaling.lock() {
                        sig.end_call(&call.peer);
                        call.rtc.handle_hang_up();
                        sig.logout();
                    }
                }
            }
        }
    }
}

/// Función principal que inicia la aplicación cliente de RoomRTC.
fn main() -> eframe::Result<()> {
    // Captura global de panics para evitar cierre silencioso
    std::panic::set_hook(Box::new(|info| {
        eprintln!("[CLIENT] Panic atrapado: {:?}", info);
    }));

    // Analizar los argumentos de la línea de comandos para la ruta del archivo de configuración
    let args: Vec<String> = std::env::args().collect();
    let config = if args.len() > 1 {
        let config_path = &args[1];
        match AppConfig::from_file(config_path) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("Error al cargar configuración desde {}: {}", config_path, e);
                eprintln!("Usando configuración por defecto");
                AppConfig::default()
            }
        }
    } else {
        let config_path = format!("{}/config.conf", env!("CARGO_MANIFEST_DIR"));

        match AppConfig::from_file(&config_path) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("Error al cargar configuración desde {}: {}", config_path, e);
                eprintln!("Usando configuración por defecto");
                let prog = match args.first() {
                    Some(s) => s.as_str(),
                    None => "client",
                };
                println!("Uso: {} <ruta/al/config.conf>", prog);
                AppConfig::default()
            }
        }
    };

    // Configuración de ventana
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 700.0])
            .with_title("RoomRTC - Cliente"),
        ..Default::default()
    };

    // Ejecutar la aplicación RootApp (Lobby + Call)
    eframe::run_native(
        "RoomRTC",
        options,
        Box::new(move |_cc| Ok(Box::new(RootApp::new(config)))),
    )
}
