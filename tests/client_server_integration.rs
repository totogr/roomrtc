//! Pruebas de integración E2E: Servidor Real + Clientes Mock
//!
//! Estos tests validan el comportamiento REAL del servidor signaling:
//! - Autenticación y validación de credenciales
//! - Gestión de estado de usuarios (disponible, ocupado, desconectado)
//! - Enrutamiento de mensajes entre clientes
//! - Validación de reglas de negocio (no duplicados, no auto-invitaciones, etc.)
//!
//! El servidor es la implementación REAL importada de src/signaling_server.rs.
//! Los clientes son mock simples que envían mensajes TCP.

use roomrtc::protocols::message::{build_message, parse_message};
use roomrtc::protocols::tls::{TlsKey, derive_key_from_psk, read_encrypted, write_encrypted};
use roomrtc::signaling_server::{ServerState, User, handle_client};
use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// ============================================================================
// CLIENTE MOCK (envía mensajes TCP, sin lógica de negocio)
// ============================================================================

struct MockClient {
    stream: std::net::TcpStream,
    key: TlsKey,
}

impl MockClient {
    fn new(addr: &str, psk: &str) -> std::io::Result<Self> {
        let stream = std::net::TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let key = derive_key_from_psk(psk);
        Ok(MockClient { stream, key })
    }

    fn send_login(&mut self, username: &str, password: &str) -> std::io::Result<()> {
        let msg = build_message("LOGIN", &[("username", username), ("password", password)]);
        write_encrypted(&mut self.stream, &msg, &self.key)
    }

    fn send_list_users(&mut self) -> std::io::Result<()> {
        let msg = build_message("LIST_USERS", &[]);
        write_encrypted(&mut self.stream, &msg, &self.key)
    }

    fn send_invite(&mut self, to: &str) -> std::io::Result<()> {
        let msg = build_message("INVITE", &[("to", to)]);
        write_encrypted(&mut self.stream, &msg, &self.key)
    }

    fn send_accept_call(&mut self, from: &str) -> std::io::Result<()> {
        let msg = build_message("ACCEPT_CALL", &[("from", from)]);
        write_encrypted(&mut self.stream, &msg, &self.key)
    }

    fn receive(&mut self) -> std::io::Result<(String, HashMap<String, String>)> {
        let raw_msg = read_encrypted(&mut self.stream, &self.key)?;
        if let Some(msg) = parse_message(&raw_msg) {
            Ok((msg.msg_type, msg.fields))
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "No se pudo parsear mensaje",
            ))
        }
    }
}

// ============================================================================
// UTILIDADES PARA TESTS
// ============================================================================

fn start_test_server() -> (
    String,
    std::thread::JoinHandle<()>,
    Arc<Mutex<ServerState>>,
    TlsKey,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Fallo al bindear");
    let addr = listener.local_addr().expect("Fallo al obtener dirección");
    let addr_str = addr.to_string();
    let tls_key = derive_key_from_psk("test_psk");

    // Crear usuarios de prueba
    let mut users = HashMap::new();
    users.insert(
        "alice".to_string(),
        User {
            username: "alice".to_string(),
            password: "pass_alice".to_string(),
            state: "desconectado".into(),
        },
    );
    users.insert(
        "bob".to_string(),
        User {
            username: "bob".to_string(),
            password: "pass_bob".to_string(),
            state: "desconectado".into(),
        },
    );

    let state = Arc::new(Mutex::new(ServerState::new_with_users(users, tls_key)));
    let state_clone = state.clone();

    let server_thread = thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let state_clone = state_clone.clone();
            thread::spawn(move || handle_client(stream, state_clone));
        }
    });

    (addr_str, server_thread, state, tls_key)
}

// ============================================================================
// TESTS E2E
// ============================================================================

/// Test: Autenticación exitosa con credenciales correctas
/// Verifica que el servidor REAL acepta LOGIN cuando el usuario y contraseña son correctos.
#[test]
fn test_e2e_login_success() {
    let (addr, _server_thread, _state, _key) = start_test_server();
    thread::sleep(Duration::from_millis(100));

    let mut client = MockClient::new(&addr, "test_psk").expect("Fallo al conectar");
    client
        .send_login("alice", "pass_alice")
        .expect("Fallo al enviar LOGIN");

    let (msg_type, fields) = client.receive().expect("Fallo al recibir respuesta");
    assert_eq!(msg_type, "OK", "Respuesta debe ser OK");
    assert_eq!(fields.get("msg").unwrap(), "Login exitoso");
}

/// Test: Autenticación fallida con contraseña incorrecta
/// Verifica que el servidor REAL rechaza LOGIN cuando la contraseña es incorrecta.
#[test]
fn test_e2e_login_wrong_password() {
    let (addr, _server_thread, _state, _key) = start_test_server();
    thread::sleep(Duration::from_millis(100));

    let mut client = MockClient::new(&addr, "test_psk").expect("Fallo al conectar");
    client
        .send_login("alice", "wrong_password")
        .expect("Fallo al enviar LOGIN");

    let (msg_type, fields) = client.receive().expect("Fallo al recibir respuesta");
    assert_eq!(msg_type, "ERROR", "Respuesta debe ser ERROR");
    assert_eq!(fields.get("msg").unwrap(), "Contrasena incorrecta");
}

/// Test: Autenticación fallida con usuario inexistente
/// Verifica que el servidor REAL rechaza LOGIN cuando el usuario no existe.
#[test]
fn test_e2e_login_user_not_found() {
    let (addr, _server_thread, _state, _key) = start_test_server();
    thread::sleep(Duration::from_millis(100));

    let mut client = MockClient::new(&addr, "test_psk").expect("Fallo al conectar");
    client
        .send_login("nonexistent", "password")
        .expect("Fallo al enviar LOGIN");

    let (msg_type, fields) = client.receive().expect("Fallo al recibir respuesta");
    assert_eq!(msg_type, "ERROR", "Respuesta debe ser ERROR");
    assert_eq!(fields.get("msg").unwrap(), "Usuario no existe");
}

/// Test: Validación de usuarios duplicados
/// Verifica que el servidor REAL rechaza LOGIN cuando el usuario ya está conectado.
/// Flujo: Client A se autentica → Client B intenta autenticarse con mismo usuario → ERROR
#[test]
fn test_e2e_duplicate_login_rejection() {
    let (addr, _server_thread, _state, _key) = start_test_server();
    thread::sleep(Duration::from_millis(100));

    // Primer cliente conecta exitosamente
    let mut client1 = MockClient::new(&addr, "test_psk").expect("Fallo al conectar");
    client1
        .send_login("alice", "pass_alice")
        .expect("Fallo al enviar LOGIN");
    let (msg_type, _) = client1.receive().expect("Fallo al recibir respuesta");
    assert_eq!(msg_type, "OK", "Primer login debe ser exitoso");

    thread::sleep(Duration::from_millis(100));

    // Segundo cliente intenta conectar con el mismo usuario
    let mut client2 = MockClient::new(&addr, "test_psk").expect("Fallo al conectar");
    client2
        .send_login("alice", "pass_alice")
        .expect("Fallo al enviar LOGIN");
    let (msg_type, fields) = client2.receive().expect("Fallo al recibir respuesta");
    assert_eq!(msg_type, "ERROR", "Segundo login debe ser rechazado");
    assert_eq!(fields.get("msg").unwrap(), "Usuario ya conectado");
}

/// Test: Listado de usuarios
/// Verifica que el servidor REAL devuelve la lista de usuarios con sus estados.
#[test]
fn test_e2e_list_users() {
    let (addr, _server_thread, _state, _key) = start_test_server();
    thread::sleep(Duration::from_millis(100));

    let mut client = MockClient::new(&addr, "test_psk").expect("Fallo al conectar");
    client
        .send_list_users()
        .expect("Fallo al enviar LIST_USERS");

    let (msg_type, fields) = client.receive().expect("Fallo al recibir respuesta");
    assert_eq!(msg_type, "USER_LIST", "Respuesta debe ser USER_LIST");

    let list = fields.get("list").unwrap();
    assert!(
        list.contains("alice:desconectado"),
        "Lista debe mostrar alice como desconectado"
    );
    assert!(
        list.contains("bob:desconectado"),
        "Lista debe mostrar bob como desconectado"
    );
}

/// Test: Invitación a usuario inexistente
/// Verifica que el servidor REAL rechaza INVITE cuando el usuario destino no existe.
#[test]
fn test_e2e_invite_user_not_found() {
    let (addr, _server_thread, _state, _key) = start_test_server();
    thread::sleep(Duration::from_millis(100));

    let mut client = MockClient::new(&addr, "test_psk").expect("Fallo al conectar");
    client
        .send_login("alice", "pass_alice")
        .expect("Fallo al enviar LOGIN");
    let (msg_type, _) = client.receive().expect("Fallo al recibir respuesta");
    assert_eq!(msg_type, "OK");

    // Después del LOGIN, el servidor envía USER_LIST broadcast
    let (msg_type, _) = client.receive().expect("Fallo al recibir USER_LIST");
    assert_eq!(msg_type, "USER_LIST");

    // Intentar invitar a usuario inexistente
    client
        .send_invite("nonexistent")
        .expect("Fallo al enviar INVITE");

    let (msg_type, fields) = client.receive().expect("Fallo al recibir respuesta");
    assert_eq!(msg_type, "ERROR", "Respuesta debe ser ERROR");
    assert_eq!(fields.get("msg").unwrap(), "Usuario no existe");
}

/// Test: Validación que usuario no puede invitarse a sí mismo
/// Verifica que el servidor REAL rechaza INVITE cuando from == to.
#[test]
fn test_e2e_invite_self_rejection() {
    let (addr, _server_thread, _state, _key) = start_test_server();
    thread::sleep(Duration::from_millis(100));

    let mut client = MockClient::new(&addr, "test_psk").expect("Fallo al conectar");
    client
        .send_login("alice", "pass_alice")
        .expect("Fallo al enviar LOGIN");
    let (msg_type, _) = client.receive().expect("Fallo al recibir respuesta");
    assert_eq!(msg_type, "OK");

    // Después del LOGIN, el servidor envía USER_LIST broadcast
    let (msg_type, _) = client.receive().expect("Fallo al recibir USER_LIST");
    assert_eq!(msg_type, "USER_LIST");

    // Intentar invitar a sí mismo
    client.send_invite("alice").expect("Fallo al enviar INVITE");

    let (msg_type, fields) = client.receive().expect("Fallo al recibir respuesta");
    assert_eq!(msg_type, "ERROR", "Respuesta debe ser ERROR");
    assert_eq!(fields.get("msg").unwrap(), "No puedes llamarte a ti mismo");
}

/// Test: Flujo E2E completo de llamada
/// Valida la cadena completa: LOGIN A → LOGIN B → INVITE → INCOMING_CALL → ACCEPT_CALL → CALL_ACCEPTED
/// Este es el test más importante porque valida toda la orquestación del servidor.
#[test]
fn test_e2e_complete_call_flow() {
    let (addr, _server_thread, _state, _key) = start_test_server();
    thread::sleep(Duration::from_millis(100));

    // PASO 1: Alice se autentica
    let mut alice = MockClient::new(&addr, "test_psk").expect("Alice: Fallo al conectar");
    alice
        .send_login("alice", "pass_alice")
        .expect("Alice: Fallo al enviar LOGIN");
    let (msg_type, _) = alice.receive().expect("Alice: Fallo al recibir OK");
    assert_eq!(msg_type, "OK", "Alice LOGIN debe ser exitoso");

    // Alice recibe USER_LIST broadcast
    let (msg_type, _) = alice.receive().expect("Alice: Fallo al recibir USER_LIST");
    assert_eq!(msg_type, "USER_LIST");

    thread::sleep(Duration::from_millis(100));

    // PASO 2: Bob se autentica
    let mut bob = MockClient::new(&addr, "test_psk").expect("Bob: Fallo al conectar");
    bob.send_login("bob", "pass_bob")
        .expect("Bob: Fallo al enviar LOGIN");
    let (msg_type, _) = bob.receive().expect("Bob: Fallo al recibir OK");
    assert_eq!(msg_type, "OK", "Bob LOGIN debe ser exitoso");

    // Bob también recibe USER_LIST actualizada (Alice ahora conectada)
    let (msg_type, _) = bob.receive().expect("Bob: Fallo al recibir USER_LIST");
    assert_eq!(msg_type, "USER_LIST");

    // Alice también recibe USER_LIST actualizada (Bob ahora conectado)
    let (msg_type, _) = alice.receive().expect("Alice: Fallo al recibir USER_LIST");
    assert_eq!(msg_type, "USER_LIST");

    thread::sleep(Duration::from_millis(100));

    // PASO 3: Alice invita a Bob
    alice
        .send_invite("bob")
        .expect("Alice: Fallo al enviar INVITE");

    // Alice recibe USER_LIST broadcast (cambio de estado a ocupado)
    let (msg_type, _) = alice
        .receive()
        .expect("Alice: Fallo al recibir USER_LIST después INVITE");
    assert_eq!(msg_type, "USER_LIST");

    thread::sleep(Duration::from_millis(100));

    // PASO 4: Bob recibe INCOMING_CALL (puede haber USER_LIST antes)
    let (mut msg_type, mut fields) = bob.receive().expect("Bob: Fallo al recibir mensaje");
    if msg_type == "USER_LIST" {
        // Si recibe USER_LIST primero, consume y lee el siguiente
        (msg_type, fields) = bob
            .receive()
            .expect("Bob: Fallo al recibir INCOMING_CALL después USER_LIST");
    }
    assert_eq!(msg_type, "INCOMING_CALL", "Bob debe recibir INCOMING_CALL");
    assert_eq!(fields.get("from").unwrap(), "alice");

    thread::sleep(Duration::from_millis(100));

    // PASO 5: Bob acepta la llamada
    bob.send_accept_call("alice")
        .expect("Bob: Fallo al enviar ACCEPT_CALL");

    // PASO 6: Alice recibe CALL_ACCEPTED
    let (msg_type, fields) = alice
        .receive()
        .expect("Alice: Fallo al recibir CALL_ACCEPTED");
    assert_eq!(
        msg_type, "CALL_ACCEPTED",
        "Alice debe recibir CALL_ACCEPTED"
    );
    assert_eq!(fields.get("by").unwrap(), "bob");

    // PASO 7: Bob recibe CALL_ESTABLISHED
    let (msg_type, fields) = bob
        .receive()
        .expect("Bob: Fallo al recibir CALL_ESTABLISHED");
    assert_eq!(
        msg_type, "CALL_ESTABLISHED",
        "Bob debe recibir CALL_ESTABLISHED"
    );
    assert_eq!(fields.get("with").unwrap(), "alice");
}
