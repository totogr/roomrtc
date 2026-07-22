# RoomRTC - Taller de Programacion ni2to2

Proyecto final del Taller de Programacion.
Implementacion desde cero de un stack WebRTC simplificado utilizando **Rust**, con:
- Servidor de señalización TCP con autenticación.
- Descubrimiento dinámico de usuarios.
- Inicio/aceptación/rechazo de llamadas.
- Intercambio automático de SDP Offer/Answer.
- Conectividad P2P mediante ICE-Lite + STUN.
- Transmisión de video en tiempo real (H.264 sobre RTP/RTCP).
- Interfaz gráfica con egui/eframe (Lobby + Call).
- Cifrado DTLS simplificado + SRTP para datos multimedia.

---

## Integrantes

Nicolas Gaido - 100856  
Tomas Goncalvez Rei - 111405  
Nicolas Olano Soley - 104881  
Tobias Lamanna - 104126  

---

## Descripcion del proyecto

**RoomRTC** es una plataforma de videollamadas P2P implementada íntegramente en **Rust estándar**, sin runtimes async ni librerías de WebRTC.

EL sistema implementa:

### Señalizacion (cliente-servidor)

- Conexión TCP persistente.
- Protocolo de mensajes textual, enmarcado y documentado.
- Registro, login, logout.
- Broadcast de lista de usuarios.
- Solicitudes y respuestas de llamada.
- Reenvío automático de Offer/Answer/SDP.

### Conectividad P2P
- Implementación de **ICE-Lite**, suficiente para entornos controlados.
- STUN Binding Request/Success.
- Selección automática del par de candidatos.
- Sockets UDP directos para video.

### Transmisión multimedia
- Captura de cámara con *nokhwa*.
- Codificación H.264 (OpenH264).
- Fragmentación FU-A (RFC 6184).
- RTP/RTCP implementados manualmente.
- Decodificación y renderizado remoto.
- Logs y métricas de calidad en tiempo real.

### Seguridad
- **Señalización segura cliente-servidor**
  - Cifrado simétrico AES-256-GCM sobre TCP.
  - Clave derivada mediante SHA-256 a partir de un PSK configurable.
  - Framing explícito de mensajes para evitar desincronización del stream.

- **Autenticación del peer remoto**
  - Verificación de fingerprint DTLS intercambiado vía SDP.

- **Cifrado de media**
  - Handshake DTLS para establecimiento de secretos compartidos.
  - Derivación de claves mediante HKDF.
  - Protección de RTP con SRTP (AES-GCM).

### Arquitectura concurrente (multi-threading)
- Hilos dedicados para:
  - Manejo de la interfaz gráfica.
  - Captura de audio.
  - Envio de archivos.
  - Captura de video.
  - Decodificación de video.
  - Recepción y envío de paquetes UDP.
  - Manejo de señalización TCP.

### Interfaz gráfica
Basada en **egui/eframe**, con dos pantallas:

- **Lobby:** lista de usuarios, login/registro, inicio/recepción de llamadas.
- **Call:** videollamada completa, logs, control de la llamada.

---

## Como usar 

A continuacion se detallan los pasos para compilar y ejecutar el programa.

### Compilacion

Para compilar el proyecto en modo optimizado:

```bash
cargo build --release
```

Se generaran dos ejecutables, uno del servidor y otro del cliente en:

```bash
target/release/server
target/release/client
```

### Como correr

Para ejecutar el **servidor**, ejecuta el siguiente comando:

```bash
cargo run --release --bin server
```

Para ejecutar el **cliente**, ejecuta el siguiente comando:

```bash
cargo run --release --bin client
```

Una vez que el servidor y un cliente están ejecutándose, el proceso para iniciar una videollamada es el siguiente:

1. Iniciar sesion o registrarse en la pantalla de Lobby.
2. Una vez autenticado, se mostrara la lista de usuarios conectados, cada uno con su respectivo estado (disponible/ocupado/desconectado).
3. Seleccionar un usuario disponible de la lista y presionar **Llamar** para solicitar una videollamada.
4. El otro usuarios recibira la notificacion de llamada y eligira si **Aceptarla** o **Rechazarla**.
5. Si se establece la llamada, se realiza el intercambio automatico de SDP y se establece la conexion P2P para comenzar la transmision de video.
6. La aplicacion inicia la camara local y muestra el video remoto, ademas de los logs de estadisticas.
7. En cualquier momento se puede colgar la llamada con el boton **Colgar**, cambiando ambos usuarios a estado *disponible* y volviendo a la pantalla Lobby

---

## Como testear

### Testeo Manual

- Verificar conexión con el servidor.
- Probar registro/login/logout.
- Realizar llamada entre dos usuarios.
- Verificar video local y remoto.
- Consultar logs de RTP/RTCP.

### Testeo Automatizado

```bash
cargo test
```

## Estructura del proyecto

```text
src/
├── app/
│   ├── call.rs                 # Pantalla y logica de llamada (CallApp)
│   ├── file_transfer.rs        # Logica de transferencia de archivos
│   ├── handlers.rs             # Manejo de eventos entrantes (SDP, ICE, signaling)
│   ├── lobby.rs                # Pantalla y logica de lobby (autenticacion y usuarios)
│   ├── logging.rs              # Sistema de logs con timestamp
│   ├── media.rs                # Control local de camara, encoder y decodificador
│   ├── mod.rs                  # Modulo raiz de la aplicacion
│   ├── multiplexer.rs          # Multiplexado de trafico UDP (STUN/DTLS/RTP/RTCP)
│   ├── signaling_client.rs     # Cliente TCP persistente hacia el server
│   ├── ui.rs                   # Render de video local/remoto + UI egui
├── bin/
│   ├── client.rs               # Ejecutable del cliente RoomRTC
│   ├── server.rs               # Ejecutable del servidor de signaling
├── codec/
│   ├── decode_thread.rs        # Hilo de decodificacion de video
│   ├── h264.rs                 # Implementación del códec H.264
│   ├── mod.rs                  # Módulo raíz de códecs
│   ├── opus.rs                 # Implementación del códec Opus
│   ├── rgb_to_rgba_thread.rs   # Hilo de conversión RGB a RGBA para render
├── protocols/
│   ├── data_channel.rs         # Canal de datos SCTP
│   ├── dtls.rs                 # Handshake DTLS
│   ├── dtls_utils.rs           # Utilidades criptograficas de DTLS
│   ├── h264_rtp.rs             # Implementación del protocolo RTP con H.264
│   ├── ice.rs                  # Implementación del protocolo ICE/STUN
│   ├── jitter_buffer.rs        # Jitter buffer para video
│   ├── message.rs              # Protocolo TCP textual
│   ├── mod.rs                  # Módulo raíz de protocolos
│   ├── opus_rtp.rs             # Implementación del protocolo RTP con Opus
|	├── rtcp.rs                 # Definición del paquete RTCP
│	├── rtcp_receiver.rs        # Implementación del receptor RTCP
│   ├── rtp_packet.rs           # Definición del paquete RTP
│   ├── srtp.rs                 # Encriptado AES-GCM para RTP
│   ├── tls.rs                  # Implementación TLS simplificada
├── sdp/
│   ├── mod.rs                  # Módulo raíz para manejo de SDP
│   ├── sdp_core.rs             # Funciones centrales para SDP
│   ├── sdp_utils.rs            # Utilidades para manejo de SDP
├── users/
│   ├── users.txt               # Registro persistente de usuarios (credenciales)
├── audio_output.rs             # Salida de audio
├── camera.rs                   # Captura de video desde la cámara usando Nokhwa
├── certificate.rs              # Generacion de certificados para DTLS
├── config.rs                   # LEctura de configuracion
├── lib.rs                      # Biblioteca principal del proyecto
├── microphone.rs               # Captura de audio desde el microfono
├── singaling_server.rs         # Logica del servidor signaling
└── utils.rs                    # Funciones utilitarias generales
test/
```