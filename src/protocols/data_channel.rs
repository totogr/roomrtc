//! Data Channels sobre SCTP para transferir archivos
use bytes::Bytes;
use sctp_proto::{
    Association, AssociationEvent, AssociationHandle, ClientConfig, DatagramEvent, Endpoint,
    EndpointConfig, Event, PayloadProtocolIdentifier, ServerConfig, StreamEvent, StreamId,
    Transmit,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

/// Valida estructura básica de paquete SCTP
pub fn is_valid_sctp_packet(buf: &[u8], len: usize) -> bool {
    // Mínimo 16 bytes (12 header + 4 chunk)
    if len < 16 {
        return false;
    }

    let src_port = u16::from_be_bytes([buf[0], buf[1]]);
    let dst_port = u16::from_be_bytes([buf[2], buf[3]]);
    if src_port == 0 && dst_port == 0 {
        return false;
    }

    // Chunk type debe ser válido
    let chunk_type = buf[12];
    if !is_valid_sctp_chunk_type(chunk_type) {
        return false;
    }

    // Chunk length debe ser coherente
    let chunk_length = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    if chunk_length < 4 || chunk_length > (len - 12) {
        return false;
    }

    true
}

/// Valida que el chunk type sea soportado por sctp-proto
#[inline]
fn is_valid_sctp_chunk_type(chunk_type: u8) -> bool {
    matches!(
        chunk_type,
        0x00..=0x0F |  // Chunks estándar
        0xC0 | 0xC1 // ASCONF y ASCONF-ACK
                    // No aceptar 192-255 porque sctp-proto no los soporta
    )
}

/// Estados posibles de un Data Channel
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    /// Canal iniciando handshake SCTP
    Connecting,
    /// Canal establecido y listo para transmitir
    Open,
    /// Canal cerrado
    Closed,
}

/// Representa un Data Channel sobre SCTP para transferencia de archivos
#[derive(Debug, Clone)]
pub struct DataChannel {
    pub stream_id: u16,
    pub label: String,
    pub state: ChannelState,
}

/// Manejador de Data Channels sobre SCTP
impl DataChannel {
    pub fn new(stream_id: u16, label: String) -> Self {
        Self {
            stream_id,
            label,
            state: ChannelState::Connecting,
        }
    }
}

/// Manejador de múltiples Data Channels y asociación SCTP
pub struct DataChannelManager {
    channels: HashMap<u16, DataChannel>,
    endpoint: Endpoint,
    association: Option<(AssociationHandle, Association)>,
    received_data: VecDeque<(u16, Vec<u8>)>,
    pending_transmits: VecDeque<(SocketAddr, Vec<u8>)>,
    open_streams: HashSet<u16>,
    next_stream_id: u16,
    is_initiator: bool,
    max_outbound_streams: u16,
}

/// Implementación del manejador de Data Channels
impl DataChannelManager {
    pub fn new(_sctp_port: u16, is_initiator: bool) -> Self {
        let endpoint_config = Arc::new(EndpointConfig::default());

        let endpoint = if is_initiator {
            Endpoint::new(endpoint_config, None)
        } else {
            // sctp-proto usa delayed ACKs (~200ms) por defecto
            // No hay forma de cambiar esto en v0.5/v0.6
            let server_config = Arc::new(ServerConfig::default());
            Endpoint::new(endpoint_config, Some(server_config))
        };

        Self {
            channels: HashMap::new(),
            endpoint,
            association: None,
            received_data: VecDeque::new(),
            pending_transmits: VecDeque::new(),
            open_streams: HashSet::new(),
            next_stream_id: if is_initiator { 0 } else { 1 },
            is_initiator,
            max_outbound_streams: 65535,
        }
    }

    /// Cierra todos los Data Channels abiertos
    pub fn close_all_streams(&mut self) {
        let stream_ids: Vec<u16> = self.channels.keys().cloned().collect();
        for sid in stream_ids {
            self.close_stream(sid);
        }
    }

    /// Cierra la asociación SCTP y limpia recursos
    pub fn shutdown(&mut self) {
        // Cerrar todos los streams lógicos
        for channel in self.channels.values_mut() {
            channel.state = ChannelState::Closed;
        }
        self.channels.clear();

        // Limpiar buffers internos
        self.received_data.clear();
        self.pending_transmits.clear();

        // Eliminar asociación SCTP
        self.association = None;
    }

    /// Crea un nuevo Data Channel con un stream ID único
    pub fn create_channel(&mut self, label: String) -> Result<u16, String> {
        if self.next_stream_id >= self.max_outbound_streams {
            return Err("No hay stream IDs disponibles".to_string());
        }

        let stream_id = self.next_stream_id;

        // Verificar overflow antes de incrementar
        if let Some(next) = self.next_stream_id.checked_add(2) {
            self.next_stream_id = next;
        } else {
            self.next_stream_id = self.max_outbound_streams; // Marcar como lleno
        }

        let channel = DataChannel::new(stream_id, label);
        self.channels.insert(stream_id, channel);

        Ok(stream_id)
    }

    /// Inicia una conexión SCTP con el peer remoto (como cliente)
    pub fn connect(&mut self, remote_addr: SocketAddr) -> Result<(), String> {
        if !self.is_initiator {
            return Err("Solo quien inicia puede llamar connect()".to_string());
        }

        let client_config = ClientConfig::default();

        match self.endpoint.connect(client_config, remote_addr) {
            Ok((handle, association)) => {
                self.association = Some((handle, association));

                // Flush de paquetes iniciales del handshake
                self.drain_transmits();

                Ok(())
            }
            Err(e) => Err(format!("Error al conectar: {:?}", e)),
        }
    }

    /// Procesa un datagrama SCTP recibido desde UDP
    pub fn handle_datagram(
        &mut self,
        data: &[u8],
        remote_addr: SocketAddr,
        now: Instant,
    ) -> Result<(), String> {
        let data_bytes = Bytes::copy_from_slice(data);

        // Procesar en endpoint
        match self
            .endpoint
            .handle(now, remote_addr, None, None, data_bytes)
        {
            Some((handle, event)) => match event {
                DatagramEvent::AssociationEvent(assoc_event) => {
                    self.handle_association_event(handle, assoc_event, now)?;
                }
                DatagramEvent::NewAssociation(association) => {
                    self.association = Some((handle, association));
                    self.process_association_events(now)?;
                }
            },
            None => {
                // Puede haber eventos en la asociación aunque el endpoint no retorne nada
                if self.association.is_some() {
                    self.process_association_events(now)?;
                }
            }
        }

        self.drain_transmits_with_time(now);

        Ok(())
    }

    /// Obtiene datos SCTP pendientes para enviar por UDP
    pub fn poll_transmit(&mut self) -> Option<(Vec<u8>, SocketAddr)> {
        self.pending_transmits
            .pop_front()
            .map(|(addr, data)| (data, addr))
    }

    /// Abre un stream SCTP para enviar datos (solo para sender)
    pub fn open_stream(&mut self, stream_id: u16) -> Result<(), String> {
        if let Some((_, ref mut association)) = self.association {
            let stream_id_sctp = StreamId::from(stream_id);
            association
                .open_stream(stream_id_sctp, PayloadProtocolIdentifier::Binary)
                .map_err(|e| format!("Error abriendo stream: {:?}", e))?;
            self.open_streams.insert(stream_id);
            Ok(())
        } else {
            Err("No hay asociación SCTP activa".into())
        }
    }

    /// Acepta un stream SCTP entrante abierto por el peer (solo para receiver)
    pub fn accept_stream(&mut self, _stream_id: u16) -> Result<(), String> {
        if let Some((_, ref mut association)) = self.association {
            if let Some(stream) = association.accept_stream() {
                let actual_id = stream.stream_identifier();
                self.open_streams.insert(actual_id);
                Ok(())
            } else {
                Err("No hay streams pendientes de aceptar".to_string())
            }
        } else {
            Err("No hay asociación SCTP activa".into())
        }
    }

    /// Devuelve los stream_ids que están abiertos
    pub fn get_open_streams(&self) -> Vec<u16> {
        self.open_streams.iter().copied().collect()
    }

    /// Obtiene la cantidad de bytes buffereados en un stream
    pub fn get_buffered_amount(&mut self, stream_id: u16) -> Result<usize, String> {
        if let Some((_, ref mut association)) = self.association {
            let stream_id_sctp = StreamId::from(stream_id);
            match association.stream(stream_id_sctp) {
                Ok(stream) => stream
                    .buffered_amount()
                    .map_err(|e| format!("Error obteniendo buffered_amount: {:?}", e)),
                Err(e) => Err(format!("Stream no encontrado: {:?}", e)),
            }
        } else {
            Err("No hay asociación SCTP activa".into())
        }
    }

    /// Envía datos en un Data Channel para transferencia de archivos
    /// Usa PPID Binary automáticamente
    pub fn send_file_data(&mut self, stream_id: u16, data: &[u8]) -> Result<(), String> {
        if data.is_empty() {
            return Err("No se pueden enviar datos vacíos".to_string());
        }

        let stream_id_sctp = StreamId::from(stream_id);

        {
            if let Some((_, ref mut association)) = self.association {
                if association
                    .open_stream(stream_id_sctp, PayloadProtocolIdentifier::Binary)
                    .is_ok()
                {
                    self.open_streams.insert(stream_id);
                }
            } else {
                return Err("No hay asociación SCTP activa".to_string());
            }
        }

        self.drain_transmits();

        {
            if let Some((_, ref mut association)) = self.association {
                match association.stream(stream_id_sctp) {
                    Ok(mut stream) => {
                        stream
                            .write_with_ppi(data, PayloadProtocolIdentifier::Binary)
                            .map_err(|e| format!("Error escribiendo en stream: {:?}", e))?;
                    }
                    Err(e) => {
                        return Err(format!("Error obteniendo stream: {:?}", e));
                    }
                }
            } else {
                return Err("No hay asociación SCTP activa".to_string());
            }
        }

        self.drain_transmits();

        Ok(())
    }

    /// Procesa eventos SCTP y retorna datos de archivos recibidos
    pub fn poll_file_data(&mut self) -> Vec<(u16, Vec<u8>)> {
        let mut result = Vec::new();
        while let Some(data) = self.received_data.pop_front() {
            result.push(data);
        }
        result
    }

    /// Maneja timeouts de la asociación SCTP
    pub fn handle_timeout(&mut self, now: Instant) {
        if let Some((_, ref mut association)) = self.association {
            association.handle_timeout(now);
            self.drain_transmits();
        }
    }

    /// Obtiene el próximo timeout que debe ser procesado
    pub fn poll_timeout(&mut self) -> Option<Instant> {
        self.association
            .as_mut()
            .and_then(|(_, assoc)| assoc.poll_timeout())
    }

    /// Cierra un stream SCTP (rechazo explícito de transferencia)
    pub fn close_stream(&mut self, stream_id: u16) {
        // Cerrar stream a nivel SCTP
        if let Some((_, ref mut association)) = self.association {
            let sid = StreamId::from(stream_id);
            let _ = association.stream(sid);
        }

        if let Some(channel) = self.channels.get_mut(&stream_id) {
            channel.state = ChannelState::Closed;
        }
    }

    /// Maneja un evento de asociación existente
    fn handle_association_event(
        &mut self,
        _handle: AssociationHandle,
        event: AssociationEvent,
        now: Instant,
    ) -> Result<(), String> {
        if let Some((_, ref mut association)) = self.association {
            association.handle_event(event);
            self.process_association_events(now)?;
        }
        Ok(())
    }

    /// Procesa eventos pendientes de la asociación
    fn process_association_events(&mut self, _now: Instant) -> Result<(), String> {
        loop {
            // Drenar eventos del endpoint (comunicación interna con Association)
            if let Some((_, ref mut association)) = self.association {
                while let Some(_endpoint_event) = association.poll_endpoint_event() {
                    // Solo drenar, no hay que hacer nada con estos
                }
            }

            // Obtener todos los eventos disponibles
            let mut events = Vec::new();
            if let Some((_, ref mut association)) = self.association {
                while let Some(event) = association.poll() {
                    events.push(event);
                }
            }

            if events.is_empty() {
                break;
            }

            for event in events {
                match event {
                    Event::Connected => {
                        for channel in self.channels.values_mut() {
                            if channel.state == ChannelState::Connecting {
                                channel.state = ChannelState::Open;
                            }
                        }
                    }
                    Event::Stream(stream_event) => {
                        self.handle_stream_event(stream_event)?;
                    }
                    Event::AssociationLost { reason } => {
                        for channel in self.channels.values_mut() {
                            channel.state = ChannelState::Closed;
                        }
                        return Err(format!("Asociación perdida: {:?}", reason));
                    }
                    Event::DatagramReceived => {
                        // Los datos se procesarán cuando llegue StreamEvent::Readable
                    }
                }
            }
        }

        Ok(())
    }
    /// Maneja eventos de streams
    fn handle_stream_event(&mut self, event: StreamEvent) -> Result<(), String> {
        match event {
            StreamEvent::Readable { id } => {
                self.read_stream_data(id)?;
            }
            StreamEvent::Finished { id } | StreamEvent::Stopped { id, error_code: _ } => {
                if let Some(channel) = self.channels.get_mut(&id) {
                    channel.state = ChannelState::Closed;
                }
            }
            StreamEvent::Opened => {
                if let Some((_, ref mut association)) = self.association
                    && let Some(stream) = association.accept_stream()
                {
                    let stream_id = stream.stream_identifier();
                    self.open_streams.insert(stream_id);
                }
            }
            StreamEvent::Writable { id: _ }
            | StreamEvent::Available
            | StreamEvent::BufferedAmountLow { id: _ } => {
                // Ignorar
            }
        }
        Ok(())
    }

    /// Lee datos de un stream
    pub fn read_stream_data(&mut self, stream_id: StreamId) -> Result<(), String> {
        if let Some((_, ref mut association)) = self.association {
            match association.stream(stream_id) {
                Ok(mut stream) => loop {
                    match stream.read_sctp() {
                        Ok(Some(chunks)) => {
                            let chunk_len = chunks.len();
                            let mut buffer = vec![0u8; chunk_len];
                            match chunks.read(&mut buffer) {
                                Ok(n) => {
                                    buffer.truncate(n);
                                    self.received_data.push_back((stream_id, buffer));
                                }
                                Err(e) => {
                                    return Err(format!("Error leyendo chunks: {:?}", e));
                                }
                            }
                        }
                        Ok(None) => {
                            break;
                        }
                        Err(e) => {
                            return Err(format!("Error leyendo stream: {:?}", e));
                        }
                    }
                },
                Err(e) => {
                    return Err(format!("Error obteniendo stream: {:?}", e));
                }
            }
        }

        Ok(())
    }

    /// Flush de todas las transmisiones pendientes
    fn drain_transmits(&mut self) {
        self.drain_transmits_with_time(Instant::now());
    }

    /// Flush de todas las transmisiones pendientes con timestamp específico
    fn drain_transmits_with_time(&mut self, now: Instant) {
        while let Some(transmit) = self.endpoint.poll_transmit() {
            self.queue_transmit(transmit);
        }

        let mut transmits = Vec::new();
        if let Some((_, ref mut association)) = self.association {
            while let Some(transmit) = association.poll_transmit(now) {
                transmits.push(transmit);
            }
        }

        for transmit in transmits {
            self.queue_transmit(transmit);
        }
    }

    /// Encola una transmisión para enviar por UDP
    fn queue_transmit(&mut self, transmit: Transmit) {
        use sctp_proto::Payload;

        let bytes = match transmit.payload {
            Payload::RawEncode(chunks) => {
                let total_len: usize = chunks.iter().map(|c| c.len()).sum();
                let mut result = Vec::with_capacity(total_len);
                for chunk in chunks {
                    result.extend_from_slice(&chunk);
                }
                result
            }
            Payload::PartialDecode(_) => {
                // No se debería generar esto
                return;
            }
        };

        self.pending_transmits.push_back((transmit.remote, bytes));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_new_manager_as_initiator() {
        let manager = DataChannelManager::new(5000, true);

        assert_eq!(
            manager.next_stream_id, 0,
            "Quien inicia debe comenzar con stream_id 0"
        );
        assert!(manager.is_initiator, "Debe ser quien inicia");
        assert_eq!(manager.max_outbound_streams, 65535);
        assert!(
            manager.association.is_none(),
            "No debe tener asociación al inicio"
        );
        assert_eq!(manager.channels.len(), 0, "No debe tener canales al inicio");
    }

    #[test]
    fn test_new_manager_as_server() {
        let manager = DataChannelManager::new(5000, false);

        assert_eq!(
            manager.next_stream_id, 1,
            "Servidor debe comenzar con stream_id 1"
        );
        assert!(!manager.is_initiator, "No debe ser quien inicia");
        assert!(manager.association.is_none());
    }

    #[test]
    fn test_create_channel_increments_stream_id() {
        let mut manager = DataChannelManager::new(5000, true);

        let stream1 = manager.create_channel("channel1".to_string()).unwrap();
        assert_eq!(stream1, 0, "Primer stream debe ser 0");

        let stream2 = manager.create_channel("channel2".to_string()).unwrap();
        assert_eq!(stream2, 2, "Segundo stream debe ser 2 (pares)");

        let stream3 = manager.create_channel("channel3".to_string()).unwrap();
        assert_eq!(stream3, 4, "Tercer stream debe ser 4");

        assert_eq!(manager.channels.len(), 3, "Debe tener 3 canales");
    }

    #[test]
    fn test_create_channel_server_uses_odd_ids() {
        let mut manager = DataChannelManager::new(5000, false);

        let stream1 = manager.create_channel("channel1".to_string()).unwrap();
        assert_eq!(stream1, 1, "Servidor: primer stream debe ser 1 (impar)");

        let stream2 = manager.create_channel("channel2".to_string()).unwrap();
        assert_eq!(stream2, 3, "Servidor: segundo stream debe ser 3");

        let stream3 = manager.create_channel("channel3".to_string()).unwrap();
        assert_eq!(stream3, 5, "Servidor: tercer stream debe ser 5");
    }

    #[test]
    fn test_create_channel_stores_metadata() {
        let mut manager = DataChannelManager::new(5000, true);

        let stream_id = manager.create_channel("file-transfer".to_string()).unwrap();

        let channel = manager.channels.get(&stream_id).unwrap();
        assert_eq!(channel.stream_id, 0);
        assert_eq!(channel.label, "file-transfer");
        assert_eq!(channel.state, ChannelState::Connecting);
    }

    #[test]
    fn test_connect_only_for_initiator() {
        let mut client = DataChannelManager::new(5000, true);
        let mut server = DataChannelManager::new(5000, false);

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5000);

        // Cliente puede conectar
        let result = client.connect(addr);
        assert!(result.is_ok(), "Quien inicia debe poder conectar");
        assert!(client.association.is_some(), "Debe crear asociación");

        // Servidor no puede conectar
        let result = server.connect(addr);
        assert!(result.is_err(), "Servidor no debe poder conectar");
        assert_eq!(
            result.unwrap_err(),
            "Solo quien inicia puede llamar connect()"
        );
    }

    #[test]
    fn test_poll_transmit_empty_queue() {
        let mut manager = DataChannelManager::new(5000, true);

        let result = manager.poll_transmit();
        assert!(result.is_none(), "Cola vacía debe retornar None");
    }

    #[test]
    fn test_poll_file_data_empty_queue() {
        let mut manager = DataChannelManager::new(5000, true);

        let result = manager.poll_file_data();
        assert_eq!(
            result.len(),
            0,
            "Sin datos recibidos debe retornar Vec vacío"
        );
    }

    #[test]
    fn test_poll_file_data_drains_queue() {
        let mut manager = DataChannelManager::new(5000, true);

        manager.received_data.push_back((0, vec![1, 2, 3]));
        manager.received_data.push_back((0, vec![4, 5, 6]));
        manager.received_data.push_back((2, vec![7, 8, 9]));

        let result = manager.poll_file_data();

        assert_eq!(result.len(), 3, "Debe retornar 3 chunks");
        assert_eq!(result[0], (0, vec![1, 2, 3]));
        assert_eq!(result[1], (0, vec![4, 5, 6]));
        assert_eq!(result[2], (2, vec![7, 8, 9]));

        // Segunda llamada debe retornar vacío
        let result2 = manager.poll_file_data();
        assert_eq!(result2.len(), 0, "Cola debe estar vacía tras drenar");
    }

    #[test]
    fn test_send_file_data_rejects_empty_data() {
        let mut manager = DataChannelManager::new(5000, true);
        let _ = manager.create_channel("test".to_string());

        let result = manager.send_file_data(0, &[]);

        assert!(result.is_err(), "Debe rechazar datos vacíos");
        assert_eq!(result.unwrap_err(), "No se pueden enviar datos vacíos");
    }

    #[test]
    fn test_send_file_data_requires_association() {
        let mut manager = DataChannelManager::new(5000, true);
        let _ = manager.create_channel("test".to_string());

        let result = manager.send_file_data(0, &[1, 2, 3]);

        assert!(result.is_err(), "Debe requerir asociación activa");
        assert_eq!(result.unwrap_err(), "No hay asociación SCTP activa");
    }

    #[test]
    fn test_poll_timeout_without_association() {
        let mut manager = DataChannelManager::new(5000, true);

        let timeout = manager.poll_timeout();
        assert!(timeout.is_none(), "Sin asociación no debe haber timeout");
    }

    #[test]
    fn test_channel_state_transitions() {
        let mut channel = DataChannel::new(0, "test".to_string());

        assert_eq!(
            channel.state,
            ChannelState::Connecting,
            "Estado inicial debe ser Connecting"
        );

        // Transición a Open
        channel.state = ChannelState::Open;
        assert_eq!(channel.state, ChannelState::Open);

        // Transición a Closed
        channel.state = ChannelState::Closed;
        assert_eq!(channel.state, ChannelState::Closed);
    }

    #[test]
    fn test_create_channel_max_streams_limit() {
        let mut manager = DataChannelManager::new(5000, true);
        manager.next_stream_id = 65534; // Casi al límite

        let result1 = manager.create_channel("channel1".to_string());
        assert!(result1.is_ok(), "Debe permitir crear canal en el límite");
        assert_eq!(result1.unwrap(), 65534);

        // Siguiente intento debe fallar (65534 + 2 = 65536 > 65535)
        let result2 = manager.create_channel("channel2".to_string());
        assert!(
            result2.is_err(),
            "Debe rechazar crear canal sobre el límite"
        );
        assert_eq!(result2.unwrap_err(), "No hay stream IDs disponibles");
    }

    #[test]
    fn test_handle_timeout_without_association() {
        let mut manager = DataChannelManager::new(5000, true);

        // No debe paniquear sin asociación
        manager.handle_timeout(Instant::now());

        // Verificar que no crasheó
        assert!(manager.association.is_none());
    }
}
