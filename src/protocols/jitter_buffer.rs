//! Buffer para reordenamiento y mitigación de jitter en paquetes RTP.

use crate::protocols::rtp_packet::RtpHeader;
use std::collections::BTreeMap;

/// Buffer para reordenamiento y mitigación de jitter en paquetes RTP.
pub struct JitterBuffer {
    /// Mapa ordenado de paquetes: Sequence Number -> (Header, Payload)
    buffer: BTreeMap<u16, (RtpHeader, Vec<u8>)>,
    next_seq: Option<u16>,
    max_capacity: usize,
    min_buffering: usize,
    is_buffering: bool,
}

/// Implementación del JitterBuffer.
impl JitterBuffer {
    /// Crea un nuevo JitterBuffer.
    ///
    /// `max_capacity`: Cantidad máxima de paquetes a guardar.
    /// `min_buffering`: Cantidad mínima de paquetes antes de empezar a entregar.
    pub fn new(max_capacity: usize, min_buffering: usize) -> Self {
        Self {
            buffer: BTreeMap::new(),
            next_seq: None,
            max_capacity,
            min_buffering,
            is_buffering: true,
        }
    }

    /// Inserta un paquete RTP en el buffer.
    pub fn push(&mut self, header: RtpHeader, payload: Vec<u8>) {
        if self.next_seq.is_none() {
            self.next_seq = Some(header.seq);
        }

        let next = match self.next_seq {
            Some(n) => n,
            None => return,
        };

        let diff = (header.seq.wrapping_sub(next)) as i16;
        if diff < 0 {
            // Se descartan paquetes atrasados
            return;
        }

        self.buffer.insert(header.seq, (header, payload));
    }

    /// Devuelve el siguiente paquete en orden o None
    pub fn pop(&mut self) -> Option<(RtpHeader, Vec<u8>)> {
        if self.is_buffering {
            if self.buffer.len() < self.min_buffering {
                return None;
            } else {
                self.is_buffering = false;
            }
        }

        if self.buffer.is_empty() {
            self.is_buffering = true;
            return None;
        }

        let next = self.next_seq?;

        if let Some((_seq, _)) = self.buffer.get_key_value(&next) {
            let packet = self.buffer.remove(&next);
            if packet.is_some() {
                self.next_seq = Some(next.wrapping_add(1));
            }
            return packet;
        }

        if self.buffer.len() >= self.max_capacity {
            let mut best_seq = None;
            let mut min_diff = i16::MAX;

            for seq in self.buffer.keys() {
                let diff = (seq.wrapping_sub(next)) as i16;
                if diff > 0 && diff < min_diff {
                    min_diff = diff;
                    best_seq = Some(*seq);
                }
            }

            if let Some(seq) = best_seq {
                let packet = self.buffer.remove(&seq);
                if packet.is_some() {
                    self.next_seq = Some(seq.wrapping_add(1));
                }
                return packet;
            } else if let Some(first_key) = self.buffer.keys().next().cloned() {
                let packet = self.buffer.remove(&first_key);
                if packet.is_some() {
                    self.next_seq = Some(first_key.wrapping_add(1));
                }
                return packet;
            }
        }
        None
    }
}
