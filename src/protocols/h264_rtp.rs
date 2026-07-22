//! Paquetizador y despaquetizador RTP para H.264.

use crate::protocols::rtp_packet::{RtpHeader, RtpParams};
use std::collections::HashMap;

/// Verifica si el byte slice comienza con un codigo de inicio de 3 bytes.
fn is_start_code3(b: &[u8]) -> bool {
    b.len() >= 3 && b[0] == 0 && b[1] == 0 && b[2] == 1
}

/// Verifica si el byte slice comienza con un codigo de inicio de 4 bytes.
fn is_start_code4(b: &[u8]) -> bool {
    b.len() >= 4 && b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 1
}

/// Divide un flujo de bytes H.264 en NALUs basandose en los codigos de inicio.
pub fn split_nalus(data: &[u8]) -> Vec<&[u8]> {
    let mut nalus = Vec::new();
    let mut i = 0usize;
    let n = data.len();
    let mut nal_start = None;

    while i + 3 < n {
        let sc_len = if is_start_code4(&data[i..]) {
            4
        } else if is_start_code3(&data[i..]) {
            3
        } else {
            0
        };
        if sc_len > 0 {
            if let Some(start) = nal_start.take()
                && i > start
            {
                nalus.push(&data[start..i]);
            }
            nal_start = Some(i + sc_len);
            i += sc_len;
        } else {
            i += 1;
        }
    }

    if let Some(start) = nal_start
        && start < n
    {
        nalus.push(&data[start..n]);
    }

    nalus
}

/// Paquetizador RTP para H.264.
pub struct H264RtpPacketizer {
    pub mtu: usize,
    pub payload_type: u8, // 97
    pub seq: u16,
    pub ssrc: u32,
}

/// Implementacion del paquetizador RTP para H.264.
impl H264RtpPacketizer {
    /// Crea un nuevo paquetizador RTP para H.264.
    pub fn new(mtu: usize, payload_type: u8, initial_seq: u16, ssrc: u32) -> Self {
        Self {
            mtu,
            payload_type,
            seq: initial_seq,
            ssrc,
        }
    }

    /// Paquetiza un frame H.264 en paquetes RTP.
    pub fn packetize_frame(&mut self, bitstream: &[u8], timestamp: u32) -> Vec<Vec<u8>> {
        let nalus = split_nalus(bitstream);
        let mut packets: Vec<Vec<u8>> = Vec::new();
        if nalus.is_empty() {
            return packets;
        }

        let rtp_header_len = 12usize;

        for (nal_idx, nal) in nalus.iter().enumerate() {
            if nal.is_empty() {
                continue;
            }
            let last_nal_of_au = nal_idx == nalus.len() - 1;
            let nal_len = nal.len();

            if rtp_header_len + nal_len <= self.mtu {
                let rtp_params = RtpParams {
                    version: 2,
                    padding: false,
                    extension: false,
                    csrc_count: 0,
                };
                let header = RtpHeader::new(
                    rtp_params,
                    last_nal_of_au,
                    self.payload_type,
                    self.seq,
                    timestamp,
                    self.ssrc,
                );
                self.seq = self.seq.wrapping_add(1);
                let mut pkt = Vec::with_capacity(rtp_header_len + nal_len);
                pkt.extend_from_slice(&header.to_bytes());
                pkt.extend_from_slice(nal);
                packets.push(pkt);
                continue;
            }

            let nal_hdr = nal[0];
            let f_nri = nal_hdr & 0xE0;
            let nal_type = nal_hdr & 0x1F;
            let fu_indicator = f_nri | 28;

            let fu_overhead = 2usize;
            let max_frag = self.mtu.saturating_sub(rtp_header_len + fu_overhead);
            if max_frag == 0 {
                continue;
            }

            let mut offset = 1;
            let mut first = true;
            while offset < nal_len {
                let remaining = nal_len - offset;
                let frag_size = remaining.min(max_frag);
                let last = offset + frag_size >= nal_len;
                let fu_header = ((first as u8) << 7) | ((last as u8) << 6) | nal_type;

                let marker = last && last_nal_of_au;
                let rtp_params = RtpParams {
                    version: 2,
                    padding: false,
                    extension: false,
                    csrc_count: 0,
                };
                let header = RtpHeader::new(
                    rtp_params,
                    marker,
                    self.payload_type,
                    self.seq,
                    timestamp,
                    self.ssrc,
                );
                self.seq = self.seq.wrapping_add(1);

                let mut pkt = Vec::with_capacity(rtp_header_len + fu_overhead + frag_size);
                pkt.extend_from_slice(&header.to_bytes());
                pkt.push(fu_indicator);
                pkt.push(fu_header);
                pkt.extend_from_slice(&nal[offset..offset + frag_size]);
                packets.push(pkt);

                offset += frag_size;
                first = false;
            }
        }

        packets
    }
}

/// Despaquetizador RTP para H.264.
pub struct H264RtpDepacketizer {
    current_timestamp: Option<u32>,
    au_nalus: Vec<Vec<u8>>,

    fu_state: HashMap<(u32, u32), FuState>,
    have_vcl: bool,
}

/// Implementacion del trait Default para H264RtpDepacketizer.
impl Default for H264RtpDepacketizer {
    fn default() -> Self {
        Self::new()
    }
}
/// Implementacion del despaquetizador RTP para H.264.
impl H264RtpDepacketizer {
    /// Crea un nuevo despaquetizador RTP para H.264.
    pub fn new() -> Self {
        Self {
            current_timestamp: None,
            au_nalus: Vec::new(),
            fu_state: HashMap::new(),
            have_vcl: false,
        }
    }

    /// Despaquetiza un paquete RTP y devuelve un frame H.264 si esta completo.
    pub fn push_rtp(&mut self, hdr: &RtpHeader, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.is_empty() {
            return None;
        }

        if self.current_timestamp != Some(hdr.timestamp) {
            if let Some(prev_ts) = self.current_timestamp.take() {
                self.fu_state.retain(|(_, ts), _| *ts != prev_ts);
            }
            self.current_timestamp = Some(hdr.timestamp);
            self.au_nalus.clear();
            self.have_vcl = false;
        }

        let nal_header = payload[0];
        let nal_type = nal_header & 0x1F;

        match nal_type {
            1..=23 => {
                if nal_type == 1 || nal_type == 5 {
                    self.have_vcl = true;
                }
                self.au_nalus.push(payload.to_vec());
            }
            24 => {
                let mut off = 1;
                while off + 2 <= payload.len() {
                    let size = u16::from_be_bytes([payload[off], payload[off + 1]]) as usize;
                    off += 2;
                    if off + size > payload.len() {
                        break;
                    }
                    let t = payload[off] & 0x1F;
                    if t == 1 || t == 5 {
                        self.have_vcl = true;
                    }
                    self.au_nalus.push(payload[off..off + size].to_vec());
                    off += size;
                }
            }
            28 => {
                if payload.len() < 2 {
                    return None;
                }
                let fu_indicator = payload[0];
                let fu_header = payload[1];
                let start = (fu_header & 0x80) != 0;
                let end = (fu_header & 0x40) != 0;
                let orig_type = fu_header & 0x1F;
                let f_nri = fu_indicator & 0xE0;
                let reconstructed_hdr = f_nri | orig_type;

                let key = (hdr.ssrc, hdr.timestamp);
                if start {
                    let mut st = FuState {
                        buf: Vec::with_capacity(payload.len()),
                        last_seq: hdr.seq,
                    };
                    st.buf.push(reconstructed_hdr);
                    st.buf.extend_from_slice(&payload[2..]);
                    self.fu_state.insert(key, st);
                } else if let Some(st) = self.fu_state.get_mut(&key) {
                    if hdr.seq == st.last_seq.wrapping_add(1) {
                        st.buf.extend_from_slice(&payload[2..]);
                        st.last_seq = hdr.seq;
                        if end {
                            let nal = self.fu_state.remove(&key).unwrap().buf;
                            let t = nal[0] & 0x1F;
                            if t == 1 || t == 5 {
                                self.have_vcl = true;
                            }
                            self.au_nalus.push(nal);
                        }
                    } else {
                        self.fu_state.remove(&key);
                    }
                } else {
                    // ignorar si no tiene start
                }
            }
            _ => {
                // tipo no soportado
            }
        }

        if hdr.marker {
            let mut out = Vec::new();
            if self.have_vcl {
                for nal in self.au_nalus.drain(..) {
                    out.extend_from_slice(&[0, 0, 0, 1]);
                    out.extend_from_slice(&nal);
                }
            }
            self.fu_state.retain(|(_, ts), _| *ts != hdr.timestamp);
            if !out.is_empty() {
                return Some(out);
            }
        }

        None
    }
}

/// Estado de reensamblaje para NALUs fragmentados (FU-A).
struct FuState {
    buf: Vec<u8>,
    last_seq: u16,
}
