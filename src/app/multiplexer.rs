//! Packet multiplexer: Routes incoming UDP packets to appropriate handlers based on first-byte analysis.
//!
//! This module demultiplexes received packets into:
//! - SCTP: Chunk type validation (RFC 4960)
//! - STUN: bytes[4:8] == 0x2112A442 (magic cookie)
//! - DTLS: bytes[0] in [16-23] (content type range)
//! - RTCP: version==2 (bits [0]>>6), payload type in valid range
//! - RTP: version==2, payload type==97 (H.264)

use crate::protocols::data_channel;
use crate::protocols::ice;
use crate::protocols::rtcp;
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};
use std::thread;

/// Packet types identified by the multiplexer
#[derive(Clone, Debug, PartialEq)]
pub enum PacketType {
    Stun,
    Dtls,
    Sctp,
    Rtcp,
    Rtp,
    Unknown,
}

/// A packet with its type and source address
pub struct DemultiplexedPacket {
    pub packet_type: PacketType,
    pub buffer: Vec<u8>,
    pub len: usize,
    pub src_addr: SocketAddr,
}

/// Configuration for the packet multiplexer
pub struct MultiplexerConfig {
    /// Timeout in milliseconds for recv_from calls
    pub recv_timeout_ms: u64,
    /// Buffer size for receiving packets
    pub buffer_size: usize,
}

impl Default for MultiplexerConfig {
    fn default() -> Self {
        Self {
            recv_timeout_ms: 500,
            buffer_size: 65_535,
        }
    }
}

/// Analyzes the first byte(s) to identify packet type
///
/// Returns the packet type based on protocol-specific markers:
/// - SCTP: Chunk type validation
/// - STUN: magic cookie at bytes [4:8]
/// - DTLS: content type (bytes[0]) in range [16-23]
/// - RTCP: version==2, payload type in valid RTCP range
/// - RTP: version==2, payload type (for H.264 detection)
#[inline]
pub fn detect_packet_type(buf: &[u8], len: usize) -> PacketType {
    // SCTP detection: Verificar estructura SCTP
    if data_channel::is_valid_sctp_packet(buf, len) {
        return PacketType::Sctp;
    }

    // STUN detection: check magic cookie at bytes 4-8
    if len >= 20 && ice::is_stun_message(&buf[..len]) {
        return PacketType::Stun;
    }

    // DTLS detection: content type in first byte (16-23 range)
    if len >= 1 {
        let first_byte = buf[0];
        // DTLS content types: ChangeCipherSpec(20), Alert(21), Handshake(22), ApplicationData(23)
        // Also: ContentType can be 16-19 for reserved types
        if (16..=23).contains(&first_byte) {
            // Packets starting with 16-23 are DTLS
            return PacketType::Dtls;
        }
    }

    // RTCP detection: version==2 + valid payload type
    if len >= 4 && rtcp::is_rtcp(&buf[..len]) {
        return PacketType::Rtcp;
    }

    // RTP detection: version==2, PT==97 (H.264) or PT==111 (Opus), minimum header size
    if len >= 12 {
        let version = (buf[0] >> 6) & 0x3;
        if version == 2 {
            let payload_type = buf[1] & 0x7F;
            // Accept both H.264 video (PT=97) and Opus audio (PT=111)
            if payload_type == 97 || payload_type == 111 {
                return PacketType::Rtp;
            }
        }
    }

    PacketType::Unknown
}

/// Spawns the packet multiplexer thread
///
/// The multiplexer continuously reads from the UDP socket and routes packets
/// to the appropriate handler channel based on first-byte analysis.
/// It monitors the `multiplexer_active` flag and exits when it becomes false.
pub fn spawn_multiplexer(
    sock: UdpSocket,
    config: MultiplexerConfig,
    multiplexer_active: Arc<Mutex<bool>>,
) -> PacketChannels {
    let (stun_tx, stun_rx) = channel::<DemultiplexedPacket>();
    let (dtls_tx, dtls_rx) = channel::<DemultiplexedPacket>();
    let (sctp_tx, sctp_rx) = channel::<DemultiplexedPacket>();
    let (rtcp_tx, rtcp_rx) = channel::<DemultiplexedPacket>();
    let (rtp_tx, rtp_rx) = channel::<DemultiplexedPacket>();

    // Set socket timeout
    let timeout = std::time::Duration::from_millis(config.recv_timeout_ms);
    let _ = sock.set_read_timeout(Some(timeout));

    thread::spawn(move || {
        let mut buf = vec![0u8; config.buffer_size];

        loop {
            // Check if multiplexer should still be active
            let is_active = multiplexer_active
                .lock()
                .map(|guard| *guard)
                .unwrap_or(false);

            if !is_active {
                // Receiver stopped, exit multiplexer
                break;
            }

            match sock.recv_from(&mut buf) {
                Ok((len, src_addr)) => {
                    let packet_type = detect_packet_type(&buf, len);

                    let packet = DemultiplexedPacket {
                        packet_type: packet_type.clone(),
                        buffer: buf[..len].to_vec(),
                        len,
                        src_addr,
                    };

                    // Route packet to appropriate channel
                    let _ = match packet_type {
                        PacketType::Stun => stun_tx.send(packet),
                        PacketType::Dtls => dtls_tx.send(packet),
                        PacketType::Sctp => sctp_tx.send(packet),
                        PacketType::Rtcp => rtcp_tx.send(packet),
                        PacketType::Rtp => rtp_tx.send(packet),
                        PacketType::Unknown => continue, // Discard unknown packets
                    };
                }
                Err(e) => {
                    // Timeout or error - loop back to check multiplexer_active flag
                    if e.kind() != std::io::ErrorKind::WouldBlock
                        && e.kind() != std::io::ErrorKind::TimedOut
                    {
                        // Non-timeout error (socket closed, etc)
                        break;
                    }
                }
            }
        }
    });

    PacketChannels {
        stun: stun_rx,
        dtls: dtls_rx,
        sctp: sctp_rx,
        rtcp: rtcp_rx,
        rtp: rtp_rx,
    }
}

/// Alternativa de spawn que devuelve los receptores en una estructura para un manejo mas sencillo
pub struct PacketChannels {
    pub stun: Receiver<DemultiplexedPacket>,
    pub dtls: Receiver<DemultiplexedPacket>,
    pub sctp: Receiver<DemultiplexedPacket>,
    pub rtcp: Receiver<DemultiplexedPacket>,
    pub rtp: Receiver<DemultiplexedPacket>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_detection() {
        // STUN message has magic cookie at bytes 4-8: 0x2112A442
        let mut buf = vec![0u8; 20];
        buf[4] = 0x21;
        buf[5] = 0x12;
        buf[6] = 0xA4;
        buf[7] = 0x42;

        match detect_packet_type(&buf, 20) {
            PacketType::Stun => (),
            other => panic!("Expected Stun, got {:?}", other),
        }
    }

    #[test]
    fn test_dtls_detection() {
        // DTLS Handshake: content type = 22 (Handshake)
        let buf = vec![22u8, 0, 0, 0];
        match detect_packet_type(&buf, 4) {
            PacketType::Dtls => (),
            other => panic!("Expected Dtls, got {:?}", other),
        }
    }

    #[test]
    fn test_rtp_h264_detection() {
        // RTP packet: V=2, PT=97 (H.264)
        let mut buf = vec![0u8; 20];
        buf[0] = 2 << 6; // V=2, P=0, X=0, CC=0
        buf[1] = 97; // PT=97 (H.264)

        match detect_packet_type(&buf, 20) {
            PacketType::Rtp => (),
            other => panic!("Expected Rtp, got {:?}", other),
        }
    }

    #[test]
    fn test_unknown_detection() {
        // Random packet
        let buf = vec![255u8, 254, 253, 252];
        match detect_packet_type(&buf, 4) {
            PacketType::Unknown => (),
            other => panic!("Expected Unknown, got {:?}", other),
        }
    }
}
