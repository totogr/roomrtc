//! Recibidor de estado RTCP por SSRC remoto

use crate::protocols::rtcp;
use crate::protocols::rtp_packet::RtpHeader;
/// RTCP receiver state por SSRC remoto
use std::time::Instant;

/// Estado del receptor RTCP para un SSRC remoto.
#[derive(Debug, Clone)]
pub struct RtcpRecvState {
    base_seq: u16,
    cycles: u32,
    highest_seq: u16,
    highest_ext_seq: u32,
    pub received: u32,
    expected_prior: u32,
    received_prior: u32,
    last_arrival: Option<Instant>,
    prev_rtp_ts: Option<u32>,
    jitter: f64,
    pub last_sr_mid: Option<u32>,
    pub last_sr_arrival: Option<Instant>,
}

/// Implementacion del estado del receptor RTCP.
impl RtcpRecvState {
    /// Crea un nuevo estado de receptor RTCP.
    pub fn new(first_seq: u16) -> Self {
        Self {
            base_seq: first_seq,
            cycles: 0,
            highest_seq: first_seq,
            highest_ext_seq: first_seq as u32,
            received: 0,
            expected_prior: 0,
            received_prior: 0,
            last_arrival: None,
            prev_rtp_ts: None,
            jitter: 0.0,
            last_sr_mid: None,
            last_sr_arrival: None,
        }
    }

    /// Procesa un paquete RTP recibido para actualizar el estado.
    pub fn on_rtp(&mut self, hdr: &RtpHeader, now: Instant) {
        self.received = self.received.saturating_add(1);
        if hdr.seq < self.highest_seq
            && (self.highest_seq as u32).wrapping_sub(hdr.seq as u32) > 30000
        {
            self.cycles = self.cycles.wrapping_add(1 << 16);
        }

        if hdr.seq >= self.highest_seq {
            self.highest_seq = hdr.seq;
        }
        self.highest_ext_seq = (self.cycles) | (self.highest_seq as u32);

        // jitter calc
        let clock = 90_000f64; // video clock
        if let (Some(prev_arrival), Some(prev_ts)) = (self.last_arrival, self.prev_rtp_ts) {
            let ia = now.duration_since(prev_arrival).as_secs_f64();
            let d = ((ia * clock) as i64) - (hdr.timestamp.wrapping_sub(prev_ts) as i64);
            let ad = d.abs() as f64;
            self.jitter += (ad - self.jitter) / 16.0;
        }
        self.prev_rtp_ts = Some(hdr.timestamp);
        self.last_arrival = Some(now);
    }

    /// Construye un bloque de informe RTCP Report Block.
    pub fn build_rr_block(&mut self) -> rtcp::ReportBlock {
        let expected = (self.highest_ext_seq.wrapping_sub(self.base_seq as u32)).wrapping_add(1);
        let expected_interval = expected.saturating_sub(self.expected_prior);
        let received_interval = self.received.saturating_sub(self.received_prior);
        self.expected_prior = expected;
        self.received_prior = self.received;
        let lost_interval = expected_interval.saturating_sub(received_interval);
        let fraction_lost = if expected_interval > 0 {
            ((lost_interval.saturating_mul(256)) / expected_interval).min(255) as u8
        } else {
            0
        };
        let cumulative_lost = expected.saturating_sub(self.received);
        let jitter_u32 = self.jitter.round() as u32;
        // LSR/DLSR
        let lsr = self.last_sr_mid.unwrap_or(0);
        let dlsr = if let Some(arr) = self.last_sr_arrival {
            let d = Instant::now().saturating_duration_since(arr);
            let secs = d.as_secs();
            let frac = ((d.subsec_nanos() as u64) << 16) / 1_000_000_000u64;
            ((secs as u32) << 16) | (frac as u32)
        } else {
            0
        };
        rtcp::ReportBlock {
            ssrc: 0,
            fraction_lost,
            cumulative_lost,
            ext_highest_seq: self.highest_ext_seq,
            jitter: jitter_u32,
            lsr,
            dlsr,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::rtp_packet::{RtpHeader, RtpParams};
    use std::time::Duration;

    fn make_header(seq: u16, ts: u32) -> RtpHeader {
        RtpHeader::new(
            RtpParams {
                version: 2,
                padding: false,
                extension: false,
                csrc_count: 0,
            },
            false,
            96,
            seq,
            ts,
            0x1234_5678,
        )
    }

    #[test]
    fn new_initializes_expected_state() {
        let state = RtcpRecvState::new(321);
        assert_eq!(state.received, 0);
        assert_eq!(state.highest_seq, 321);
        assert_eq!(state.highest_ext_seq, 321u32);
        assert!(state.last_arrival.is_none());
        assert!(state.prev_rtp_ts.is_none());
    }

    #[test]
    fn on_rtp_updates_counters_and_rr_values() {
        let mut state = RtcpRecvState::new(1000);
        let start = Instant::now();

        state.on_rtp(&make_header(1000, 10_000), start);
        assert_eq!(state.received, 1);
        assert_eq!(state.highest_seq, 1000);
        assert_eq!(state.highest_ext_seq, 1000);

        let rr_first = state.build_rr_block();
        assert_eq!(rr_first.fraction_lost, 0);
        assert_eq!(rr_first.cumulative_lost, 0);
        assert_eq!(rr_first.ext_highest_seq, 1000);

        let later = start + Duration::from_millis(33);
        state.on_rtp(&make_header(1001, 5_000), later);

        assert_eq!(state.received, 2);
        assert_eq!(state.highest_seq, 1001);
        assert_eq!(state.highest_ext_seq, 1001);

        let rr_second = state.build_rr_block();
        assert_eq!(rr_second.fraction_lost, 0);
        assert_eq!(rr_second.cumulative_lost, 0);
        assert_eq!(rr_second.ext_highest_seq, 1001);
    }
}
