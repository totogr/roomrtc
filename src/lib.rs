//! # Media Streaming Library

pub mod app;
pub mod audio_output;
pub mod camera;
pub mod certificate;
pub mod codec;
pub mod config;
pub mod microphone;
pub mod sdp {
    pub mod sdp_core;
    pub mod sdp_utils;
}
pub mod protocols {
    pub mod data_channel;
    pub mod dtls;
    pub mod dtls_utils;
    pub mod h264_rtp;
    pub mod ice;
    pub mod jitter_buffer;
    pub mod message;
    pub mod opus_rtp;
    pub mod rtcp;
    pub mod rtcp_receiver;
    pub mod rtp_packet;
    pub mod srtp;
    pub mod tls;
}
pub mod signaling_server;
pub mod utils;
