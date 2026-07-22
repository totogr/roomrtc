//! Modulos de codificadores y decodificadores de video y audio.

pub mod h264;
pub use h264::{DecodedFrame, H264Decoder, H264Encoder};

pub mod opus;
pub use opus::{OpusDecoder, OpusEncoder};
pub mod decode_thread;
pub mod rgb_to_rgba_thread;

/// Mensajes que el hilo de decodificación le envía al ReceiverRunner.
pub enum DecodeThreadMsg {
    Frame {
        frame: DecodedFrame,
        fps: Option<u32>,
        au_len: usize,
    },
    Error {
        description: String,
        au_len: usize,
    },
}
