//! Hilo dedicado a la decodificación H.264 (usa H264Decoder y devuelve DecodedFrame)

use crate::codec::DecodeThreadMsg;
use crate::codec::h264::H264Decoder;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

/// Lanza un hilo que:
///  - recibe AUs H.264 por `au_rx`
///  - decodifica con H264Decoder
///  - manda resultados (o errores) por `frame_tx`
pub fn spawn_decoder_thread(au_rx: Receiver<Vec<u8>>, frame_tx: Sender<DecodeThreadMsg>) {
    thread::spawn(move || {
        let mut decoder = match H264Decoder::new() {
            Ok(d) => d,
            Err(_) => {
                return;
            }
        };

        let mut fps_counter: u32 = 0;
        let mut last_fps_time = Instant::now();

        // Loop principal: consumir AUs y decodificar
        while let Ok(au) = au_rx.recv() {
            // Señal de apagado
            if au.is_empty() {
                break;
            }

            let au_len = au.len();

            match decoder.decode(&au) {
                Ok(frame) => {
                    fps_counter += 1;

                    let fps_to_report = if last_fps_time.elapsed() >= Duration::from_secs(1) {
                        let v = fps_counter;
                        fps_counter = 0;
                        last_fps_time = Instant::now();
                        Some(v)
                    } else {
                        None
                    };

                    // Enviar frame decodificado al thread principal
                    let _ = frame_tx.send(DecodeThreadMsg::Frame {
                        frame,
                        fps: fps_to_report,
                        au_len,
                    });
                }

                Err(e) => {
                    // Enviar error al thread principal
                    let _ = frame_tx.send(DecodeThreadMsg::Error {
                        description: e.to_string(),
                        au_len,
                    });
                }
            }
        }
    });
}
