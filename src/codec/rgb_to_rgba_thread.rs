//! Metodo para convertir DecodedFrame (RGB) a ColorImage (RGBA) en un hilo separado.

use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use eframe::egui::ColorImage;

use crate::app::media::RgbaFrameMsg;
use crate::codec::h264::DecodedFrame;

/// Hilo dedicado a convertir DecodedFrame (RGB) a ColorImage (RGBA)
pub fn spawn_rgb_to_rgba_thread(rgb_rx: Receiver<DecodedFrame>, rgba_tx: Sender<RgbaFrameMsg>) {
    thread::spawn(move || {
        let mut rgba_buffer = Vec::new();

        while let Ok(frame) = rgb_rx.recv() {
            let w = frame.width as usize;
            let h = frame.height as usize;

            let num_pixels = frame.data.len() / 3;
            rgba_buffer.clear();
            if rgba_buffer.capacity() < num_pixels * 4 {
                rgba_buffer.reserve(num_pixels * 4 - rgba_buffer.capacity());
            }
            // Conversión RGB → RGBA
            for chunk in frame.data.chunks_exact(3) {
                rgba_buffer.extend_from_slice(&[chunk[0], chunk[1], chunk[2], 255]);
            }

            let image = ColorImage::from_rgba_unmultiplied([w, h], &rgba_buffer);

            let _ = rgba_tx.send(RgbaFrameMsg::Image {
                image,
                width: frame.width,
                height: frame.height,
            });
        }
    });
}
