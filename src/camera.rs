//! Modulo para manejar la camara web y capturar fotogramas.

use eframe::egui;
use nokhwa::utils::{CameraFormat, FrameFormat};
use nokhwa::{
    Camera,
    pixel_format::RgbFormat,
    utils::{CameraIndex, RequestedFormat, RequestedFormatType, Resolution},
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;

/// Estructura que representa un frame raw capturado de la camara.
#[derive(Clone)]
pub struct RawFrame {
    pub width: usize,
    pub height: usize,
    pub pixels: Vec<u8>,
}

/// Estructura para manejar la camara web.
pub struct CameraHandler {
    raw_frame: Arc<Mutex<Option<RawFrame>>>,
    stop_flag: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

/// Implementacion de metodos para CameraHandler.
impl CameraHandler {
    /// Hilo para capturar fotogramas de la camara.
    fn spawn_capture_thread(
        mut cam: Camera,
        raw_frame: Arc<Mutex<Option<RawFrame>>>,
        stop_flag: Arc<AtomicBool>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                if let Ok(frame) = cam.frame()
                    && let Ok(buffer) = frame.decode_image::<RgbFormat>()
                {
                    let res = frame.resolution();
                    let width = res.width() as usize;
                    let height = res.height() as usize;

                    let pixels = buffer.into_raw();

                    if let Ok(mut guard) = raw_frame.lock() {
                        *guard = Some(RawFrame {
                            width,
                            height,
                            pixels,
                        });
                    }
                }
            }
        })
    }

    /// Crea una nueva instancia de CameraHandler.
    pub fn new(width: u32, height: u32, framerate: u32) -> Result<Self, nokhwa::NokhwaError> {
        let index0 = CameraIndex::Index(0);
        let index1 = CameraIndex::Index(1);

        let formats = [FrameFormat::MJPEG, FrameFormat::YUYV];

        // cámara inicial (random)
        let rand = rand::random::<u8>() % 2;
        let cameras = if rand == 0 {
            vec![index0, index1]
        } else {
            vec![index1, index0]
        };

        let mut final_cam: Option<Camera> = None;

        'cam_loop: for camera_index in cameras {
            for format in &formats {
                let requested = RequestedFormat::new::<RgbFormat>(RequestedFormatType::Closest(
                    CameraFormat::new(Resolution::new(width, height), *format, framerate),
                ));

                if let Ok(mut cam) = Camera::new(camera_index.clone(), requested)
                    && cam.open_stream().is_ok()
                {
                    final_cam = Some(cam);
                    break 'cam_loop;
                }
            }
        }

        let cam = final_cam.ok_or_else(|| {
            nokhwa::NokhwaError::OpenDeviceError(
                "No se pudo inicializar ninguna cámara".to_string(),
                "Todos los intentos con MJPEG y YUYV fallaron".to_string(),
            )
        })?;

        // Obtener configuración aplicada
        let actual_format = cam.camera_format();

        println!("=== Configuración de cámara ===");
        println!(
            "Resolución: {}x{}",
            actual_format.resolution().width(),
            actual_format.resolution().height()
        );
        println!("Frame format: {:?}", actual_format.format());
        println!("Framerate: {} fps", actual_format.frame_rate());
        println!("Pixel type: {:?}", cam.frame_format()); // formato del buffer
        println!("Backend: {:?}", cam.backend());
        println!("===============================");

        let raw_frame = Arc::new(Mutex::new(None));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let handle =
            Self::spawn_capture_thread(cam, Arc::clone(&raw_frame), Arc::clone(&stop_flag));

        Ok(Self {
            raw_frame,
            stop_flag,
            handle: Some(handle),
        })
    }

    /// Convierte el frame raw → ColorImage solo cuando el UI lo solicita
    pub fn get_frame(&mut self) -> Option<egui::ColorImage> {
        let raw = self.raw_frame.lock().ok()?.as_ref()?.clone();
        let pixels = raw
            .pixels
            .chunks_exact(3)
            .map(|c| egui::Color32::from_rgb(c[0], c[1], c[2]))
            .collect();

        Some(egui::ColorImage {
            size: [raw.width, raw.height],
            pixels,
        })
    }

    /// Cierra el manejador de camara y detiene la captura.
    pub fn close(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }

    /// Devuelve el frame raw capturado actualmente.
    pub fn get_raw_frame(&mut self) -> Option<RawFrame> {
        self.raw_frame.lock().ok()?.clone()
    }
}

/// Implementacion del trait Drop para CameraHandler.
impl Drop for CameraHandler {
    /// Limpia los recursos al eliminar la instancia.
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}
