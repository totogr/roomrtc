//! Módulo de captura de audio del micrófono
//! Este módulo proporciona acceso al micrófono usando cpal para entrada de audio multiplataforma.

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{Stream, StreamConfig};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Representa un frame de audio capturado
#[derive(Debug, Clone)]
pub struct AudioFrame {
    pub samples: Vec<i16>, // Samples PCM de 16 bits
    pub sample_rate: u32,  // Sample rate (ej., 48000)
    pub channels: u8,      // Numero de channels (1 para mono)
}

/// Handler de micrófono para captura de audio
pub struct MicrophoneHandler {
    frame_queue: Arc<Mutex<VecDeque<AudioFrame>>>,
    muted: Arc<AtomicBool>,
    _stream: Stream,
    sample_rate: u32,
    frame_size: usize,
}

impl MicrophoneHandler {
    /// Crea un nuevo handler de micrófono
    pub fn new(sample_rate: u32) -> Result<Self, String> {
        let host = cpal::default_host();
        let device = host
            .default_input_device()
            .ok_or("No input device available")?;

        let config = StreamConfig {
            channels: 1,
            sample_rate: cpal::SampleRate(sample_rate),
            buffer_size: cpal::BufferSize::Default,
        };

        // Calcular frame size para 20ms
        let frame_size = (sample_rate as usize * 20) / 1000;

        // Cola para almacenar hasta 5 frames (100ms de buffer)
        let frame_queue = Arc::new(Mutex::new(VecDeque::with_capacity(5)));
        let muted = Arc::new(AtomicBool::new(false));

        let frame_queue_clone = Arc::clone(&frame_queue);
        let muted_clone = Arc::clone(&muted);
        let mut buffer = Vec::with_capacity(frame_size * 2);

        // Construir stream de entrada con callback
        let stream = device
            .build_input_stream(
                &config,
                move |data: &[f32], _: &cpal::InputCallbackInfo| {
                    // Convertir samples f32 a i16
                    for &sample in data {
                        let sample_i16 = if muted_clone.load(Ordering::Relaxed) {
                            0 // Muteado: emitir silencio
                        } else {
                            // Convertir f32 [-1.0, 1.0] a i16 [-32768, 32767]
                            (sample * 32767.0).clamp(-32768.0, 32767.0) as i16
                        };
                        buffer.push(sample_i16);

                        // Cuando tenemos un frame completo, agregarlo a la cola
                        if buffer.len() >= frame_size {
                            let frame = AudioFrame {
                                samples: buffer.drain(..frame_size).collect(),
                                sample_rate,
                                channels: 1,
                            };
                            if let Ok(mut queue) = frame_queue_clone.lock() {
                                queue.push_back(frame);
                                // Limitar el tamaño de la cola a 5 frames para evitar latencia excesiva
                                while queue.len() > 5 {
                                    queue.pop_front();
                                }
                            }
                        }
                    }
                },
                |err| eprintln!("Audio input error: {}", err),
                None,
            )
            .map_err(|e| format!("Failed to build input stream: {}", e))?;

        // Iniciar el stream
        stream
            .play()
            .map_err(|e| format!("Failed to start stream: {}", e))?;

        Ok(Self {
            frame_queue,
            muted,
            _stream: stream,
            sample_rate,
            frame_size,
        })
    }

    /// Obtener el siguiente frame de audio de la cola (non-blocking)
    pub fn get_samples(&mut self) -> Option<AudioFrame> {
        self.frame_queue.lock().ok()?.pop_front()
    }

    /// Establecer el estado de mute
    /// Cuando esta muteado, el microfono emitira silencio en lugar de audio real.
    pub fn set_muted(&self, muted: bool) {
        self.muted.store(muted, Ordering::Relaxed);
    }

    /// Verificar si el microfono esta actualmente muteado
    pub fn is_muted(&self) -> bool {
        self.muted.load(Ordering::Relaxed)
    }

    /// Obtener el frame size (samples por frame)
    pub fn frame_size(&self) -> usize {
        self.frame_size
    }

    /// Obtener el sample rate
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_microphone_creation() {
        match MicrophoneHandler::new(48000) {
            Ok(mic) => {
                assert_eq!(mic.sample_rate(), 48000);
                assert_eq!(mic.frame_size(), 960); // 20ms @ 48kHz
                assert!(!mic.is_muted());
            }
            Err(e) => {
                println!("No hay micrófono disponible: {}", e);
            }
        }
    }

    #[test]
    fn test_mute_functionality() {
        match MicrophoneHandler::new(48000) {
            Ok(mic) => {
                assert!(!mic.is_muted());

                mic.set_muted(true);
                assert!(mic.is_muted());

                mic.set_muted(false);
                assert!(!mic.is_muted());
            }
            Err(e) => {
                println!("No hay micrófono disponible: {}", e);
            }
        }
    }

    #[test]
    fn test_audio_frame_capture() {
        match MicrophoneHandler::new(48000) {
            Ok(mut mic) => {
                // Esperar un poco para que el micrófono empiece a capturar
                thread::sleep(Duration::from_millis(100));

                // Intentar obtener un frame
                let frame = mic.get_samples();

                // Podemos o no obtener un frame dependiendo del timing
                if let Some(frame) = frame {
                    assert_eq!(frame.sample_rate, 48000);
                    assert_eq!(frame.channels, 1);
                    assert_eq!(frame.samples.len(), 960);
                    println!(
                        "Frame de audio capturado con {} samples",
                        frame.samples.len()
                    );
                }
            }
            Err(e) => {
                println!("No hay micrófono disponible: {}", e);
            }
        }
    }

    #[test]
    fn test_muted_audio_is_silent() {
        match MicrophoneHandler::new(48000) {
            Ok(mut mic) => {
                // Mutear el micrófono
                mic.set_muted(true);

                // Esperar captura
                thread::sleep(Duration::from_millis(100));

                // Obtener samples
                if let Some(frame) = mic.get_samples() {
                    // Todos los samples deben ser 0 cuando esta muteado
                    let all_silent = frame.samples.iter().all(|&s| s == 0);
                    assert!(
                        all_silent,
                        "Micrófono muteado debe producir frames silenciosos"
                    );
                }
            }
            Err(e) => {
                println!("No hay micrófono disponible: {}", e);
            }
        }
    }

    #[test]
    fn test_multiple_sample_rates() {
        // Probar diferentes sample rates comunes
        for &sample_rate in &[8000, 16000, 48000] {
            match MicrophoneHandler::new(sample_rate) {
                Ok(mic) => {
                    assert_eq!(mic.sample_rate(), sample_rate);
                    let expected_frame_size = (sample_rate as usize * 20) / 1000;
                    assert_eq!(mic.frame_size(), expected_frame_size);
                }
                Err(e) => {
                    println!(
                        "Saltando test de {}Hz - No hay micrófono disponible: {}",
                        sample_rate, e
                    );
                }
            }
        }
    }

    #[test]
    fn test_frame_size_calculation() {
        if let Ok(mic) = MicrophoneHandler::new(48000) {
            assert_eq!(mic.frame_size(), 960);
        }

        if let Ok(mic) = MicrophoneHandler::new(16000) {
            assert_eq!(mic.frame_size(), 320);
        }
    }
}
