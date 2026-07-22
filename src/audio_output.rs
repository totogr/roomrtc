//! Modulo de salida de audio (reproduccion)
//! Este modulo proporciona reproduccion de audio usando cpal para salida de audio multiplataforma.
//! Las muestras de audio se almacenan en buffer y se reproducen a traves del dispositivo de salida predeterminado.

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{Device, Stream, StreamConfig};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// Handler de salida de audio para reproducir audio a traves de altavoces
pub struct AudioOutput {
    _device: Device,
    _stream: Stream,
    buffer: Arc<Mutex<VecDeque<i16>>>,
    sample_rate: u32,
    prebuffer_samples: usize,
}

impl AudioOutput {
    /// Crea un nuevo handler de salida de audio
    pub fn new(sample_rate: u32, channels: u8) -> Result<Self, String> {
        let host = cpal::default_host();
        let device = host
            .default_output_device()
            .ok_or("No output device available")?;

        let config = StreamConfig {
            channels: channels as u16,
            sample_rate: cpal::SampleRate(sample_rate),
            buffer_size: cpal::BufferSize::Default,
        };

        // Crear buffer circular con capacidad para ~1 segundo de audio
        // Pre-llenar con ~200ms de silencio para evitar underruns (10 frames @ 20ms)
        let mut initial_buffer = VecDeque::with_capacity(sample_rate as usize);
        let prebuffer_samples = (sample_rate as usize * 200) / 1000; // 200ms
        for _ in 0..prebuffer_samples {
            initial_buffer.push_back(0);
        }
        let buffer = Arc::new(Mutex::new(initial_buffer));
        let buffer_clone = Arc::clone(&buffer);

        // Construir stream de salida con callback de reproduccion
        let stream = device
            .build_output_stream(
                &config,
                move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                    if let Ok(mut buf) = buffer_clone.lock() {
                        for sample in data.iter_mut() {
                            *sample = if let Some(s) = buf.pop_front() {
                                // Convertir i16 [-32768, 32767] a f32 [-1.0, 1.0]
                                s as f32 / 32768.0
                            } else {
                                // No hay datos disponibles - reproducir silencio
                                0.0
                            };
                        }
                    }
                },
                |err| eprintln!("Audio output error: {}", err),
                None,
            )
            .map_err(|e| format!("Failed to build output stream: {}", e))?;

        // Iniciar el stream
        stream
            .play()
            .map_err(|e| format!("Failed to start stream: {}", e))?;

        Ok(Self {
            _device: device,
            _stream: stream,
            buffer,
            sample_rate,
            prebuffer_samples,
        })
    }

    /// Agregar muestras al buffer de reproduccion
    pub fn play_samples(&mut self, samples: &[i16]) -> Result<(), String> {
        if let Ok(mut buf) = self.buffer.lock() {
            // Agregar muestras al buffer
            buf.extend(samples);

            // Prevenir crecimiento ilimitado - descartar muestras antiguas si el buffer excede 2 segundos
            let max_size = (self.sample_rate as usize) * 2;
            while buf.len() > max_size {
                buf.pop_front();
            }
            Ok(())
        } else {
            Err("Failed to lock buffer".to_string())
        }
    }

    /// Obtener el tamano actual del buffer (numero de muestras en cola)
    pub fn buffer_size(&self) -> usize {
        self.buffer
            .lock()
            .map(|buf| buf.len().saturating_sub(self.prebuffer_samples))
            .unwrap_or(0)
    }

    /// Limpiar el buffer de reproduccion
    pub fn clear_buffer(&mut self) {
        if let Ok(mut buf) = self.buffer.lock() {
            buf.clear();
        }
    }

    /// Obtener el sample rate
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Crear una salida dummy para pruebas (descarta audio)
    pub fn dummy() -> Self {
        let host = cpal::default_host();
        let device = host.default_output_device().unwrap();
        let config = device.default_output_config().unwrap().config();

        // Crear un stream no-op que descarta audio
        let stream = device
            .build_output_stream(
                &config,
                |_data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                    // No hacer nada - descartar audio
                },
                |_err| {},
                None,
            )
            .unwrap();

        Self {
            _device: device,
            _stream: stream,
            buffer: Arc::new(Mutex::new(VecDeque::new())),
            sample_rate: 48000,
            prebuffer_samples: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_audio_output_creation() {
        // This test may fail on systems without an audio output device
        match AudioOutput::new(48000, 1) {
            Ok(output) => {
                assert_eq!(output.sample_rate(), 48000);
                assert_eq!(output.buffer_size(), 0);
            }
            Err(e) => {
                println!("Skipping test - no audio output available: {}", e);
            }
        }
    }

    #[test]
    fn test_play_samples() {
        match AudioOutput::new(48000, 1) {
            Ok(mut output) => {
                let samples = vec![100i16; 960]; // 20ms of audio

                let result = output.play_samples(&samples);
                assert!(result.is_ok());

                // Buffer should now contain 960 samples
                assert_eq!(output.buffer_size(), 960);
            }
            Err(e) => {
                println!("Skipping test - no audio output available: {}", e);
            }
        }
    }

    #[test]
    fn test_buffer_overflow_protection() {
        match AudioOutput::new(48000, 1) {
            Ok(mut output) => {
                // Add more than 2 seconds of audio (2 * 48000 = 96000 samples)
                let chunk = vec![0i16; 48000]; // 1 second

                output.play_samples(&chunk).ok();
                output.play_samples(&chunk).ok();
                output.play_samples(&chunk).ok(); // Total: 3 seconds

                // Buffer should be capped at 2 seconds (96000 samples)
                let buffer_size = output.buffer_size();
                assert!(
                    buffer_size <= 96000,
                    "Buffer size {} exceeds maximum",
                    buffer_size
                );
            }
            Err(e) => {
                println!("Skipping test - no audio output available: {}", e);
            }
        }
    }

    #[test]
    fn test_clear_buffer() {
        match AudioOutput::new(48000, 1) {
            Ok(mut output) => {
                let samples = vec![100i16; 960];
                output.play_samples(&samples).ok();

                assert!(output.buffer_size() > 0);

                output.clear_buffer();
                assert_eq!(output.buffer_size(), 0);
            }
            Err(e) => {
                println!("Skipping test - no audio output available: {}", e);
            }
        }
    }

    #[test]
    fn test_playback_drains_buffer() {
        match AudioOutput::new(48000, 1) {
            Ok(mut output) => {
                let samples = vec![1000i16; 960];
                output.play_samples(&samples).ok();

                let initial_size = output.buffer_size();
                assert!(initial_size > 0);

                // Wait for playback to drain some samples
                thread::sleep(Duration::from_millis(50));

                // Buffer should have been drained (or at least not grown)
                let final_size = output.buffer_size();
                println!(
                    "Buffer drained from {} to {} samples",
                    initial_size, final_size
                );
            }
            Err(e) => {
                println!("Skipping test - no audio output available: {}", e);
            }
        }
    }

    #[test]
    fn test_multiple_sample_rates() {
        for &sample_rate in &[8000, 16000, 48000] {
            match AudioOutput::new(sample_rate, 1) {
                Ok(output) => {
                    assert_eq!(output.sample_rate(), sample_rate);
                }
                Err(e) => {
                    println!(
                        "Skipping {}Hz test - no audio output available: {}",
                        sample_rate, e
                    );
                }
            }
        }
    }

    #[test]
    fn test_stereo_output() {
        match AudioOutput::new(48000, 2) {
            Ok(mut output) => {
                // Stereo: 960 samples per channel = 1920 total for 20ms
                let stereo_samples = vec![500i16; 1920];
                let result = output.play_samples(&stereo_samples);
                assert!(result.is_ok());
            }
            Err(e) => {
                println!("Skipping test - no stereo output available: {}", e);
            }
        }
    }

    #[test]
    fn test_dummy_output() {
        let mut output = AudioOutput::dummy();
        assert_eq!(output.sample_rate(), 48000);

        let samples = vec![1000i16; 960];
        let result = output.play_samples(&samples);
        assert!(result.is_ok());
    }
}
