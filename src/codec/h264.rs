//! Módulo para codificación y decodificación H.264 usando OpenH264

use openh264::OpenH264API;
use openh264::decoder::Decoder;
use openh264::encoder::{BitRate, Encoder, EncoderConfig, FrameRate, RateControlMode};
use openh264::formats::YUVSource;
use std::error::Error;

/// Frame decodificado en formato RGB
#[derive(Clone, Debug)]
pub struct DecodedFrame {
    pub data: Vec<u8>, // RGB bytes
    pub width: u32,
    pub height: u32,
}

/// Estructura para almacenar datos YUV420
struct YUV420 {
    y: Vec<u8>,
    u: Vec<u8>,
    v: Vec<u8>,
}

/// Decoder H.264
pub struct H264Decoder {
    decoder: Decoder,
    rgb_buffer: Vec<u8>,
}

/// Encoder H.264
pub struct H264Encoder {
    encoder: Encoder,
    width: u32,
    height: u32,
    yuv: YUV420,
}

/// Implementación de YUVSource para YUV420
pub struct YUV420Source<'a> {
    y: &'a [u8],
    u: &'a [u8],
    v: &'a [u8],
    width: usize,
    height: usize,
}

/// Implementación de YUVSource para YUV420
impl<'a> YUVSource for YUV420Source<'a> {
    /// Devuelve las dimensiones del frame YUV
    #[inline(always)]
    fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }

    /// Devuelve las planas Y
    #[inline(always)]
    fn y(&self) -> &[u8] {
        self.y
    }

    /// Devuelve las planas U
    #[inline(always)]
    fn u(&self) -> &[u8] {
        self.u
    }

    /// Devuelve las planas V
    #[inline(always)]
    fn v(&self) -> &[u8] {
        self.v
    }

    /// Devuelve los strides de las planas Y, U y V
    #[inline(always)]
    fn strides(&self) -> (usize, usize, usize) {
        (self.width, self.width / 2, self.width / 2)
    }
}

/// Implementación del encoder H.264
impl H264Encoder {
    /// Crea un nuevo encoder H.264
    pub fn new(width: u32, height: u32, fps: u32, bitrate: u32) -> Result<Self, Box<dyn Error>> {
        let api = OpenH264API::from_source();

        let cfg = EncoderConfig::new()
            .bitrate(BitRate::from_bps(bitrate))
            .max_frame_rate(FrameRate::from_hz(fps as f32))
            .rate_control_mode(RateControlMode::Bitrate);

        let encoder = Encoder::with_api_config(api, cfg)?;

        let y_size = (width * height) as usize;
        let uv_size = y_size / 4;

        Ok(Self {
            encoder,
            width,
            height,
            yuv: YUV420 {
                y: vec![0; y_size],
                u: vec![0; uv_size],
                v: vec![0; uv_size],
            },
        })
    }

    /// Codifica datos RGB a H.264
    pub fn encode(
        &mut self,
        rgb_data: &[u8],
        width: u32,
        height: u32,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        if width != self.width || height != self.height {
            return Err(format!(
                "Dimensiones incorrectas: esperado {}x{}, recibido {}x{}",
                self.width, self.height, width, height
            )
            .into());
        }

        let expected_size = (width * height * 3) as usize;
        if rgb_data.len() != expected_size {
            return Err(format!(
                "Tamaño de buffer incorrecto: esperado {}, recibido {}",
                expected_size,
                rgb_data.len()
            )
            .into());
        }

        rgb_to_yuv420_reusable(
            rgb_data,
            width,
            height,
            &mut self.yuv.y,
            &mut self.yuv.u,
            &mut self.yuv.v,
        );

        // Crear fuente YUV
        let yuv_source = YUV420Source {
            y: &self.yuv.y,
            u: &self.yuv.u,
            v: &self.yuv.v,
            width: width as usize,
            height: height as usize,
        };

        // Codificar
        let bitstream = self.encoder.encode(&yuv_source)?;

        Ok(bitstream.to_vec())
    }

    /// Fuerza la generación de un keyframe (IDR)
    pub fn force_keyframe(&mut self) -> Result<(), Box<dyn Error>> {
        self.encoder.force_intra_frame();
        Ok(())
    }

    pub fn enc_width(&self) -> u32 {
        self.width
    }
    pub fn enc_height(&self) -> u32 {
        self.height
    }
}

/// Implementación del decoder H.264
impl H264Decoder {
    /// Crea un nuevo decoder H.264
    pub fn new() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            decoder: Decoder::new()?,
            rgb_buffer: Vec::new(),
        })
    }

    /// Decodifica datos H.264 a RGB
    pub fn decode(&mut self, data: &[u8]) -> Result<DecodedFrame, Box<dyn Error>> {
        // Decodificar H.264
        let yuv_frame = self.decoder.decode(data)?;

        if let Some(yuv) = yuv_frame {
            let (width_usize, height_usize) = yuv.dimensions();
            let width = width_usize as u32;
            let height = height_usize as u32;

            // Determinar strides reales de las planas devueltas por OpenH264.
            // Muchos decoders alinean a múltiplos de 16, por lo que stride puede ser > width.
            let y_plane = yuv.y();
            let u_plane = yuv.u();
            let v_plane = yuv.v();

            let h = height as usize;
            let h2 = (height as usize).div_ceil(2); // seguridad si altura impar

            let y_stride = if h > 0 {
                y_plane.len() / h
            } else {
                width as usize
            };
            let u_stride = if h2 > 0 {
                u_plane.len() / h2
            } else {
                (width as usize).div_ceil(2)
            };
            let v_stride = if h2 > 0 {
                v_plane.len() / h2
            } else {
                (width as usize).div_ceil(2)
            };

            let needed = width as usize * height as usize * 3;
            if self.rgb_buffer.len() != needed {
                self.rgb_buffer.resize(needed, 0);
            }

            yuv420_to_rgb_strided_reusable(
                y_plane,
                u_plane,
                v_plane,
                width,
                height,
                y_stride,
                u_stride,
                v_stride,
                &mut self.rgb_buffer,
            );

            Ok(DecodedFrame {
                data: self.rgb_buffer.clone(),
                width,
                height,
            })
        } else {
            Err("No se pudo decodificar el frame H.264".into())
        }
    }
}

/// Convierte un frame RGB a YUV420
#[inline(always)]
fn rgb_to_yuv420_reusable(
    rgb: &[u8],
    width: u32,
    height: u32,
    y_out: &mut [u8],
    u_out: &mut [u8],
    v_out: &mut [u8],
) {
    let w = width as usize;
    let h = height as usize;

    let mut u_idx = 0;
    let mut v_idx = 0;

    for y in 0..h {
        let row_rgb = y * w * 3;
        let row_y = y * w;

        for x in 0..w {
            let idx_rgb = row_rgb + x * 3;

            let r = rgb[idx_rgb] as f32;
            let g = rgb[idx_rgb + 1] as f32;
            let b = rgb[idx_rgb + 2] as f32;

            // Y
            y_out[row_y + x] = (0.299 * r + 0.587 * g + 0.114 * b).clamp(0.0, 255.0) as u8;

            // U y V cada 2x2
            if (y & 1) == 0 && (x & 1) == 0 {
                u_out[u_idx] =
                    ((-0.169 * r - 0.331 * g + 0.500 * b) + 128.0).clamp(0.0, 255.0) as u8;
                v_out[v_idx] =
                    ((0.500 * r - 0.419 * g - 0.081 * b) + 128.0).clamp(0.0, 255.0) as u8;

                u_idx += 1;
                v_idx += 1;
            }
        }
    }
}

/// Convierte un frame YUV420 a RGB con strides personalizados
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn yuv420_to_rgb_strided_reusable(
    y: &[u8],
    u: &[u8],
    v: &[u8],
    width: u32,
    height: u32,
    y_stride: usize,
    u_stride: usize,
    v_stride: usize,
    rgb_out: &mut [u8],
) {
    let w = width as usize;
    let h = height as usize;

    for y_coord in 0..h {
        let y_row = y_coord * y_stride;
        let u_row = (y_coord >> 1) * u_stride;
        let v_row = (y_coord >> 1) * v_stride;

        // Precompute row start in output
        let out_row = y_coord * w * 3;

        for x in 0..w {
            // Read Y normally
            let y_val = y[y_row + x] as i32;

            // U/V are subsampled -> same U/V applies to 2 pixels
            let uv_index = x >> 1;

            let u_val = (u[u_row + uv_index] as i32) - 128;
            let v_val = (v[v_row + uv_index] as i32) - 128;

            // Precompute UV mixed terms
            let rv = 179 * v_val; // 1.402 * 128 ≈ 179
            let guv = 44 * u_val + 91 * v_val; // 0.344*128+0.714*128 ≈ (44+91)
            let bu = 227 * u_val; // 1.772 * 128 ≈ 227

            // Scale Y for integer math
            let y_scaled = y_val << 8; // *256

            // Calculate RGB with integer fast approx
            let r = (y_scaled + rv) >> 8;
            let g = (y_scaled - guv) >> 8;
            let b = (y_scaled + bu) >> 8;

            // Clamp manually (faster que clamp() de f32)
            let r = r.clamp(0, 255) as u8;
            let g = g.clamp(0, 255) as u8;
            let b = b.clamp(0, 255) as u8;

            let idx = out_row + x * 3;
            rgb_out[idx] = r;
            rgb_out[idx + 1] = g;
            rgb_out[idx + 2] = b;
        }
    }
}
