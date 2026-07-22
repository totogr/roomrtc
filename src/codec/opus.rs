/// Implementación del códec Opus
use opus::{Application, Channels, Decoder as OpusDecoderImpl, Encoder as OpusEncoderImpl};

/// Encoder Opus - Convierte PCM de 16 bits a Opus comprimido
pub struct OpusEncoder {
    encoder: OpusEncoderImpl,
    sample_rate: u32,
    channels: Channels,
    frame_size: usize, // Samples por frame (ej. 960 para 20ms @ 48kHz)
}

impl OpusEncoder {
    /// Crea un nuevo encoder Opus
    pub fn new(
        sample_rate: u32,
        channels: Channels,
        application: Application,
    ) -> Result<Self, opus::Error> {
        let encoder = OpusEncoderImpl::new(sample_rate, channels, application)?;
        let frame_size = (sample_rate as usize * 20) / 1000;

        Ok(Self {
            encoder,
            sample_rate,
            channels,
            frame_size,
        })
    }

    /// Establece el bitrate en bits por segundo
    pub fn set_bitrate(&mut self, bitrate: i32) -> Result<(), opus::Error> {
        self.encoder.set_bitrate(opus::Bitrate::Bits(bitrate))
    }

    /// Codifica samples PCM a Opus
    pub fn encode(&mut self, pcm: &[i16], output: &mut [u8]) -> Result<usize, opus::Error> {
        self.encoder.encode(pcm, output)
    }

    /// Obtiene el frame size (samples por frame de 20ms)
    pub fn frame_size(&self) -> usize {
        self.frame_size
    }

    /// Obtiene el sample rate
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Obtiene los channels
    pub fn channels(&self) -> Channels {
        self.channels
    }
}

/// Decoder Opus - Convierte Opus a PCM de 16 bits
pub struct OpusDecoder {
    decoder: OpusDecoderImpl,
    sample_rate: u32,
    channels: Channels,
    frame_size: usize,
}

impl OpusDecoder {
    /// Crea un nuevo decoder Opus
    pub fn new(sample_rate: u32, channels: Channels) -> Result<Self, opus::Error> {
        let decoder = OpusDecoderImpl::new(sample_rate, channels)?;
        let frame_size = (sample_rate as usize * 20) / 1000;

        Ok(Self {
            decoder,
            sample_rate,
            channels,
            frame_size,
        })
    }

    /// Decodifica datos Opus a PCM
    pub fn decode(
        &mut self,
        opus_data: &[u8],
        output: &mut [i16],
        fec: bool,
    ) -> Result<usize, opus::Error> {
        self.decoder.decode(opus_data, output, fec)
    }

    /// Decodifica con packet loss concealment
    pub fn decode_plc(&mut self, output: &mut [i16]) -> Result<usize, opus::Error> {
        // Decodifica con PLC cuando se pierde un paquete
        self.decoder.decode(&[], output, true)
    }

    /// Obtiene el frame size
    pub fn frame_size(&self) -> usize {
        self.frame_size
    }

    /// Obtiene el sample rate
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Obtiene los channels
    pub fn channels(&self) -> Channels {
        self.channels
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoder_creation() {
        let encoder = OpusEncoder::new(48000, Channels::Mono, Application::Voip);
        assert!(encoder.is_ok());

        let encoder = encoder.unwrap();
        assert_eq!(encoder.sample_rate(), 48000);
        assert_eq!(encoder.frame_size(), 960); // 20ms @ 48kHz
    }

    #[test]
    fn test_decoder_creation() {
        let decoder = OpusDecoder::new(48000, Channels::Mono);
        assert!(decoder.is_ok());

        let decoder = decoder.unwrap();
        assert_eq!(decoder.sample_rate(), 48000);
        assert_eq!(decoder.frame_size(), 960);
    }

    #[test]
    fn test_encode_decode_silence() {
        let mut encoder = OpusEncoder::new(48000, Channels::Mono, Application::Voip).unwrap();
        let mut decoder = OpusDecoder::new(48000, Channels::Mono).unwrap();

        // Crear silencio (960 samples = 20ms @ 48kHz)
        let silence = vec![0i16; 960];
        let mut encoded = vec![0u8; 4000];

        // Codificar
        let encoded_len = encoder.encode(&silence, &mut encoded).unwrap();
        assert!(encoded_len > 0);
        assert!(encoded_len < 4000);

        // Decodificar
        let mut decoded = vec![0i16; 5760]; // Max frame size
        let decoded_len = decoder
            .decode(&encoded[..encoded_len], &mut decoded, false)
            .unwrap();

        assert_eq!(decoded_len, 960);

        // El silencio decodificado debe estar cerca de cero
        for &sample in &decoded[..decoded_len] {
            assert!(
                sample.abs() < 100,
                "Decoded silence sample too loud: {}",
                sample
            );
        }
    }

    #[test]
    fn test_bitrate_setting() {
        let mut encoder = OpusEncoder::new(48000, Channels::Mono, Application::Voip).unwrap();

        // Probar varios bitrates
        assert!(encoder.set_bitrate(8000).is_ok()); // 8 kbps
        assert!(encoder.set_bitrate(32000).is_ok()); // 32 kbps
        assert!(encoder.set_bitrate(64000).is_ok()); // 64 kbps
        assert!(encoder.set_bitrate(128000).is_ok()); // 128 kbps
    }

    #[test]
    fn test_packet_loss_concealment() {
        let mut decoder = OpusDecoder::new(48000, Channels::Mono).unwrap();

        // Simular pérdida de paquete con PLC
        let mut plc_output = vec![0i16; 5760];
        let plc_len = decoder.decode_plc(&mut plc_output).unwrap();

        // PLC puede retornar varios frame sizes dependiendo del estado interno
        // Solo verificar que retorna una cantidad razonable de samples
        assert!(plc_len > 0, "PLC should generate samples");
        assert!(plc_len <= 5760, "PLC should not exceed buffer size");

        println!("PLC generated {} samples", plc_len);
    }

    #[test]
    fn test_multiple_sample_rates() {
        // Probar 8kHz
        let encoder_8k = OpusEncoder::new(8000, Channels::Mono, Application::Voip);
        assert!(encoder_8k.is_ok());
        assert_eq!(encoder_8k.unwrap().frame_size(), 160); // 20ms @ 8kHz

        // Probar 16kHz
        let encoder_16k = OpusEncoder::new(16000, Channels::Mono, Application::Voip);
        assert!(encoder_16k.is_ok());
        assert_eq!(encoder_16k.unwrap().frame_size(), 320); // 20ms @ 16kHz

        // Probar 48kHz
        let encoder_48k = OpusEncoder::new(48000, Channels::Mono, Application::Voip);
        assert!(encoder_48k.is_ok());
        assert_eq!(encoder_48k.unwrap().frame_size(), 960); // 20ms @ 48kHz
    }

    #[test]
    fn test_stereo_encoding() {
        let mut encoder = OpusEncoder::new(48000, Channels::Stereo, Application::Audio).unwrap();
        let mut decoder = OpusDecoder::new(48000, Channels::Stereo).unwrap();

        // Stereo: 960 samples por channel = 1920 total para 20ms @ 48kHz
        let stereo_samples = vec![0i16; 1920];
        let mut encoded = vec![0u8; 4000];

        let encoded_len = encoder.encode(&stereo_samples, &mut encoded).unwrap();
        assert!(encoded_len > 0);

        let mut decoded = vec![0i16; 11520]; // Buffer grande para stereo
        let decoded_len = decoder
            .decode(&encoded[..encoded_len], &mut decoded, false)
            .unwrap();

        // Opus retorna samples por channel para stereo, entonces 960 samples = 960 samples/channel
        // lo que significa 1920 samples totales (960 * 2 channels)
        assert_eq!(decoded_len, 960); // Samples per channel
    }

    #[test]
    fn test_frame_size_consistency() {
        let encoder = OpusEncoder::new(48000, Channels::Mono, Application::Voip).unwrap();
        let decoder = OpusDecoder::new(48000, Channels::Mono).unwrap();

        assert_eq!(encoder.frame_size(), decoder.frame_size());
        assert_eq!(encoder.frame_size(), 960);
    }
}
