//! Image admission checks before decoding or RGB expansion.

use base64::Engine;
use image::{ImageFormat, ImageReader, Limits};
use sable_core::biometric::PalmImage;
use std::io::Cursor;

const MAX_COMPRESSED_BYTES: usize = 2 * 1024 * 1024;
const MAX_BASE64_BYTES: usize = MAX_COMPRESSED_BYTES.div_ceil(3) * 4;

#[derive(Clone, Copy)]
pub(crate) enum CaptureImage {
    Frame,
    Eye,
}

pub(crate) fn decode(input: &str, kind: CaptureImage) -> Result<PalmImage, String> {
    // Bound the complete string before searching for prefixes or allocating bytes.
    if input.len() > MAX_BASE64_BYTES + 32 {
        return Err("Encoded image exceeds size limit".into());
    }
    let encoded = if input.starts_with("data:") {
        input.strip_prefix("data:image/jpeg;base64,")
            .or_else(|| input.strip_prefix("data:image/png;base64,"))
            .ok_or("Unsupported image data URL")?
    } else { input };
    if encoded.is_empty() || encoded.len() > MAX_BASE64_BYTES {
        return Err("Encoded image exceeds size limit".into());
    }
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded)
        .map_err(|_| "Invalid image base64")?;
    if bytes.len() > MAX_COMPRESSED_BYTES {
        return Err("Compressed image exceeds size limit".into());
    }
    let format = image::guess_format(&bytes).map_err(|_| "Unknown image format")?;
    if !matches!(format, ImageFormat::Jpeg | ImageFormat::Png)
        || (matches!(kind, CaptureImage::Frame) && format != ImageFormat::Jpeg)
    {
        return Err("Unsupported capture image format".into());
    }
    let (max_width, max_height, max_pixels, max_alloc) = match kind {
        CaptureImage::Frame => (1920, 1080, 1920u64 * 1080, 24 * 1024 * 1024),
        CaptureImage::Eye => (256, 256, 256u64 * 256, 2 * 1024 * 1024),
    };
    let mut limits = Limits::default();
    limits.max_image_width = Some(max_width);
    limits.max_image_height = Some(max_height);
    limits.max_alloc = Some(max_alloc);

    // Header-only pass: check dimensions before output allocation or RGB conversion.
    // PNG receives allocation limits at decoder creation; JPEG's compressed input
    // is already bounded above. All decoders receive strict dimension limits.
    let mut header = ImageReader::with_format(Cursor::new(&bytes), format);
    header.limits(limits.clone());
    let (width, height) = header.into_dimensions()
        .map_err(|_| "Invalid image metadata or dimensions exceed limits")?;
    let pixels = u64::from(width).checked_mul(u64::from(height))
        .ok_or("Image dimensions overflow")?;
    if width == 0 || height == 0 || pixels > max_pixels {
        return Err("Image dimensions exceed limits".into());
    }
    let rgb_bytes = pixels.checked_mul(3).ok_or("Image size overflow")?;
    if rgb_bytes > isize::MAX as u64 {
        return Err("Image size exceeds addressable memory".into());
    }
    let mut reader = ImageReader::with_format(Cursor::new(&bytes), format);
    reader.limits(limits);
    let image = reader.decode().map_err(|_| "Image decoding failed or allocation limit exceeded")?;
    let rgb = image.into_rgb8();
    Ok(PalmImage::new(width, height, 3, rgb.into_raw()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::ImageEncoder;

    fn encoded(width: u32, height: u32, format: ImageFormat) -> String {
        let data = vec![100; width as usize * height as usize * 3];
        let mut bytes = Vec::new();
        match format {
            ImageFormat::Png => image::codecs::png::PngEncoder::new(&mut bytes)
                .write_image(&data, width, height, image::ExtendedColorType::Rgb8).unwrap(),
            _ => image::codecs::jpeg::JpegEncoder::new(&mut bytes)
                .write_image(&data, width, height, image::ExtendedColorType::Rgb8).unwrap(),
        }
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn accepts_normal_capture_and_lossless_eye_crops() {
        let frame = encoded(640, 480, ImageFormat::Jpeg);
        assert_eq!(decode(&frame, CaptureImage::Frame).unwrap().width, 640);
        let eye = encoded(16, 16, ImageFormat::Png);
        assert_eq!(decode(&format!("data:image/png;base64,{eye}"), CaptureImage::Eye).unwrap().height, 16);
        assert!(decode(&eye, CaptureImage::Frame).is_err());
    }

    #[test]
    fn rejects_oversized_dimensions_from_small_valid_images() {
        for (width, height) in [(1921, 1), (1, 1081)] {
            let frame = encoded(width, height, ImageFormat::Jpeg);
            assert!(frame.len() < 10_000);
            assert!(decode(&frame, CaptureImage::Frame).unwrap_err().contains("metadata"));
        }
        for (width, height) in [(257, 1), (1, 257)] {
            assert!(decode(&encoded(width, height, ImageFormat::Png), CaptureImage::Eye).is_err());
        }
    }

    #[test]
    fn rejects_oversized_encoded_inputs_and_malformed_urls() {
        assert!(decode(&"A".repeat(MAX_BASE64_BYTES + 33), CaptureImage::Frame).is_err());
        for input in ["", "garbage", "data:text/plain;base64,AAAA", "unexpected,AAAA"] {
            assert!(decode(input, CaptureImage::Eye).is_err());
        }
    }
}
