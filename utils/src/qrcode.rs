pub const FILLED_CHAR: char = '█';
pub const EMPTY_CHAR: char = ' ';

#[derive(thiserror::Error, Debug)]
pub enum QrCodeError {
    #[error("Given data is too long to fit in a QR code: {0}")]
    DataTooLong(usize),
}

pub trait QrCode: Sized {
    type Error;

    /// Constructs QR Code from a string
    fn from_str<S: AsRef<str>>(s: S) -> Result<Self, Self::Error>;

    /// Constructs QR Code from binary data
    fn from_data<D: AsRef<[u8]>>(data: D) -> Result<Self, Self::Error>;

    /// QR Codes are strictly squares, so this returns the side length
    fn side_length(&self) -> usize;

    /// Returns the pixel at coordinate (x, y) if it exists, otherwise None
    fn pixel(&self, x: usize, y: usize) -> Option<bool>;

    /// If the pixel is out of bounds, return false
    fn pixel_or_false(&self, x: usize, y: usize) -> bool {
        self.pixel(x, y).unwrap_or(false)
    }
}

struct QrCodeImpl(qrcodegen::QrCode);

impl QrCode for QrCodeImpl {
    type Error = QrCodeError;

    fn from_str<S: AsRef<str>>(s: S) -> Result<Self, Self::Error> {
        let errcorlvl = qrcodegen::QrCodeEcc::Low; // Error correction level

        let qr = qrcodegen::QrCode::encode_text(s.as_ref(), errcorlvl)
            .map_err(|_| QrCodeError::DataTooLong(s.as_ref().len()))?;

        Ok(QrCodeImpl(qr))
    }

    fn from_data<D: AsRef<[u8]>>(data: D) -> Result<Self, Self::Error> {
        let errcorlvl = qrcodegen::QrCodeEcc::Low; // Error correction level

        let qr = qrcodegen::QrCode::encode_binary(data.as_ref(), errcorlvl)
            .map_err(|_| QrCodeError::DataTooLong(data.as_ref().len()))?;

        Ok(QrCodeImpl(qr))
    }

    fn side_length(&self) -> usize {
        self.0.size() as usize
    }

    fn pixel(&self, x: usize, y: usize) -> Option<bool> {
        if (0..self.side_length()).contains(&x) && (0..self.side_length()).contains(&y) {
            Some(self.0.get_module(x as i32, y as i32))
        } else {
            None
        }
    }
}
