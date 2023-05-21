// Copyright (c) 2023 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub const FILLED_CHAR: char = '█';
pub const EMPTY_CHAR: char = ' ';
pub const NEW_LINE: char = '\n';

#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum QrCodeError {
    #[error("Given data is too long to fit in a QR code: {0}")]
    DataTooLong(usize),
}

pub trait QrCode: Sized {
    type Error;

    /// QR Codes are strictly squares, so this returns the side length
    fn side_length(&self) -> usize;

    /// Returns the pixel at coordinate (x, y) if it exists, otherwise None
    fn pixel(&self, x: usize, y: usize) -> Option<bool>;

    /// If the pixel is out of bounds, return false
    fn pixel_or_false(&self, x: usize, y: usize) -> bool {
        self.pixel(x, y).unwrap_or(false)
    }

    /// Returns the QR code as a vector of booleans, where true represents a filled pixel and false
    /// This contains the all the information required to reconstruct the QR code. The side-length
    /// can be calculated by taking the square root of the length of the vector
    fn as_vec(&self) -> Vec<bool> {
        let mut result = Vec::with_capacity(self.side_length() * self.side_length());
        for y in 0..self.side_length() {
            for x in 0..self.side_length() {
                result.push(self.pixel_or_false(x, y));
            }
        }
        result
    }

    /// Returns a string representation of the QR code, using the given characters as placeholders
    /// for empty and filled pixels, and the new line character
    /// border_size is the number of pixels to add around the QR code
    #[must_use]
    fn encode_to_string(
        &self,
        border_size: u8,
        empty_char: char,
        filled_char: char,
        new_line: char,
    ) -> String {
        let mut result = String::new();
        let border: i32 = border_size as i32;
        for y in -border..self.side_length() as i32 + border {
            for x in -border..self.side_length() as i32 + border {
                let c: char = if self.pixel_or_false(x as usize, y as usize) {
                    filled_char
                } else {
                    empty_char
                };
                result.push(c);
                result.push(c);
            }
            result.push(new_line)
        }
        result.push(new_line);
        result
    }

    /// Returns a string representation of the QR code, using the default characters as placeholders
    /// for empty and filled pixels, and the new line character
    #[must_use]
    fn encode_to_string_with_defaults(&self, border_size: u8) -> String {
        self.encode_to_string(border_size, EMPTY_CHAR, FILLED_CHAR, NEW_LINE)
    }
}

impl QrCode for qrcodegen::QrCode {
    type Error = QrCodeError;

    fn side_length(&self) -> usize {
        self.size() as usize
    }

    fn pixel(&self, x: usize, y: usize) -> Option<bool> {
        if (0..self.side_length()).contains(&x) && (0..self.side_length()).contains(&y) {
            Some(self.get_module(x as i32, y as i32))
        } else {
            None
        }
    }
}

/// Constructs QR Code from a string
pub fn qrcode_from_str<S: AsRef<str>>(s: S) -> Result<impl QrCode, QrCodeError> {
    let errcorlvl = qrcodegen::QrCodeEcc::Medium; // Error correction level

    let qr = qrcodegen::QrCode::encode_text(s.as_ref(), errcorlvl)
        .map_err(|_| QrCodeError::DataTooLong(s.as_ref().len()))?;

    Ok(qr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_world_str() {
        let text: &'static str = "Hello, world!";
        let qr = super::qrcode_from_str(text).unwrap();
        let expected = [
            1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0,
            0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0,
            1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1,
            1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1,
            1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1,
            1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1,
            1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1,
            0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0,
            1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1,
            0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1,
            1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0,
            0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1,
            1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0,
            0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1,
            0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1,
            0, 1, 0, 0, 1, 0,
        ];
        assert_eq!(
            qr.as_vec().into_iter().map(|v| v as u32).collect::<Vec<_>>(),
            expected
        );
    }

    #[test]
    fn pi_str() {
        let text = "314159265358979323846264338327950288419716939937510";
        let qr = super::qrcode_from_str(text).unwrap();
        let expected = [
            1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0,
            0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0,
            0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1,
            1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1,
            0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0,
            0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1,
            1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1,
            1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0,
            0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1,
            0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0,
            0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1,
            0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1,
            1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0,
            0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0,
            1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
            1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0,
            0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0,
            0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1,
            0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1,
            0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0,
            0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1,
            0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1,
        ];
        assert_eq!(
            qr.as_vec().into_iter().map(|v| v as u32).collect::<Vec<_>>(),
            expected
        );
    }
}
