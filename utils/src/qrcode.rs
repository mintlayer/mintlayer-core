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

#[derive(thiserror::Error, Debug, Eq, PartialEq, Clone, PartialOrd, Ord)]
pub enum QrCodeError {
    #[error("Given data is too long to fit in a QR code: {0}")]
    DataTooLong(usize),
    #[error("Border scaling failed. Possible very large border size: {0}")]
    BorderScalingFailed(u32),
}

pub trait QrCode {
    /// QR Codes are strictly squares, so this returns the side length
    #[must_use]
    fn side_length(&self) -> usize;

    /// Returns the pixel at coordinate (x, y) if it exists, otherwise None
    #[must_use]
    fn pixel(&self, x: usize, y: usize) -> Option<bool>;

    /// If the pixel is out of bounds, return false
    #[must_use]
    fn pixel_or_false(&self, x: usize, y: usize) -> bool {
        self.pixel(x, y).unwrap_or(false)
    }

    /// Returns the QR code as a vector of booleans, where true represents a filled pixel and false
    /// represents an empty pixel.
    /// This contains all the information required to reconstruct the QR code. The side-length
    /// can be calculated by taking the square root of the length of the vector
    #[must_use]
    fn as_vec(&self) -> Vec<bool> {
        let mut result = Vec::with_capacity(self.side_length() * self.side_length());
        for y in 0..self.side_length() {
            for x in 0..self.side_length() {
                result.push(self.pixel_or_false(x, y));
            }
        }
        result
    }

    /// Returns a console string representation of the QR code,
    /// using the given characters as placeholders
    /// for empty, filled pixels, and the new line character.
    /// Console string assumes that the height is twice the width.
    ///
    /// border_size is the number of pixels to add around the QR code
    #[must_use]
    fn encode_to_console_string(
        &self,
        border_size: u8,
        empty_char: char,
        filled_char: char,
        new_line: char,
    ) -> String {
        let mut result = String::with_capacity(2 * self.side_length() * self.side_length());
        let border = border_size as i32;
        for y in -border..self.side_length() as i32 + border {
            for x in -border..self.side_length() as i32 + border {
                let c = if self.pixel_or_false(x as usize, y as usize) {
                    filled_char
                } else {
                    empty_char
                };
                // We push twice because in a standard terminal, chars are rectangular,
                // not square, with the height being twice the width (9x18 pixels).
                // This makes the QR code pixels become squares.
                result.push(c);
                result.push(c);
            }
            result.push(new_line)
        }
        result.push(new_line);
        result
    }

    /// Returns a console string representation of the QR code,
    /// using the default characters as placeholders
    /// for empty and filled pixels, and the new line character.
    /// Console string assumes that the height is twice the width.
    ///
    /// border_size is the number of pixels to add around the QR code
    #[must_use]
    fn encode_to_console_string_with_defaults(&self, border_size: u8) -> String {
        self.encode_to_console_string(border_size, EMPTY_CHAR, FILLED_CHAR, NEW_LINE)
    }

    /// Create an SVG string representation of the QR code, using the given border size
    /// To use this output, you can write it to a file with extension svg, or you can embed it in
    /// an HTML document
    #[must_use]
    fn encode_to_svg_string(&self, border_size: usize) -> String {
        let mut result = String::new();
        result += "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        result += "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n";

        let dimension = self
            .side_length()
            .checked_add(border_size.checked_mul(2).expect("QR code SVG border size mul overflow"))
            .expect("QR code SVG addition overflow");

        result += &format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" viewBox=\"0 0 {0} {0}\" stroke=\"none\">\n", dimension);
        result += "\t<rect width=\"100%\" height=\"100%\" fill=\"#FFFFFF\"/>\n";
        result += "\t<path d=\"";
        for y in 0..self.side_length() {
            for x in 0..self.side_length() {
                if self.pixel_or_false(x, y) {
                    if x != 0 || y != 0 {
                        result += " ";
                    }
                    result += &format!("M{},{}h1v1h-1z", x + border_size, y + border_size);
                }
            }
        }
        result += "\" fill=\"#000000\"/>\n";
        result += "</svg>\n";
        result
    }
}

impl QrCode for qrcodegen::QrCode {
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

    fn test_string_qrcode(qr: &impl QrCode) {
        let qr_str = qr
            .encode_to_console_string(0, '0', '1', '\n')
            .chars()
            // Remove new lines to compare with vectors next
            .filter(|c| *c != '\n')
            .collect::<String>();
        let expected_str = qr
            .as_vec()
            .into_iter()
            // duplicate each bool twice, then flatten the vec, because QR code
            // console strings are twice as wide in the interest of making squares
            .flat_map(|v| if v { vec!['1', '1'] } else { vec!['0', '0'] })
            .collect::<String>();
        assert_eq!(qr_str, expected_str);
    }

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

        test_string_qrcode(&qr);
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

        test_string_qrcode(&qr);
    }

    #[test]
    fn svg_attempt_str() {
        let text: &'static str = "Hello, world!";
        let qr = super::qrcode_from_str(text).unwrap();
        let _svg = qr.encode_to_svg_string(20);
    }
}
