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

use iced::{
    font,
    widget::{container, row, Container},
    Alignment, Element, Font, Length, Padding, Theme,
};

use wallet_controller::types::WalletExtraInfo;

use super::WalletMessage;

pub fn view_status_bar(wallet_info: &WalletExtraInfo) -> Option<Element<'static, WalletMessage>> {
    let bold_font = Font {
        weight: font::Weight::Bold,
        ..Font::default()
    };
    let text_size = 16;

    let row = match wallet_info {
        WalletExtraInfo::SoftwareWallet => {
            return None;
        }
        #[cfg(feature = "trezor")]
        WalletExtraInfo::TrezorWallet {
            device_id: _,
            device_name,
            firmware_version,
        } => {
            use iced::widget::{rich_text, span};

            row![
                rich_text([span("Device name: ").font(bold_font), span(device_name.clone())])
                    .size(text_size),
                rich_text([
                    span("Firmware version: ").font(bold_font),
                    span(firmware_version.clone())
                ])
                .size(text_size),
            ]
        }
    };

    let vertical_padding = 5.;
    let horizontal_padding = 10.;

    let status_bar = Container::new(
        row.width(Length::Fill)
            .padding(Padding {
                top: vertical_padding,
                right: horizontal_padding,
                bottom: vertical_padding,
                left: horizontal_padding,
            })
            .spacing(horizontal_padding)
            .align_y(Alignment::Center),
    )
    .style(|theme: &Theme| {
        let palette = theme.extended_palette();

        container::Style {
            background: Some(palette.background.weak.color.into()),
            ..container::Style::default()
        }
    })
    .into();

    Some(status_bar)
}
