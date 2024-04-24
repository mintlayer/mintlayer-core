// Copyright (c) 2022 RBB S.r.l
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

mod buffered_transcoder;
mod impls;
mod message_codec;
mod traits;

use impls::{channel, socks5, stream_adapter, tcp};

pub use self::{
    buffered_transcoder::BufferedTranscoder,
    channel::{ChannelListener, ChannelStream, MpscChannelTransport, MpscChannelTransportError},
    socks5::Socks5TransportSocket,
    stream_adapter::{
        identity::IdentityStreamAdapter,
        noise::{NoiseEncryptionAdapter, NoiseEncryptionAdapterMaker},
        wrapped_transport::wrapped_socket::WrappedTransportSocket,
    },
    tcp::TcpTransportSocket,
    traits::{ConnectedSocketInfo, PeerStream, TransportListener, TransportSocket},
};

pub type NoiseTcpTransport =
    WrappedTransportSocket<NoiseEncryptionAdapterMaker, NoiseEncryptionAdapter, TcpTransportSocket>;
pub type NoiseSocks5Transport = WrappedTransportSocket<
    NoiseEncryptionAdapterMaker,
    NoiseEncryptionAdapter,
    Socks5TransportSocket,
>;
