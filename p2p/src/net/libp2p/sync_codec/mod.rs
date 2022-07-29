// Copyright 2019-2020 Parity Technologies (UK) Ltd.
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

//! Syncing codec implementation for Mintlayer
//!
//! Used to exchange SCALE-encoded header/block request/response pairs

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::{
    core::upgrade::{read_length_prefixed, write_length_prefixed},
    request_response::*,
};
use std::io;

use self::message_types::{SyncRequest, SyncResponse};

pub mod message_types;

const MESSAGE_MAX_SIZE: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct SyncingProtocol();

impl ProtocolName for SyncingProtocol {
    /// When using the RequestResponse<> behavior with Libp2p, this is going to be the string that is used to demultiplex the stream
    /// we get for a specific use-case. For example, for syncing, we use this prefix. If we add our custom PubSub implementation,
    /// we have to use another string, or the demultiplexer will fail at distinguishing streams
    fn protocol_name(&self) -> &[u8] {
        "/mintlayer/sync/0.1.0".as_bytes()
    }
}

/// The SyncingMessageCodec defines the types of request/response messages and how they are serialized and deserialized,
/// which is done by implementating the RequestResponseCodec for it and defining the request response types
#[derive(Clone)]
pub struct SyncMessagingCodec();

#[async_trait]
impl RequestResponseCodec for SyncMessagingCodec {
    type Protocol = SyncingProtocol;
    type Request = SyncRequest;
    type Response = SyncResponse;

    async fn read_request<T>(
        &mut self,
        _: &SyncingProtocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, MESSAGE_MAX_SIZE).await?;

        if vec.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        Ok(SyncRequest::new(vec))
    }

    async fn read_response<T>(
        &mut self,
        _: &SyncingProtocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, MESSAGE_MAX_SIZE).await?;

        if vec.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        Ok(SyncResponse::new(vec))
    }

    async fn write_request<T>(
        &mut self,
        _: &SyncingProtocol,
        io: &mut T,
        data: SyncRequest,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        if data.len() > MESSAGE_MAX_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Input data size ({} bytes) exceeds maximum ({} bytes)",
                    data.len(),
                    MESSAGE_MAX_SIZE,
                ),
            ));
        }

        write_length_prefixed(io, data.take()).await?;
        io.close().await?;

        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &SyncingProtocol,
        io: &mut T,
        data: SyncResponse,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        if data.len() > MESSAGE_MAX_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Input data size ({} bytes) exceeds maximum ({} bytes)",
                    data.len(),
                    MESSAGE_MAX_SIZE,
                ),
            ));
        }

        write_length_prefixed(io, data.take()).await?;
        io.close().await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests;
