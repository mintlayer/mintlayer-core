// Copyright 2020 Parity Technologies (UK) Ltd.
// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen

//! Syncing codec implementation for Mintlayer
//!
//! Used to exchange SCALE-encoded header/block request/response pairs

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::{
    core::upgrade::{read_length_prefixed, write_length_prefixed},
    request_response::*,
};
use std::{io, ops::Deref};

#[derive(Debug, Clone)]
pub struct SyncingProtocol();

#[derive(Clone)]
pub struct SyncingCodec();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRequest(Vec<u8>);

impl SyncRequest {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl Deref for SyncRequest {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncResponse(Vec<u8>);

impl SyncResponse {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl Deref for SyncResponse {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ProtocolName for SyncingProtocol {
    fn protocol_name(&self) -> &[u8] {
        "/mintlayer/sync/0.1.0".as_bytes()
    }
}

#[async_trait]
impl RequestResponseCodec for SyncingCodec {
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
        let vec = read_length_prefixed(io, 1024).await?;

        if vec.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        Ok(SyncRequest(vec))
    }

    async fn read_response<T>(
        &mut self,
        _: &SyncingProtocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, 1024).await?;

        if vec.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        Ok(SyncResponse(vec))
    }

    async fn write_request<T>(
        &mut self,
        _: &SyncingProtocol,
        io: &mut T,
        SyncRequest(data): SyncRequest,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_length_prefixed(io, data).await?;
        io.close().await?;

        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &SyncingProtocol,
        io: &mut T,
        SyncResponse(data): SyncResponse,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_length_prefixed(io, data).await?;
        io.close().await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
