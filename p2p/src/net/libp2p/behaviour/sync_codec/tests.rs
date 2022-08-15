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

use super::*;

#[tokio::test]
async fn test_read_request() {
    let mut codec = SyncMessagingCodec();
    let protocol = SyncingProtocol();

    // empty stream
    {
        let mut out = vec![0u8; 1];
        let data = vec![];
        let mut socket = futures::io::Cursor::new(&mut out[..]);
        write_length_prefixed(&mut socket, &data).await.unwrap();

        let res = codec.read_request(&protocol, &mut socket).await;
        assert!(res.is_err());
    }

    // 10 MB
    {
        let mut out = vec![0u8; 11 * 1024 * 1024];
        let data = vec![1u8; MESSAGE_MAX_SIZE];

        let mut socket = futures::io::Cursor::new(&mut out[..]);
        write_length_prefixed(&mut socket, &data).await.unwrap();

        let mut socket = futures::io::Cursor::new(&mut out[..]);
        let res = codec.read_request(&protocol, &mut socket).await.unwrap();
        assert_eq!(res, message_types::SyncRequest::new(data));
    }

    // 10 MB + 1 byte
    {
        let mut out = vec![0u8; 11 * 1024 * 1024];
        let data = vec![1u8; MESSAGE_MAX_SIZE + 1];

        let mut socket = futures::io::Cursor::new(&mut out[..]);
        write_length_prefixed(&mut socket, &data).await.unwrap();

        let mut socket = futures::io::Cursor::new(&mut out[..]);
        if let Err(e) = codec.read_request(&protocol, &mut socket).await {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        } else {
            panic!("should not work");
        }
    }
}

#[tokio::test]
async fn test_read_response() {
    let mut codec = SyncMessagingCodec();
    let protocol = SyncingProtocol();

    // empty stream
    {
        let mut out = vec![0u8; 1];
        let data = vec![];
        let mut socket = futures::io::Cursor::new(&mut out[..]);
        write_length_prefixed(&mut socket, &data).await.unwrap();

        let res = codec.read_response(&protocol, &mut socket).await;
        assert!(res.is_err());
    }

    // 10 MB
    {
        let mut out = vec![0u8; 11 * 1024 * 1024];
        let data = vec![1u8; MESSAGE_MAX_SIZE];

        let mut socket = futures::io::Cursor::new(&mut out[..]);
        write_length_prefixed(&mut socket, &data).await.unwrap();

        let mut socket = futures::io::Cursor::new(&mut out[..]);
        let res = codec.read_response(&protocol, &mut socket).await.unwrap();
        assert_eq!(res, message_types::SyncResponse::new(data));
    }

    // 10 MB + 1 byte
    {
        let mut out = vec![0u8; 11 * 1024 * 1024];
        let data = vec![1u8; MESSAGE_MAX_SIZE + 1];

        let mut socket = futures::io::Cursor::new(&mut out[..]);
        write_length_prefixed(&mut socket, &data).await.unwrap();

        let mut socket = futures::io::Cursor::new(&mut out[..]);
        if let Err(e) = codec.read_response(&protocol, &mut socket).await {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        } else {
            panic!("should not work");
        }
    }
}

#[tokio::test]
async fn test_write_request() {
    let mut codec = SyncMessagingCodec();
    let protocol = SyncingProtocol();

    // empty response
    {
        let mut out = vec![0u8; 1024];
        let data = vec![];

        let mut socket = futures::io::Cursor::new(&mut out[..]);
        codec
            .write_request(
                &protocol,
                &mut socket,
                message_types::SyncRequest::new(data),
            )
            .await
            .unwrap();
    }

    // 10 MB
    {
        let mut out = vec![0u8; 20 * 1024 * 1024];
        let data = vec![1u8; 10 * 1024 * 1024];

        let mut socket = futures::io::Cursor::new(&mut out[..]);
        codec
            .write_request(
                &protocol,
                &mut socket,
                message_types::SyncRequest::new(data),
            )
            .await
            .unwrap();
    }

    // 12 MB
    {
        let mut out = vec![0u8; 20 * 1024 * 1024];
        let data = vec![1u8; 12 * 1024 * 1024];

        let mut socket = futures::io::Cursor::new(&mut out[..]);
        if let Err(e) = codec
            .write_request(
                &protocol,
                &mut socket,
                message_types::SyncRequest::new(data),
            )
            .await
        {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        }
    }
}

#[tokio::test]
async fn test_write_response() {
    let mut codec = SyncMessagingCodec();
    let protocol = SyncingProtocol();

    // empty response
    {
        let mut out = vec![0u8; 1024];
        let data = vec![];

        let mut socket = futures::io::Cursor::new(&mut out[..]);
        codec
            .write_response(
                &protocol,
                &mut socket,
                message_types::SyncResponse::new(data),
            )
            .await
            .unwrap();
    }

    // 10 MB
    {
        let mut out = vec![0u8; 20 * 1024 * 1024];
        let data = vec![1u8; 10 * 1024 * 1024];

        let mut socket = futures::io::Cursor::new(&mut out[..]);
        codec
            .write_response(
                &protocol,
                &mut socket,
                message_types::SyncResponse::new(data),
            )
            .await
            .unwrap();
    }

    // 12 MB
    {
        let mut out = vec![0u8; 20 * 1024 * 1024];
        let data = vec![1u8; 12 * 1024 * 1024];

        let mut socket = futures::io::Cursor::new(&mut out[..]);
        if let Err(e) = codec
            .write_response(
                &protocol,
                &mut socket,
                message_types::SyncResponse::new(data),
            )
            .await
        {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        }
    }
}
