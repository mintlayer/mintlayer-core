use super::*;

#[tokio::test]
async fn test_read_request() {
    let mut codec = SyncingMessagingCodec();
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
        assert_eq!(res, SyncRequest(data));
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
    let mut codec = SyncingMessagingCodec();
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
        assert_eq!(res, SyncResponse(data));
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
    let mut codec = SyncingMessagingCodec();
    let protocol = SyncingProtocol();

    // empty response
    {
        let mut out = vec![0u8; 1024];
        let data = vec![];

        let mut socket = futures::io::Cursor::new(&mut out[..]);
        codec.write_request(&protocol, &mut socket, SyncRequest(data)).await.unwrap();
    }

    // 10 MB
    {
        let mut out = vec![0u8; 20 * 1024 * 1024];
        let data = vec![1u8; 10 * 1024 * 1024];

        let mut socket = futures::io::Cursor::new(&mut out[..]);
        codec.write_request(&protocol, &mut socket, SyncRequest(data)).await.unwrap();
    }

    // 12 MB
    {
        let mut out = vec![0u8; 20 * 1024 * 1024];
        let data = vec![1u8; 12 * 1024 * 1024];

        let mut socket = futures::io::Cursor::new(&mut out[..]);
        if let Err(e) = codec.write_request(&protocol, &mut socket, SyncRequest(data)).await {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        }
    }
}

#[tokio::test]
async fn test_write_response() {
    let mut codec = SyncingMessagingCodec();
    let protocol = SyncingProtocol();

    // empty response
    {
        let mut out = vec![0u8; 1024];
        let data = vec![];

        let mut socket = futures::io::Cursor::new(&mut out[..]);
        codec.write_response(&protocol, &mut socket, SyncResponse(data)).await.unwrap();
    }

    // 10 MB
    {
        let mut out = vec![0u8; 20 * 1024 * 1024];
        let data = vec![1u8; 10 * 1024 * 1024];

        let mut socket = futures::io::Cursor::new(&mut out[..]);
        codec.write_response(&protocol, &mut socket, SyncResponse(data)).await.unwrap();
    }

    // 12 MB
    {
        let mut out = vec![0u8; 20 * 1024 * 1024];
        let data = vec![1u8; 12 * 1024 * 1024];

        let mut socket = futures::io::Cursor::new(&mut out[..]);
        if let Err(e) = codec.write_response(&protocol, &mut socket, SyncResponse(data)).await {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        }
    }
}
