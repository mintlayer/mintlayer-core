use std::ops::Deref;

/// Generic type of Request messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRequest(Vec<u8>);

impl SyncRequest {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn take(self) -> Vec<u8> {
        self.0
    }
}

impl Deref for SyncRequest {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Generic type of Response messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncResponse(Vec<u8>);

impl SyncResponse {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn take(self) -> Vec<u8> {
        self.0
    }
}

impl Deref for SyncResponse {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
