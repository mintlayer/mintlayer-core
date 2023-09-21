use api_server_common::storage::storage_api::{
    ApiServerStorage, ApiServerStorageError, Transactional,
};

use super::podman::Podman;

pub struct ApiServerStorageWithContainer<S: ApiServerStorage> {
    storage: S,
    _container: Podman,
}

impl<'db, S: ApiServerStorage> ApiServerStorageWithContainer<S> {
    pub fn new(storage: S, container: Podman) -> ApiServerStorageWithContainer<S> {
        Self {
            storage,
            _container: container,
        }
    }
}

#[async_trait::async_trait]
impl<'tx, S: ApiServerStorage> Transactional<'tx> for ApiServerStorageWithContainer<S> {
    type TransactionRo = <S as Transactional<'tx>>::TransactionRo;

    type TransactionRw = <S as Transactional<'tx>>::TransactionRw;
    async fn transaction_ro<'db: 'tx>(
        &'db self,
    ) -> Result<Self::TransactionRo, ApiServerStorageError> {
        self.storage.transaction_ro().await
    }

    async fn transaction_rw<'db: 'tx>(
        &'db mut self,
    ) -> Result<Self::TransactionRw, ApiServerStorageError> {
        self.storage.transaction_rw().await
    }
}

impl<S: ApiServerStorage> ApiServerStorage for ApiServerStorageWithContainer<S> {}
