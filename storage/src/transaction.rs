//! Traits specifying the interface for database transactions.

/// Transaction response
#[must_use = "Response must be returned from the transaction"]
pub enum Response<T> {
    /// Commit the transaction to the storage
    Commit(T),
    /// Abort the transaction
    Abort(T),
}

impl<T> Response<T> {
    fn value(self) -> T {
        match self {
            Self::Commit(v) => v,
            Self::Abort(v) => v,
        }
    }
}

/// Commit a transaction, returning given value
#[must_use = "commit must be returned from the transaction"]
pub fn commit<T, E>(ret: T) -> Result<Response<T>, E> {
    Ok(Response::Commit(ret))
}

/// Abort a transaction, returning given value
#[must_use = "abort must be returned from the transaction"]
pub fn abort<T, E>(ret: T) -> Result<Response<T>, E> {
    Ok(Response::Abort(ret))
}

/// Low-level database transation interface
pub trait DbTransaction: Sized {
    /// Errors that can occur during a transaction.
    type Error;

    /// Commit a transaction
    fn commit(self) -> Result<(), Self::Error>;

    /// Abort a transaction.
    fn abort(self) -> Result<(), Self::Error>;
}

#[allow(type_alias_bounds)]
pub type TxResult<'s, R, T: Transactional<'s>> =
    Result<R, <T::Transaction as DbTransaction>::Error>;

/// Type where some operations can be grouped into atomic transactions.
pub trait Transactional<'s> {
    /// Associated transaction type.
    type Transaction: DbTransaction;

    /// Start a transaction.
    ///
    /// Prefer the [Self::transaction] convenience function over this.
    fn start_transaction(&'s mut self) -> Self::Transaction;

    /// Run a transaction.
    ///
    /// High-level convenience method. Prefer this over a combination of [Self::start_transaction],
    /// [DbTransaction::commit], [DbTransaction::abort].
    ///
    /// ```
    /// # use storage::Transactional;
    /// # fn foo<'a, T: Transactional<'a>>(foo: &'a mut T) {
    /// let result = foo.transaction(|tx| {
    ///     // Your transaction operations go here
    ///     storage::commit(42) // this will be the result
    /// });
    /// # }
    /// ```
    ///
    /// Implementations are allowed to override this method provided semantics are preserved.
    fn transaction<R>(
        &'s mut self,
        tx_body: impl FnOnce(&mut Self::Transaction) -> TxResult<'s, Response<R>, Self>,
    ) -> TxResult<R, Self> {
        let mut tx = self.start_transaction();
        let result = tx_body(&mut tx);
        match result {
            Ok(Response::Commit(_)) => tx.commit()?,
            Ok(Response::Abort(_)) => tx.abort()?,
            Err(_) => (),
        };
        result.map(Response::value)
    }
}
