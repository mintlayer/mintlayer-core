//! Traits specifying the interface for database transactions.

/// Low-level interface for read-only database transactions
pub trait TransactionRo: Sized {
    /// Errors that can occur during a transaction.
    type Error;

    /// Finalize the transaction.
    fn finalize(self) -> Result<(), Self::Error>;
}

#[allow(type_alias_bounds)]
pub type RoTxResult<'s, R, T: Transactional<'s>> =
    Result<R, <T::TransactionRo as TransactionRo>::Error>;

/// Low-level interface for read-write database transactions
pub trait TransactionRw: Sized {
    /// Errors that can occur during a transaction.
    type Error;

    /// Commit a transaction
    fn commit(self) -> Result<(), Self::Error>;

    /// Abort a transaction.
    fn abort(self) -> Result<(), Self::Error>;
}

/// Transaction response
#[must_use = "Response must be returned from the transaction"]
pub enum Response<T> {
    /// Commit the transaction to the storage
    Commit(T),
    /// Abort the transaction
    Abort(T),
}

impl<T> Response<T> {
    // Extract the return value from the response.
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

#[allow(type_alias_bounds)]
pub type RwTxResult<'s, R, T: Transactional<'s>> =
    Result<R, <T::TransactionRw as TransactionRw>::Error>;

/// Type where some operations can be grouped into atomic transactions.
pub trait Transactional<'s> {
    /// Associated read-only transaction type.
    type TransactionRo: TransactionRo;

    /// Associated read-write transaction type.
    type TransactionRw: TransactionRw;

    /// Start a read-only transaction.
    ///
    /// Prefer the [Self::read] convenience function over this.
    fn start_transaction_ro(&'s self) -> Self::TransactionRo;

    /// Run a read-only transaction.
    ///
    /// High-level convenience method. Prefer this over a combination of
    /// [Self::start_transaction_ro], [TransactionRo::finalize].
    ///
    /// ```
    /// # use storage::transaction::Transactional;
    /// # fn foo<'a, T: Transactional<'a>>(foo: &'a mut T) {
    /// let result = foo.transaction_ro(|tx| {
    ///     // Your transaction operations go here
    ///     Ok(42) // this will be the result
    /// });
    /// # }
    /// ```
    ///
    /// Implementations are allowed to override this method provided semantics are preserved.
    fn transaction_ro<R>(
        &'s self,
        tx_body: impl FnOnce(&Self::TransactionRo) -> RoTxResult<'s, R, Self>,
    ) -> RoTxResult<R, Self> {
        let tx = self.start_transaction_ro();
        let result = tx_body(&tx);
        tx.finalize()?;
        result
    }

    /// Start a read-write transaction.
    ///
    /// Prefer the [Self::write] convenience function over this.
    fn start_transaction_rw(&'s self) -> Self::TransactionRw;

    /// Run a read-write transaction.
    ///
    /// High-level convenience method. Prefer this over a combination of
    /// [Self::start_transaction_rw], [TransactionRw::commit], [TransactionRw::abort].
    ///
    /// ```
    /// # use storage::transaction::Transactional;
    /// # fn foo<'a, T: Transactional<'a>>(foo: &'a mut T) {
    /// let result = foo.transaction_rw(|tx| {
    ///     // Your transaction operations go here
    ///     storage::commit(42) // this will be the result
    /// });
    /// # }
    /// ```
    ///
    /// Implementations are allowed to override this method provided semantics are preserved.
    fn transaction_rw<F, R>(&'s self, tx_body: F) -> RwTxResult<'s, R, Self>
    where
        F: FnOnce(&mut Self::TransactionRw) -> RwTxResult<'s, Response<R>, Self>,
    {
        let mut tx = self.start_transaction_rw();
        let result = tx_body(&mut tx);
        match result {
            Ok(Response::Commit(_)) => tx.commit()?,
            Ok(Response::Abort(_)) => tx.abort()?,
            Err(_) => (),
        };
        result.map(Response::value)
    }
}
