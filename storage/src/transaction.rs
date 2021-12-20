//! Traits specifying the interface for database transactions.

/// Low-level database transation interface
pub trait DbTransaction {
    /// Errors that can occur during a transaction.
    type Error;

    /// Commit a transaction
    fn commit(self) -> Result<(), Self::Error>;

    /// Abort a transaction.
    fn abort(&mut self) -> Result<(), Self::Error>;
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
    /// [Transaction::commit], [Transaction::abort].
    ///
    /// ```
    /// # use storage::Transactional;
    /// # fn foo<'a, T: Transactional<'a>>(foo: &'a mut T) {
    /// let result = foo.transaction(|tx| {
    ///     // Your transaction operations go here
    ///     Ok(42) // this will be the result
    /// });
    /// # }
    /// ```
    ///
    /// Implementations are allowed to override this method provided semantics are preserved.
    fn transaction<R>(
        &'s mut self,
        tx_body: impl FnOnce(&mut Self::Transaction) -> TxResult<'s, R, Self>,
    ) -> TxResult<R, Self> {
        let mut tx = self.start_transaction();
        let result = tx_body(&mut tx);
        match result {
            Ok(_) => tx.commit()?,
            Err(_) => tx.abort()?,
        };
        result
    }
}
