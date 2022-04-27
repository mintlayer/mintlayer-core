//! Tools for interrupting function flow unless some condition holds.

/// Early exit if given condition is not satisfied.
///
/// There are two variants:
/// * `ensure!(cond)` returns from the enclosing function with [`None`] if `cond` fails
/// * `ensure!(cond, err)` returns from the function with [`Err`]`(err)` if `cond` fails
///
/// Example with [Option]:
/// ```
/// # use utils::ensure;
/// fn safe_div(x: u32, y: u32) -> Option<u32> {
///     ensure!(y != 0);
///     Some(x / y)
/// }
///
/// assert_eq!(safe_div(6, 2), Some(3));
/// assert_eq!(safe_div(0, 3), Some(0));
/// assert_eq!(safe_div(8, 0), None);
/// ```
///
/// Example with [Result]:
/// ```
/// # use utils::ensure;
/// # #[derive(PartialEq, Eq, Debug)]
/// enum DivError {
///     DivByZero,
///     NotIntegral,
/// }
///
/// fn integral_div(x: u32, y: u32) -> Result<u32, DivError> {
///     ensure!(y != 0, DivError::DivByZero);
///     ensure!(x % y == 0, DivError::NotIntegral);
///     Ok(x / y)
/// }
///
/// assert_eq!(integral_div(6, 2), Ok(3));
/// assert_eq!(integral_div(0, 3), Ok(0));
/// assert_eq!(integral_div(5, 3), Err(DivError::NotIntegral));
/// assert_eq!(integral_div(8, 0), Err(DivError::DivByZero));
/// ```
#[macro_export]
macro_rules! ensure {
    ($cond:expr $(,)?) => {
        $cond.then(|| ())?
    };
    ($cond:expr, $err:expr $(,)?) => {
        $cond.then(|| ()).ok_or_else(|| $err)?
    };
}

/// Alternative design for ensure
pub mod func_style {
    /// Return `None` if given condition is not satisfied.
    ///
    /// Maps `true` to `Some(())`, `false` to `None`.
    ///
    /// Example:
    /// ```
    /// # use utils::ensure::func_style::*;
    /// fn safe_div(x: u32, y: u32) -> Option<u32> {
    ///     ensure_some(y != 0)?;
    ///     Some(x / y)
    /// }
    ///
    /// assert_eq!(safe_div(6, 2), Some(3));
    /// assert_eq!(safe_div(0, 3), Some(0));
    /// assert_eq!(safe_div(8, 0), None);
    /// ```
    #[must_use = "Result of ensure_some not used. Use the `?` operator for early exit."]
    pub fn ensure_some(cond: bool) -> Option<()> {
        cond.then(|| ())
    }

    /// Return `Err` if given condition is not satisfied.
    ///
    /// Maps `true` to `Ok(())`, `false` to `Err(err)`.
    ///
    /// Example:
    /// ```
    /// # use utils::ensure::func_style::*;
    /// # #[derive(PartialEq, Eq, Debug)]
    /// enum DivError {
    ///     DivByZero,
    ///     NotIntegral,
    /// }
    ///
    /// fn integral_div(x: u32, y: u32) -> Result<u32, DivError> {
    ///     ensure(y != 0, DivError::DivByZero)?;
    ///     ensure(x % y == 0, DivError::NotIntegral)?;
    ///     Ok(x / y)
    /// }
    ///
    /// assert_eq!(integral_div(6, 2), Ok(3));
    /// assert_eq!(integral_div(0, 3), Ok(0));
    /// assert_eq!(integral_div(5, 3), Err(DivError::NotIntegral));
    /// assert_eq!(integral_div(8, 0), Err(DivError::DivByZero));
    /// ```
    #[must_use = "Result of ensure not used. Use the `?` operator for early exit."]
    pub fn ensure<E>(cond: bool, err: E) -> Result<(), E> {
        ensure_some(cond).ok_or(err)
    }

    /// Return `Err` if given condition is not satisfied.
    ///
    /// Maps `true` to `Ok(())`, `false` to `Err(err_fn())`.
    ///
    /// Same as [ensure()] but takes a closure to calculate the error lazily.
    /// Useful if a non-trivial computation is needed to obtain the error value.
    #[must_use = "Result of ensure_fn not used. Use the `?` operator for early exit."]
    pub fn ensure_fn<E>(cond: bool, err_fn: impl FnOnce() -> E) -> Result<(), E> {
        ensure_some(cond).ok_or_else(err_fn)
    }
}
