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
        ::core::primitive::bool::then($cond, || ())?
    };
    ($cond:expr, $err:expr $(,)?) => {
        ::core::primitive::bool::then($cond, || ()).ok_or_else(|| $err)?
    };
}
