use std::fmt::Display;

pub trait LogError
where
    Self: Sized,
{
    fn log_err(self) -> Self;
    fn log_err_pfx(self, prefix: &str) -> Self;
    fn log_warn(self) -> Self;
    fn log_warn_pfx(self, prefix: &str) -> Self;
}

impl<T, E: Display> LogError for Result<T, E> {
    #[inline(always)]
    fn log_err(self) -> Self {
        if let Err(ref err) = self {
            logging::log::error!("{}", err);
        }
        self
    }

    #[inline(always)]
    fn log_warn(self) -> Self {
        if let Err(ref err) = self {
            logging::log::warn!("{}", err);
        }
        self
    }

    #[inline(always)]
    fn log_err_pfx(self, prefix: &str) -> Self {
        if let Err(ref err) = self {
            logging::log::error!("{}{}", prefix, err);
        }
        self
    }

    #[inline(always)]
    fn log_warn_pfx(self, prefix: &str) -> Self {
        if let Err(ref err) = self {
            logging::log::warn!("{}{}", prefix, err);
        }
        self
    }
}
