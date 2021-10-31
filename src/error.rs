use core::fmt;

/// An error which occurs when providing an invalid buffer to a
/// [`BufReader`](crate::DecryptBufReader) or [`BufWriter`](crate::EncryptBufWriter)
#[derive(Debug, Clone, Copy)]
pub struct InvalidCapacity;

impl fmt::Display for InvalidCapacity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Invalid buffer capacity: capacity must be greater than 0")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidCapacity {}

/// An error for read/write operations with custom Error types. Mainly useful for `no_std`
/// environments
#[derive(Debug, Clone)]
pub enum Error<Io> {
    Aead,
    Io(Io),
}

impl<Io> From<Io> for Error<Io> {
    fn from(err: Io) -> Self {
        Self::Io(err)
    }
}

impl<Io> fmt::Display for Error<Io>
where
    Io: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aead => f.write_str("AEAD error occured"),
            Self::Io(io) => io.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl<Io> From<Error<Io>> for std::io::Error
where
    Io: Into<std::io::Error>,
{
    fn from(err: Error<Io>) -> Self {
        match err {
            Error::Aead => std::io::Error::new(std::io::ErrorKind::Other, "an AEAD error occured"),
            err => err.into(),
        }
    }
}
