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

#[cfg(feature = "std")]
impl From<InvalidCapacity> for std::io::Error {
    fn from(err: InvalidCapacity) -> Self {
        std::io::Error::new(std::io::ErrorKind::OutOfMemory, err)
    }
}

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
impl<Io> std::error::Error for Error<Io> where Io: fmt::Display + fmt::Debug {}

#[cfg(feature = "std")]
impl<Io> From<Error<Io>> for std::io::Error
where
    Io: Into<std::io::Error>,
{
    fn from(err: Error<Io>) -> Self {
        match err {
            Error::Aead => std::io::Error::new(std::io::ErrorKind::Other, "an AEAD error occured"),
            Error::Io(err) => err.into(),
        }
    }
}

/// An error returned by `EncryptBufWriter::into_inner` which combines an error that happened
/// while writing out the buffer, and the buffered writer object which may be used to recover
/// from the condition.
#[derive(Debug, Clone)]
pub struct IntoInnerError<W, Io>(W, Error<Io>);

impl<W, Io> IntoInnerError<W, Io> {
    pub(crate) fn new(writer: W, error: Error<Io>) -> Self {
        Self(writer, error)
    }

    /// Returns the error which caused the call to `EncryptBufWriter::into_inner()` to fail.
    /// This error was returned when attempting to write the internal buffer.
    pub fn error(&self) -> &Error<Io> {
        &self.1
    }

    /// Returns the buffered writer instance which generated the error.
    /// The returned object can be used for error recovery, such as re-inspecting the buffer.
    pub fn into_writer(self) -> W {
        self.0
    }

    /// Consumes the IntoInnerError and returns the error which caused the call to
    /// `EncryptBufWriter::into_inner()` to fail. Unlike error, this can be used to obtain
    /// ownership of the underlying error.
    pub fn into_error(self) -> Error<Io> {
        self.1
    }

    /// Consumes the IntoInnerError and returns the error which caused the call to
    /// `EncryptBufWriter::into_inner()` to fail, and the underlying writer. This can be used
    /// to simply obtain ownership of the underlying error; it can also be used for advanced
    /// error recovery.
    pub fn into_parts(self) -> (W, Error<Io>) {
        (self.0, self.1)
    }
}

impl<W, Io> fmt::Display for IntoInnerError<W, Io>
where
    Io: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error().fmt(f)
    }
}

#[cfg(feature = "std")]
impl<W, Io> std::error::Error for IntoInnerError<W, Io>
where
    Io: fmt::Display + fmt::Debug,
    W: fmt::Debug,
{
}

#[cfg(feature = "std")]
impl<W, Io> From<IntoInnerError<W, Io>> for std::io::Error
where
    Io: Into<std::io::Error>,
{
    fn from(err: IntoInnerError<W, Io>) -> Self {
        err.into_error().into()
    }
}
