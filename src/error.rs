// TODO display, error
#[derive(Debug, Clone, Copy)]
pub struct InvalidCapacity;

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
