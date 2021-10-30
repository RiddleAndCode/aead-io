pub trait Write {
    type Error;
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error>;
    fn flush(&mut self) -> Result<(), Self::Error>;
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error>;
}

#[cfg(feature = "std")]
impl<T> Write for T
where
    T: std::io::Write,
{
    type Error = std::io::Error;
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.write(buf)
    }
    #[inline]
    fn flush(&mut self) -> Result<(), Self::Error> {
        self.flush()
    }
    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.write_all(buf)
    }
}

pub trait Read {
    type Error;
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;
}

#[cfg(feature = "std")]
impl<T> Read for T
where
    T: std::io::Read,
{
    type Error = std::io::Error;
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.read(buf)
    }
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.read_exact(buf)
    }
}
