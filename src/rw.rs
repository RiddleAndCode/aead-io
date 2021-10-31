/// Emulates [`std::io::Write`](std::io::Write) with a simplified interface for `no_std`
/// environments.
pub trait Write {
    type Error;
    /// Write a buffer into this writer, returning how many bytes were written.
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error>;
    /// Flush this output stream, ensuring that all intermediately buffered contents reach their destination.
    fn flush(&mut self) -> Result<(), Self::Error>;
    /// Attempts to write an entire buffer into this writer.
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

/// Emulates [`std::io::Read`](std::io::Read) with a simplified interface for `no_std`
/// environments.
pub trait Read {
    type Error;
    /// Pull some bytes from this source into the specified buffer, returning how many bytes were read.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;
    /// Read the exact number of bytes required to fill `buf`.
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

/// A simple Error for implementations on byte slices in a `no_std` environment
#[cfg(not(feature = "std"))]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum IoError {
    /// Reached the end of the buffer when reading
    UnexpectedEof,
    /// Reached the end of the buffer when writing
    WriteZero,
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for IoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            UnexpectedEof => f.write_str("Failed to fill whole buffer"),
            UnexpectedWriteZero => f.write_str("Failed to write whole buffer"),
        }
    }
}

#[cfg(not(feature = "std"))]
impl Read for &[u8] {
    type Error = IoError;
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let amt = core::cmp::min(buf.len(), self.len());
        let (a, b) = self.split_at(amt);

        // First check if the amount of bytes we want to read is small:
        // `copy_from_slice` will generally expand to a call to `memcpy`, and
        // for a single byte the overhead is significant.
        if amt == 1 {
            buf[0] = a[0];
        } else {
            buf[..amt].copy_from_slice(a);
        }

        *self = b;
        Ok(amt)
    }
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        if buf.len() > self.len() {
            return Err(IoError::UnexpectedEof);
        }
        let (a, b) = self.split_at(buf.len());

        // First check if the amount of bytes we want to read is small:
        // `copy_from_slice` will generally expand to a call to `memcpy`, and
        // for a single byte the overhead is significant.
        if buf.len() == 1 {
            buf[0] = a[0];
        } else {
            buf.copy_from_slice(a);
        }

        *self = b;
        Ok(())
    }
}

#[cfg(not(feature = "std"))]
impl Write for &mut [u8] {
    type Error = IoError;
    #[inline]
    fn write(&mut self, data: &[u8]) -> Result<usize, Self::Error> {
        let amt = core::cmp::min(data.len(), self.len());
        let (a, b) = core::mem::replace(self, &mut []).split_at_mut(amt);
        a.copy_from_slice(&data[..amt]);
        *self = b;
        Ok(amt)
    }
    #[inline]
    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
    #[inline]
    fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        if self.write(data)? == data.len() {
            Ok(())
        } else {
            Err(IoError::WriteZero)
        }
    }
}

#[cfg(all(not(feature = "std"), feature = "alloc"))]
impl Write for alloc::vec::Vec<u8> {
    type Error = core::convert::Infallible;
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }
    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.extend_from_slice(buf);
        Ok(())
    }
    #[inline]
    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(not(feature = "std"))]
impl<R: Read + ?Sized> Read for &mut R {
    type Error = R::Error;
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        (**self).read(buf)
    }
    #[inline]
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        (**self).read_exact(buf)
    }
}
#[cfg(not(feature = "std"))]
impl<W: Write + ?Sized> Write for &mut W {
    type Error = W::Error;
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        (**self).write(buf)
    }
    #[inline]
    fn flush(&mut self) -> Result<(), Self::Error> {
        (**self).flush()
    }
    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        (**self).write_all(buf)
    }
}
#[cfg(all(not(feature = "std"), feature = "alloc"))]
impl<R: Read + ?Sized> Read for alloc::boxed::Box<R> {
    type Error = R::Error;
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        (**self).read(buf)
    }
    #[inline]
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        (**self).read_exact(buf)
    }
}
#[cfg(all(not(feature = "std"), feature = "alloc"))]
impl<W: Write + ?Sized> Write for alloc::boxed::Box<W> {
    type Error = W::Error;
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        (**self).write(buf)
    }
    #[inline]
    fn flush(&mut self) -> Result<(), Self::Error> {
        (**self).flush()
    }
    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        (**self).write_all(buf)
    }
}
