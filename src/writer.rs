use crate::buffer::CappedBuffer;
use crate::error::{Error, IntoInnerError, InvalidCapacity};
use crate::rw::Write;
use aead::generic_array::typenum::Unsigned;
use aead::generic_array::ArrayLength;
use aead::stream::{Encryptor, NewStream, Nonce, NonceSize, StreamPrimitive};
use aead::{AeadCore, AeadInPlace, Key, NewAead};
use core::ops::Sub;
use core::{mem, ptr};

#[derive(Clone, Copy)]
enum State {
    Init,
    Writing,
    Finished,
}

/// A wrapper around a [`Write`](Write) object and a [`StreamPrimitive`](`StreamPrimitive`)
/// providing a [`Write`](Write) interface which automatically encrypts the underlying stream when
/// writing
pub struct EncryptBufWriter<A, B, W, S>
where
    A: AeadInPlace,
    B: CappedBuffer,
    W: Write,
    S: StreamPrimitive<A>,
    A::NonceSize: Sub<S::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    encryptor: Option<Encryptor<A, S>>,
    nonce: Nonce<A, S>,
    buffer: B,
    writer: W,
    capacity: usize,
    state: State,
}

impl<A, B, W, S> EncryptBufWriter<A, B, W, S>
where
    A: AeadInPlace,
    B: CappedBuffer,
    W: Write,
    S: StreamPrimitive<A>,
    A::NonceSize: Sub<S::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    /// Constructs a new Writer using an AEAD key, buffer and reader
    pub fn new(
        key: &Key<A>,
        nonce: &Nonce<A, S>,
        mut buffer: B,
        writer: W,
    ) -> Result<Self, InvalidCapacity>
    where
        A: NewAead,
        S: NewStream<A>,
    {
        buffer.truncate(0);
        let capacity = buffer.capacity().min(u32::MAX as usize);
        if capacity < 1 {
            Err(InvalidCapacity)
        } else {
            Ok(Self {
                encryptor: Some(Encryptor::new(key, nonce)),
                nonce: nonce.clone(),
                writer,
                buffer,
                capacity,
                state: State::Init,
            })
        }
    }

    /// Constructs a new Writer using an AEAD primitive, buffer and reader
    pub fn from_aead(
        aead: A,
        nonce: &Nonce<A, S>,
        mut buffer: B,
        writer: W,
    ) -> Result<Self, InvalidCapacity>
    where
        A: NewAead,
        S: NewStream<A>,
    {
        buffer.truncate(0);
        let capacity = buffer
            .capacity()
            .min(u32::MAX as usize)
            .checked_sub(<<A as AeadCore>::TagSize as Unsigned>::to_usize())
            .ok_or(InvalidCapacity)?;
        if capacity < 1 {
            Err(InvalidCapacity)
        } else {
            Ok(Self {
                encryptor: Some(Encryptor::from_aead(aead, nonce)),
                nonce: nonce.clone(),
                writer,
                buffer,
                capacity,
                state: State::Init,
            })
        }
    }

    /// Gets a reference to the inner writer
    pub fn inner(&self) -> &W {
        &self.writer
    }

    /// Consumes the Writer and returns the inner writer
    pub fn into_inner(mut self) -> Result<W, IntoInnerError<Self, W::Error>> {
        match self.flush_buffer(true) {
            Ok(()) => {
                let inner = unsafe { ptr::read(&self.writer) };
                mem::forget(self);
                Ok(inner)
            }
            Err(err) => Err(IntoInnerError::new(self, err)),
        }
    }

    fn capacity_remaining(&self) -> usize {
        self.capacity - self.buffer.len()
    }

    fn flush_buffer(&mut self, last: bool) -> Result<(), Error<W::Error>> {
        if matches!(self.state, State::Finished) {
            return Ok(());
        }

        if last {
            self.encryptor
                .take()
                .ok_or(Error::Aead)?
                .encrypt_last_in_place(&[], &mut self.buffer)
                .map_err(|_| Error::Aead)?;
        } else {
            self.encryptor
                .as_mut()
                .ok_or(Error::Aead)?
                .encrypt_next_in_place(&[], &mut self.buffer)
                .map_err(|_| Error::Aead)?;
        }

        if matches!(self.state, State::Init) {
            self.writer.write_all(self.nonce.as_slice())?;
            self.state = State::Writing;
        }

        self.writer
            .write_all(&(self.buffer.len() as u32).to_be_bytes())?;
        self.writer.write_all(self.buffer.as_ref())?;
        if last {
            self.state = State::Finished;
        }

        self.buffer.truncate(0);
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, Error<W::Error>> {
        if matches!(self.state, State::Finished) {
            return Err(Error::Aead);
        }
        if buf.len() > self.capacity_remaining() {
            self.flush_buffer(false)?;
        }
        let bytes_to_write = buf.len().min(self.capacity_remaining());
        self.buffer
            .extend_from_slice(&buf[..bytes_to_write])
            .map_err(|_| Error::Aead)?;
        Ok(bytes_to_write)
    }

    fn flush(&mut self) -> Result<(), Error<W::Error>> {
        self.flush_buffer(true)?;
        self.writer.flush()?;
        Ok(())
    }
}

impl<A, B, W, S> Drop for EncryptBufWriter<A, B, W, S>
where
    A: AeadInPlace,
    B: CappedBuffer,
    W: Write,
    S: StreamPrimitive<A>,
    A::NonceSize: Sub<S::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    fn drop(&mut self) {
        let _ = self.flush_buffer(true);
    }
}

#[cfg(feature = "std")]
impl<A, B, W, S> std::io::Write for EncryptBufWriter<A, B, W, S>
where
    A: AeadInPlace,
    B: CappedBuffer,
    W: Write,
    W::Error: Into<std::io::Error>,
    S: StreamPrimitive<A>,
    A::NonceSize: Sub<S::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(self.write(buf)?)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(self.flush()?)
    }
}

#[cfg(not(feature = "std"))]
impl<A, B, W, S> Write for EncryptBufWriter<A, B, W, S>
where
    A: AeadInPlace,
    B: CappedBuffer,
    W: Write,
    S: StreamPrimitive<A>,
    A::NonceSize: Sub<S::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    type Error = Error<W::Error>;
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        Ok(self.write(buf)?)
    }
    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(self.flush()?)
    }
    fn write_all(&mut self, mut buf: &[u8]) -> Result<(), Self::Error> {
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => return Err(Error::Aead),
                Ok(n) => buf = &buf[n..],
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
