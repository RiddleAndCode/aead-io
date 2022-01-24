use crate::buffer::{CappedBuffer, ResizeBuffer};
use crate::error::{Error, InvalidCapacity};
use crate::rw::Read;
use aead::generic_array::ArrayLength;
use aead::stream::{Decryptor, NewStream, Nonce, NonceSize, StreamPrimitive};
use aead::{AeadInPlace, Key, NewAead};
use core::ops::Sub;

pub enum MaybeUninitDecryptor<A, S>
where
    A: AeadInPlace + NewAead,
    S: StreamPrimitive<A> + NewStream<A>,
    A::NonceSize: Sub<S::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    Uninit(A),
    Decryptor(Decryptor<A, S>),
    Empty,
}

impl<A, S> MaybeUninitDecryptor<A, S>
where
    A: AeadInPlace + NewAead,
    S: StreamPrimitive<A> + NewStream<A>,
    A::NonceSize: Sub<S::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    fn uninit(aead: A) -> Self {
        Self::Uninit(aead)
    }
    fn init(&mut self, nonce: &Nonce<A, S>) -> Result<(), aead::Error> {
        match core::mem::replace(self, Self::Empty) {
            Self::Uninit(aead) => *self = Self::Decryptor(Decryptor::from_aead(aead, &nonce)),
            Self::Decryptor(decryptor) => *self = Self::Decryptor(decryptor),
            Self::Empty => return Err(aead::Error),
        }
        Ok(())
    }
    fn is_uninit(&self) -> bool {
        match self {
            Self::Uninit(_) => true,
            _ => false,
        }
    }
    fn as_mut(&mut self) -> Option<&mut Decryptor<A, S>> {
        match self {
            Self::Decryptor(decryptor) => Some(decryptor),
            _ => None,
        }
    }
    fn take(&mut self) -> Option<Decryptor<A, S>> {
        match core::mem::replace(self, Self::Empty) {
            Self::Decryptor(decryptor) => Some(decryptor),
            Self::Uninit(_) => None,
            Self::Empty => None,
        }
    }
}

/// A wrapper around a [`Read`](Read) object and a [`StreamPrimitive`](`StreamPrimitive`)
/// providing a [`Read`](Read) interface which automatically decrypts the underlying stream when
/// reading
pub struct DecryptBufReader<A, B, R, S>
where
    A: AeadInPlace + NewAead,
    S: StreamPrimitive<A> + NewStream<A>,
    A::NonceSize: Sub<S::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    decryptor: MaybeUninitDecryptor<A, S>,
    buffer: B,
    reader: R,
    bytes_to_read: usize,
    read_offset: usize,
    capacity: usize,
}

impl<A, B, R, S> DecryptBufReader<A, B, R, S>
where
    A: AeadInPlace + NewAead,
    B: ResizeBuffer + CappedBuffer,
    S: StreamPrimitive<A> + NewStream<A>,
    A::NonceSize: Sub<S::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    /// Constructs a new Reader using an AEAD key, buffer and reader
    pub fn new(key: &Key<A>, mut buffer: B, reader: R) -> Result<Self, InvalidCapacity> {
        buffer.truncate(0);
        let capacity = buffer.capacity().min(u32::MAX as usize);
        if capacity < 1 {
            Err(InvalidCapacity)
        } else {
            Ok(Self {
                decryptor: MaybeUninitDecryptor::uninit(A::new(key)),
                reader,
                buffer,
                bytes_to_read: 0,
                read_offset: 0,
                capacity,
            })
        }
    }

    /// Constructs a new Reader using an AEAD primitive, buffer and reader
    pub fn from_aead(aead: A, mut buffer: B, reader: R) -> Result<Self, InvalidCapacity> {
        buffer.truncate(0);
        let capacity = buffer.capacity().min(u32::MAX as usize);
        if capacity < 1 {
            Err(InvalidCapacity)
        } else {
            Ok(Self {
                decryptor: MaybeUninitDecryptor::uninit(aead),
                reader,
                buffer,
                bytes_to_read: 0,
                read_offset: 0,
                capacity,
            })
        }
    }

    /// Gets a reference to the inner reader
    pub fn inner(&self) -> &R {
        &self.reader
    }

    /// Consumes the Reader and returns the inner reader
    pub fn into_inner(self) -> R {
        self.reader
    }
}

impl<A, B, R, S> DecryptBufReader<A, B, R, S>
where
    A: AeadInPlace + NewAead,
    B: ResizeBuffer + CappedBuffer,
    R: Read,
    S: StreamPrimitive<A> + NewStream<A>,
    A::NonceSize: Sub<S::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    fn read_chunk_size(&mut self) -> Result<(), Error<R::Error>> {
        let mut bytes_to_read = [0u8; 4];
        let mut offset = 0;
        while offset < 4 {
            let read = self.reader.read(&mut bytes_to_read[offset..])?;
            if read == 0 {
                if offset == 0 {
                    self.bytes_to_read = 0;
                    return Ok(());
                } else {
                    return Err(Error::Aead);
                }
            }
            offset += read;
        }
        let bytes_to_read = u32::from_be_bytes(bytes_to_read) as usize;
        if bytes_to_read > self.capacity {
            return Err(Error::Aead);
        } else {
            self.bytes_to_read = bytes_to_read;
            Ok(())
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error<R::Error>> {
        if self.decryptor.is_uninit() {
            let mut nonce = Nonce::<A, S>::default();
            self.reader.read_exact(&mut nonce)?;
            self.decryptor.init(&nonce).map_err(|_| Error::Aead)?;
            self.read_chunk_size()?;
        }

        while self.buffer.is_empty() {
            if self.bytes_to_read == 0 {
                return Ok(0);
            }
            self.buffer
                .resize_zeroed(self.bytes_to_read)
                .map_err(|_| Error::Aead)?;
            self.reader.read_exact(self.buffer.as_mut())?;
            self.read_chunk_size()?;

            if self.bytes_to_read == 0 {
                self.decryptor
                    .take()
                    .ok_or_else(|| Error::Aead)?
                    .decrypt_last_in_place(&[], &mut self.buffer)
                    .map_err(|_| Error::Aead)?;
            } else {
                self.decryptor
                    .as_mut()
                    .ok_or_else(|| Error::Aead)?
                    .decrypt_next_in_place(&[], &mut self.buffer)
                    .map_err(|_| Error::Aead)?;
            }
        }

        let bytes_to_copy = (self.buffer.len() - self.read_offset).min(buf.len());
        buf[..bytes_to_copy].copy_from_slice(
            &self.buffer.as_ref()[self.read_offset..self.read_offset + bytes_to_copy],
        );
        self.buffer.as_mut()[self.read_offset..self.read_offset + bytes_to_copy].fill(0);

        if self.buffer.len() == self.read_offset + bytes_to_copy {
            self.read_offset = 0;
            self.buffer.truncate(0);
        } else {
            self.read_offset += bytes_to_copy;
        }

        Ok(bytes_to_copy)
    }
}

#[cfg(feature = "std")]
impl<A, B, R, S> std::io::Read for DecryptBufReader<A, B, R, S>
where
    A: AeadInPlace + NewAead,
    B: ResizeBuffer + CappedBuffer,
    R: Read,
    R::Error: Into<std::io::Error>,
    S: StreamPrimitive<A> + NewStream<A>,
    A::NonceSize: Sub<S::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(self.read(buf)?)
    }
}

#[cfg(not(feature = "std"))]
impl<A, B, R, S> Read for DecryptBufReader<A, B, R, S>
where
    A: AeadInPlace + NewAead,
    B: ResizeBuffer + CappedBuffer,
    R: Read,
    S: StreamPrimitive<A> + NewStream<A>,
    A::NonceSize: Sub<S::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    type Error = Error<R::Error>;
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        Ok(self.read(buf)?)
    }
    fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<(), Self::Error> {
        while !buf.is_empty() {
            match self.read(buf) {
                Ok(0) => break,
                Ok(n) => {
                    let tmp = buf;
                    buf = &mut tmp[n..];
                }
                Err(e) => return Err(e),
            }
        }
        if !buf.is_empty() {
            Err(Error::Aead)
        } else {
            Ok(())
        }
    }
}
