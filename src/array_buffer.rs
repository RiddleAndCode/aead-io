pub use crate::buffer::*;
#[cfg(not(feature = "std"))]
use crate::rw::IoError;
use aead::Buffer;
use arrayvec::ArrayVec;
use core::ops::{Deref, DerefMut};

/// A simple `no_std` compatible Capped Buffer implementation
#[derive(Clone, Debug, Default)]
pub struct ArrayBuffer<const CAP: usize>(ArrayVec<u8, CAP>);

impl<const CAP: usize> ArrayBuffer<CAP> {
    /// Creates a new empty ArrayBuffer
    pub const fn new() -> Self {
        Self(ArrayVec::new_const())
    }

    pub fn into_inner(self) -> ArrayVec<u8, CAP> {
        self.0
    }
}

impl<const CAP: usize> From<ArrayVec<u8, CAP>> for ArrayBuffer<CAP> {
    fn from(inner: ArrayVec<u8, CAP>) -> Self {
        Self(inner)
    }
}

impl<const CAP: usize> Deref for ArrayBuffer<CAP> {
    type Target = ArrayVec<u8, CAP>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const CAP: usize> DerefMut for ArrayBuffer<CAP> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const CAP: usize> AsRef<[u8]> for ArrayBuffer<CAP> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<const CAP: usize> AsMut<[u8]> for ArrayBuffer<CAP> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<const CAP: usize> Buffer for ArrayBuffer<CAP> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aead::Result<()> {
        self.0.try_extend_from_slice(other).map_err(|_| aead::Error)
    }
    fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }
}

impl<const CAP: usize> CappedBuffer for ArrayBuffer<CAP> {
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
}

impl<const CAP: usize> ResizeBuffer for ArrayBuffer<CAP> {
    fn resize_zeroed(&mut self, new_len: usize) -> Result<(), aead::Error> {
        if new_len > self.0.capacity() {
            return Err(aead::Error);
        }
        let len = self.0.len();
        if new_len > len {
            unsafe { self.0.set_len(new_len) };
            self.0.as_mut_slice()[len..].fill(0);
        } else {
            self.0.truncate(new_len);
        }
        Ok(())
    }
}

#[cfg(feature = "std")]
impl<const CAP: usize> std::io::Write for ArrayBuffer<CAP> {
    #[inline]
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let amt = std::cmp::min(data.len(), self.0.remaining_capacity());
        self.0.try_extend_from_slice(&data[..amt]).unwrap();
        Ok(amt)
    }
    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(not(feature = "std"))]
impl<const CAP: usize> crate::rw::Write for ArrayBuffer<CAP> {
    type Error = IoError;
    #[inline]
    fn write(&mut self, data: &[u8]) -> Result<usize, Self::Error> {
        let amt = std::cmp::min(data.len(), self.0.remaining_capacity());
        self.0.try_extend_from_slice(&data[..amt]).unwrap();
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
