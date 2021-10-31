use aead::Buffer;

/// A trait for describing a buffer with a max capacity. Useful for `no_std` environments.
/// Automatically implemented for `Vec<u8>` when `alloc` enabled
pub trait CappedBuffer: Buffer {
    /// Return the maximum capacity of the buffer
    fn capacity(&self) -> usize;
}

#[cfg(feature = "alloc")]
impl CappedBuffer for alloc::vec::Vec<u8> {
    fn capacity(&self) -> usize {
        self.capacity()
    }
}

/// A trait for describing a buffer which can be resized. Useful for `no_std` environments.
/// Automatically implemented for `Vec<u8>` when `alloc` enabled
pub trait ResizeBuffer: Buffer {
    /// Resize to the specified size and fill with zeroes when necessary
    fn resize_zeroed(&mut self, new_len: usize) -> Result<(), aead::Error>;
}

#[cfg(feature = "alloc")]
impl ResizeBuffer for alloc::vec::Vec<u8> {
    fn resize_zeroed(&mut self, new_len: usize) -> Result<(), aead::Error> {
        self.resize(new_len, 0);
        Ok(())
    }
}
