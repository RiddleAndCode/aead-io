use aead::Buffer;

pub trait CappedBuffer: Buffer {
    fn capacity(&self) -> usize;
}

pub trait ResizeBuffer: Buffer {
    fn resize_zeroed(&mut self, new_len: usize) -> Result<(), aead::Error>;
}

#[cfg(feature = "alloc")]
impl CappedBuffer for alloc::vec::Vec<u8> {
    fn capacity(&self) -> usize {
        self.capacity()
    }
}

#[cfg(feature = "alloc")]
impl ResizeBuffer for alloc::vec::Vec<u8> {
    fn resize_zeroed(&mut self, new_len: usize) -> Result<(), aead::Error> {
        self.resize(new_len, 0);
        Ok(())
    }
}
