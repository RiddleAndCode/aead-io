//! Provides a wrapper around a [`Write`](std::io::Write)/[`Read`](std::io::Read) object and a
//! [`StreamPrimitive`](aead::stream::StreamPrimitive) to provide an easy interface for doing
//! correct encryption.
//!
//! ```
//! # use aead_io::{DecryptBE32BufReader, EncryptBE32BufWriter};
//! # use aead::stream::{Nonce, StreamBE32};
//! # use aead::NewAead;
//! # use chacha20poly1305::{ChaCha20Poly1305, Key};
//! # use std::io::{Read, Write, Result};
//! #
//! # fn main() -> Result<()> {
//! let key = b"my very super super secret key!!".into();
//! let plaintext = b"hello world!";
//!
//! let ciphertext = {
//!     let mut ciphertext = Vec::default();
//!     let mut writer = EncryptBE32BufWriter::<ChaCha20Poly1305, _, _>::new(
//!         key,
//!         &Default::default(), // please use a better nonce ;)
//!         Vec::with_capacity(128),
//!         &mut ciphertext,
//!     )
//!     .unwrap();
//!     writer.write_all(plaintext)?;
//!     writer.flush()?;
//!     ciphertext
//! };
//!
//! let decrypted = {
//!     let mut reader = DecryptBE32BufReader::<ChaCha20Poly1305, _, _>::new(
//!         key,
//!         Vec::with_capacity(256),
//!         ciphertext.as_slice(),
//!     )
//!     .unwrap();
//!     let mut out = Vec::new();
//!     let _ = reader.read_to_end(&mut out).unwrap();
//!     out
//! };
//!
//! assert_eq!(decrypted, plaintext);
//! #
//! # Ok(())
//! # }
//! ```
//!
//! # `no_std`
//!
//! This package is compatible with `no_std` environments. Just disable the default features, and
//! implement the [`Buffer`](aead::Buffer), [`CappedBuffer`](CappedBuffer),
//! [`ResizeBuffer`](ResizeBuffer), [`Write`](Write) and
//! [`Read`](Read) accordingly. There should be some default implementations for `Vec<u8>`
//! and slices if `alloc` is enabled but it is currently incomplete.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod buffer;
mod error;
mod reader;
mod rw;
mod writer;

pub use aead;

pub use buffer::{CappedBuffer, ResizeBuffer};
pub use error::{Error, InvalidCapacity};
pub use reader::DecryptBufReader;
pub use rw::{Read, Write};
pub use writer::EncryptBufWriter;

use aead::stream::{StreamBE32, StreamLE31};

pub type EncryptBE32BufWriter<A, B, W> = EncryptBufWriter<A, B, W, StreamBE32<A>>;
pub type EncryptLE31BufWriter<A, B, W> = EncryptBufWriter<A, B, W, StreamLE31<A>>;
pub type DecryptBE32BufReader<A, B, W> = DecryptBufReader<A, B, W, StreamBE32<A>>;
pub type DecryptLE31BufReader<A, B, W> = DecryptBufReader<A, B, W, StreamLE31<A>>;

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
    use aead::stream::{Nonce, StreamBE32};
    use aead::NewAead;
    use chacha20poly1305::{ChaCha20Poly1305, Key};
    use std::io::{Read, Write};

    #[test]
    fn short_message() {
        let aead = {
            let mut key = Key::default();
            key.copy_from_slice(b"my very super super secret key!!");
            ChaCha20Poly1305::new(&key)
        };
        let nonce = Nonce::<ChaCha20Poly1305, StreamBE32<ChaCha20Poly1305>>::default();

        let plaintext = b"hello world!";

        let mut blob = Vec::default();

        let mut writer = EncryptBE32BufWriter::<ChaCha20Poly1305, _, _>::from_aead(
            aead.clone(),
            &nonce,
            Vec::with_capacity(128),
            &mut blob,
        )
        .unwrap();
        writer.write_all(plaintext).unwrap();
        std::io::Write::flush(&mut writer).unwrap();
        drop(writer);

        let mut reader = DecryptBE32BufReader::<ChaCha20Poly1305, _, _>::from_aead(
            aead.clone(),
            Vec::with_capacity(256),
            blob.as_slice(),
        )
        .unwrap();
        let mut out = Vec::new();
        let _ = reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn long_message() {
        let aead = {
            let mut key = Key::default();
            key.copy_from_slice(b"my very super super secret key!!");
            ChaCha20Poly1305::new(&key)
        };
        let nonce = Nonce::<ChaCha20Poly1305, StreamBE32<ChaCha20Poly1305>>::default();

        let plaintext = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur eu erat non turpis viverra mollis vel a mauris. Vestibulum luctus justo vitae diam ultrices, eget vehicula velit consectetur. Sed ut sapien odio. Nullam non porttitor augue. Duis euismod, augue sed blandit eleifend, leo enim rhoncus lacus, in efficitur metus massa quis justo. Nunc velit quam, aliquam vitae enim ut, facilisis molestie odio. Phasellus nec euismod nisi, sit amet dignissim arcu. Nullam pulvinar aliquam purus ut aliquet. Sed iaculis, odio in luctus molestie, purus dui vehicula est, sed egestas erat diam sed arcu. Cras venenatis magna vitae tristique mattis.";

        let mut blob = Vec::default();

        let mut writer = EncryptBE32BufWriter::<ChaCha20Poly1305, _, _>::from_aead(
            aead.clone(),
            &nonce,
            Vec::with_capacity(128),
            &mut blob,
        )
        .unwrap();
        writer.write_all(plaintext).unwrap();
        std::io::Write::flush(&mut writer).unwrap();
        drop(writer);

        let mut reader = DecryptBE32BufReader::<ChaCha20Poly1305, _, _>::from_aead(
            aead.clone(),
            Vec::with_capacity(256),
            blob.as_slice(),
        )
        .unwrap();
        let mut out = Vec::new();
        let _ = reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, plaintext);
    }
}
