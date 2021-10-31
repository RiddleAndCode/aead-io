# aead-io

Provides a wrapper around a [`Write`](std::io::Write)/[`Read`](std::io::Read) object and a
[`StreamPrimitive`](aead::stream::StreamPrimitive) to provide an easy interface for doing
correct encryption.

```rust
let key = b"my very super super secret key!!".into();
let plaintext = b"hello world!";

let ciphertext = {
    let mut ciphertext = Vec::default();
    let mut writer = EncryptBE32BufWriter::<ChaCha20Poly1305, _, _>::new(
        key,
        &Default::default(), // please use a better nonce ;)
        Vec::with_capacity(128),
        &mut ciphertext,
    )
    .unwrap();
    writer.write_all(plaintext)?;
    writer.flush()?;
    ciphertext
};

let decrypted = {
    let mut reader = DecryptBE32BufReader::<ChaCha20Poly1305, _, _>::new(
        key,
        Vec::with_capacity(256),
        ciphertext.as_slice(),
    )
    .unwrap();
    let mut out = Vec::new();
    let _ = reader.read_to_end(&mut out).unwrap();
    out
};

assert_eq!(decrypted, plaintext);
#
```

## `no_std`

This package is compatible with `no_std` environments. Just disable the default features, and
implement the [`Buffer`](aead::Buffer), [`CappedBuffer`](CappedBuffer),
[`ResizeBuffer`](ResizeBuffer), [`Write`](Write) and
[`Read`](Read) accordingly. There should be some default implementations for `Vec<u8>`
and byte slices

License: MIT OR Apache-2.0
