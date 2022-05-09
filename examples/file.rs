use aead_io::{ArrayBuffer, DecryptBufReader, EncryptBufWriter};
use rand::prelude::*;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};

type AeadImpl = chacha20poly1305::ChaCha20Poly1305;
type StreamImpl = aead_io::aead::stream::StreamBE32<AeadImpl>;
type Key = aead_io::aead::Key<AeadImpl>;
type Nonce = aead_io::aead::stream::Nonce<AeadImpl, StreamImpl>;

fn encrypt(key: &Key, nonce: &Nonce, input: impl Read, mut output: impl Write) -> io::Result<()> {
    // create an encrypted writer
    let mut writer = EncryptBufWriter::<AeadImpl, _, _, StreamImpl>::new(
        key,
        nonce,
        ArrayBuffer::<128>::new(),
        &mut output,
    )?;
    // create a buf reader to read chunks
    let mut reader = BufReader::with_capacity(64, input);
    loop {
        // read a chunk
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            break;
        }
        // write encrypted output to output file
        let written = writer.write(chunk)?;
        reader.consume(written);
    }
    Ok(())
}

fn decrypt(key: &Key, input: impl Read, mut output: impl Write) -> io::Result<()> {
    // create a buf reader for reading decrypted chunks
    let reader =
        DecryptBufReader::<AeadImpl, _, _, StreamImpl>::new(key, ArrayBuffer::<256>::new(), input)?;
    let mut buf_reader = BufReader::with_capacity(64, reader);
    loop {
        // read a chunk
        let chunk = buf_reader.fill_buf()?;
        if chunk.is_empty() {
            break;
        }
        // write decrypted output to output file
        let written = output.write(chunk)?;
        buf_reader.consume(written);
    }
    Ok(())
}

fn main() -> io::Result<()> {
    // generate a random key and a random nonce
    let mut rng = rand::thread_rng();
    let key = {
        let mut key = Key::default();
        rng.fill(key.as_mut_slice());
        key
    };
    let nonce = {
        let mut nonce = Nonce::default();
        rng.fill(nonce.as_mut_slice());
        nonce
    };

    // create a directory for playing wtih
    let dir = tempfile::tempdir()?;

    // open a file to encrypt
    let original_file = File::open("./Cargo.toml")?;
    // create a new file for encrypted output
    let encrypted_path = dir.path().join("Cargo.toml.enc");
    let mut encrypted_file = File::create(&encrypted_path)?;
    // encrypt file into new file
    encrypt(&key, &nonce, &original_file, &mut encrypted_file)?;
    println!("encrypted to: {:?}", encrypted_path.display());

    // re-open encrypted file for reading
    encrypted_file = File::open(&encrypted_path)?;
    // create a new output file
    let decrypted_path = dir.path().join("Cargo.toml");
    let mut decrypted_file = File::create(&decrypted_path)?;
    // decrypt file into new file
    decrypt(&key, &encrypted_file, &mut decrypted_file)?;
    println!("decrypted to: {:?}", decrypted_path.display());

    // keep files around to look at
    std::mem::forget(dir);

    Ok(())
}
