use std::fs::File;
use std::fs::{self, Metadata};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use argon2::Argon2;
use blake3::Hasher;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{AeadCore, KeyInit, XChaCha20Poly1305};
use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::Verifier;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use indicatif::{ProgressBar, ProgressStyle};
use rand::rngs::OsRng;
use rand::RngCore;
use snap::raw::{Decoder, Encoder};
use zeroize::Zeroize;

mod crypt_file_header;
use crypt_file_header::{Mode, NCryptFileHeader};

mod pem_files;
use pem_files::{keyfile_to_pem, pem_to_keyfile, pem_to_signature, signature_to_pem};

const BUFFER_LEN: usize = 1024 * 128;
const XCHACHA20_NONCE_LEN: usize = 24;
const XCHACHA20_KEY_LEN: usize = 32;
const ARGON2_SALT_LEN: usize = 64;
const XCHACHA20_TAG_LEN: usize = 16;
const ED25519_SIGNATURE_LEN: usize = 64;
const BLAKE3_HASH_LEN: usize = 32;
const PROGRESS_BAR_TEMPLATE: &'static str =
    "[{bar:40.cyan/blue}] {percent}% {binary_bytes}/{binary_total_bytes}";
const PROGRESS_BAR_CHARS: &'static str = "=>-";

pub fn encrypt(
    verbose: bool,
    compression: bool,
    keyfile: Option<PathBuf>,
    inputfile: PathBuf,
    outputfile: PathBuf,
) -> Result<()> {
    let mut key: [u8; XCHACHA20_KEY_LEN] = [0; XCHACHA20_KEY_LEN];
    let password_salt: Option<[u8; ARGON2_SALT_LEN]>;
    let mode: Mode;

    if let Some(keyfile) = keyfile {
        // User wants to encrypt file with a keyfile

        print_log(verbose, format!["Reading keyfile"]);

        key = pem_to_keyfile(&fs::read_to_string(&keyfile)?)?;

        password_salt = None;
        mode = Mode::Keyfile;
    } else {
        // User wants to encrypt file with a password

        let mut password: String = rpassword::prompt_password("Password: ")?;

        print_log(verbose, format!["Deriving key from password"]);

        let mut salt: [u8; ARGON2_SALT_LEN] = [0; ARGON2_SALT_LEN];
        OsRng.fill_bytes(&mut salt);

        if let Err(err) = Argon2::default().hash_password_into(password.as_bytes(), &salt, &mut key)
        {
            return Err(anyhow::Error::msg(format![
                "Failed to derive key from password ({})",
                err
            ]));
        }

        password.zeroize();

        password_salt = Some(salt);
        mode = Mode::Password;
    }

    let cipher: XChaCha20Poly1305 = XChaCha20Poly1305::new(&key.into());
    key.zeroize();

    let unencrypted_file_metadata: Metadata = fs::metadata(&inputfile)?;
    let mut unencrypted_file: File = File::open(&inputfile)?;
    let mut encrypted_file: File = File::create(&outputfile)?;

    print_log(verbose, format!["Generating nonce"]);
    let mut nonce: [u8; XCHACHA20_NONCE_LEN] = XChaCha20Poly1305::generate_nonce(&mut OsRng).into();

    print_log(verbose, format!["Writing header to file"]);
    let header: NCryptFileHeader =
        NCryptFileHeader::new(mode, compression, &nonce.into(), password_salt);
    header.write_to_file(&mut encrypted_file)?;

    let progress_bar: ProgressBar = ProgressBar::new(unencrypted_file_metadata.len());
    progress_bar.set_style(
        ProgressStyle::with_template(PROGRESS_BAR_TEMPLATE)
            .unwrap()
            .progress_chars(PROGRESS_BAR_CHARS),
    );

    print_log(verbose, format!["Encrypting..."]);
    let mut buffer: Vec<u8> = vec![0; BUFFER_LEN];
    let mut encoder: Encoder = Encoder::new();
    loop {
        let read_bytes: usize = unencrypted_file.read(&mut buffer)?;

        if read_bytes == 0 {
            break;
        }

        let data_to_write: &[u8] = {
            if compression {
                &encoder.compress_vec(&buffer[..read_bytes])?
            } else {
                &buffer[..read_bytes]
            }
        };

        let data_length_to_write: u32 = (data_to_write.len() + XCHACHA20_TAG_LEN) as u32;

        match cipher.encrypt(
            nonce.as_ref().into(),
            data_length_to_write.to_be_bytes().as_slice(),
        ) {
            Ok(ciphertext) => {
                encrypted_file.write_all(&ciphertext)?;

                increment_nonce(&mut nonce);
            }
            Err(err) => {
                return Err(anyhow::Error::msg(format![
                    "Failed to encrypt data length ({})",
                    err
                ]));
            }
        }

        match cipher.encrypt(nonce.as_ref().into(), data_to_write) {
            Ok(ciphertext) => {
                encrypted_file.write_all(&ciphertext)?;

                increment_nonce(&mut nonce);
            }
            Err(err) => {
                return Err(anyhow::Error::msg(format![
                    "Failed to encrypt data length ({})",
                    err
                ]));
            }
        };

        progress_bar.inc(read_bytes as u64);
    }

    progress_bar.finish();

    return Ok(());
}

pub fn decrypt(
    verbose: bool,
    keyfile: Option<PathBuf>,
    inputfile: PathBuf,
    outputfile: PathBuf,
) -> Result<()> {
    let encrypted_file_metadata: Metadata = fs::metadata(&inputfile)?;
    let mut encrypted_file: File = File::open(&inputfile)?;

    print_log(verbose, format!["Reading header"]);
    let crypt_header: NCryptFileHeader = NCryptFileHeader::read_from_file(&mut encrypted_file)?;
    let mut nonce: [u8; XCHACHA20_NONCE_LEN] = crypt_header.nonce;

    let mut key: [u8; XCHACHA20_KEY_LEN] = [0; XCHACHA20_KEY_LEN];

    if keyfile.is_some() && crypt_header.mode == Mode::Keyfile {
        print_log(verbose, format!["Reading keyfile"]);
        key = pem_to_keyfile(&fs::read_to_string(&keyfile.unwrap())?)?; // Unwrap is safe
    } else if keyfile.is_none() && crypt_header.mode == Mode::Keyfile {
        return Err(anyhow::Error::msg(format![
            "File was encrypted with a keyfile -> provide a keyfile"
        ]));
    } else if keyfile.is_none() && crypt_header.mode == Mode::Password {
        let mut password: String = rpassword::prompt_password("Password: ")?;

        print_log(verbose, format!["Deriving key from password"]);

        // Unwrap is safe
        if let Err(err) = Argon2::default().hash_password_into(
            password.as_bytes(),
            crypt_header.password_salt.as_ref().unwrap(),
            &mut key,
        ) {
            return Err(anyhow::Error::msg(format![
                "Failed to derive key from password ({})",
                err
            ]));
        }

        password.zeroize();
    } else if keyfile.is_some() && crypt_header.mode == Mode::Password {
        return Err(anyhow::Error::msg(format![
            "File was encrypted with a password -> provide a password (remove keyfile)"
        ]));
    }

    let mut unencrypted_file: File = File::create(&outputfile)?;
    let cipher: XChaCha20Poly1305 = XChaCha20Poly1305::new(&key.into());
    key.zeroize();

    let progress_bar: ProgressBar = ProgressBar::new(encrypted_file_metadata.len());
    progress_bar.set_style(
        ProgressStyle::with_template(PROGRESS_BAR_TEMPLATE)
            .unwrap()
            .progress_chars(PROGRESS_BAR_CHARS),
    );

    print_log(verbose, format!["Decrypting..."]);
    let mut length_buffer: [u8; 4 + XCHACHA20_TAG_LEN] = [0; 4 + XCHACHA20_TAG_LEN];
    let mut decoder: Decoder = Decoder::new();
    loop {
        if let Err(_) = encrypted_file.read_exact(&mut length_buffer) {
            break;
        }

        let data_length: u32 = {
            let data_length: Vec<u8> = match cipher.decrypt(&nonce.into(), length_buffer.as_ref()) {
                Ok(data) => {
                    increment_nonce(&mut nonce);

                    data
                }
                Err(_) => return Err(anyhow::Error::msg(
                    "Failed to decrypt data (invalid keyfile/password or file has been corrupted)",
                )),
            };

            let byte_array: [u8; 4] = data_length.try_into().unwrap(); // Unwrap is safe

            u32::from_be_bytes(byte_array)
        };

        let mut encrypted_data: Vec<u8> = vec![0; data_length as usize];
        encrypted_file.read_exact(&mut encrypted_data)?;

        let decrypted_data: Vec<u8> =
            match cipher.decrypt(&nonce.into(), encrypted_data.as_ref()) {
                Ok(decrypted_data) => {
                    increment_nonce(&mut nonce);

                    decrypted_data
                }
                Err(_) => return Err(anyhow::Error::msg(
                    "Failed to decrypt data (invalid keyfile/password or file has been corrupted)",
                )),
            };

        if crypt_header.compression {
            unencrypted_file.write_all(&decoder.decompress_vec(&decrypted_data)?)?;
        } else {
            unencrypted_file.write_all(&decrypted_data)?;
        }

        progress_bar.inc((4 + 16) + data_length as u64);
    }

    progress_bar.finish();

    return Ok(());
}

pub fn gen_keyfile(verbose: bool, outputfile: PathBuf) -> Result<()> {
    let mut key: [u8; XCHACHA20_KEY_LEN] = [0u8; XCHACHA20_KEY_LEN];

    print_log(verbose, format!["Generating key"]);
    OsRng.fill_bytes(&mut key);

    print_log(verbose, format!["Writing key to file"]);
    fs::write(&outputfile, keyfile_to_pem(&key)?)?;

    return Ok(());
}

pub fn gen_keypair(verbose: bool, outputdir: PathBuf, prefix: String) -> Result<()> {
    print_log(verbose, format!["Generating private key"]);
    let mut csprng: OsRng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);

    print_log(verbose, format!["Writing private key to file"]);
    signing_key.write_pkcs8_pem_file(
        format!["{}/{}_prvkey.pem", outputdir.display(), prefix],
        LineEnding::LF,
    )?;

    print_log(
        verbose,
        format!["Deriving (from private key) and writing public key to file"],
    );
    signing_key.verifying_key().write_public_key_pem_file(
        format!["{}/{}_pubkey.pem", outputdir.display(), prefix],
        LineEnding::LF,
    )?;

    return Ok(());
}

pub fn read_header(inputfile: PathBuf) -> Result<()> {
    let mut file: File = File::open(&inputfile)?;

    let header: NCryptFileHeader = NCryptFileHeader::read_from_file(&mut file)?;

    print!["{}", header];

    return Ok(());
}

pub fn sign(
    verbose: bool,
    private_key: PathBuf,
    inputfile: PathBuf,
    outputfile: PathBuf,
) -> Result<()> {
    print_log(verbose, format!["Reading private key"]);
    let mut signing_key: SigningKey = SigningKey::read_pkcs8_pem_file(&private_key)?;

    print_log(verbose, format!["Creating blake3 hash from file"]);
    let hash: [u8; BLAKE3_HASH_LEN] = hash_file(&inputfile)?;

    print_log(verbose, format!["Creating signature"]);
    let signature: Signature = signing_key.sign(&hash);
    let signature_as_bytes: [u8; ED25519_SIGNATURE_LEN] = signature.to_bytes().try_into().unwrap(); // Unwrap is pretty much safe

    print_log(verbose, format!["Writing signature to file"]);
    fs::write(&outputfile, signature_to_pem(&signature_as_bytes)?)?;

    return Ok(());
}

pub fn verify(
    verbose: bool,
    public_key: PathBuf,
    inputfile: PathBuf,
    signaturefile: PathBuf,
) -> Result<()> {
    print_log(verbose, format!["Creating blake3 hash from file"]);
    let hash: [u8; BLAKE3_HASH_LEN] = hash_file(&inputfile)?;

    print_log(verbose, format!["Reading public key"]);
    let public_key: VerifyingKey = VerifyingKey::read_public_key_pem_file(&public_key)?;

    let signature: [u8; ED25519_SIGNATURE_LEN] = {
        print_log(verbose, format!["Reading signature"]);

        pem_to_signature(&fs::read_to_string(&signaturefile)?)?
    };

    print_log(
        verbose,
        format!["Verifying calculated hash with hash in signature"],
    );
    if public_key.verify(&hash, &signature.into()).is_ok() {
        println!["Match"];
        return Ok(());
    } else {
        return Err(anyhow::Error::msg("Invalid file, signature or public key"));
    }
}

fn increment_nonce(nonce: &mut [u8; XCHACHA20_NONCE_LEN]) {
    for byte in nonce.iter_mut().rev() {
        if *byte < u8::MAX {
            *byte += 1;
            return;
        } else {
            *byte = 0;
        }
    }
}

fn hash_file(filepath: &Path) -> Result<[u8; BLAKE3_HASH_LEN]> {
    let mut file: File = File::open(&filepath)?;

    let mut hasher: Hasher = blake3::Hasher::new();
    let mut buffer: Vec<u8> = vec![0; BUFFER_LEN];
    loop {
        let read_bytes: usize = file.read(&mut buffer)?;

        if read_bytes == 0 {
            break;
        }

        hasher.update(&buffer[..read_bytes]);
    }

    return Ok(hasher.finalize().into());
}

fn print_log(verbose: bool, text: String) {
    if verbose {
        println!["[VERBOSE]: {}", text];
    }
}
