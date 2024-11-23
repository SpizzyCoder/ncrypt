use std::fmt::Write;

use anyhow::Result;
use base64::{prelude::BASE64_STANDARD, Engine};

use super::{ED25519_SIGNATURE_LEN, XCHACHA20_KEY_LEN};

const KEYFILE_PEM_BEGIN: &'static str = "----- BEGIN NCRYPT KEYFILE -----";
const KEYFILE_PEM_END: &'static str = "----- BEGIN NCRYPT KEYFILE -----";
const SIGNATURE_PEM_BEGIN: &'static str = "----- BEGIN NCRYPT SIGNATURE -----";
const SIGNATURE_PEM_END: &'static str = "----- BEGIN NCRYPT SIGNATURE -----";

pub fn keyfile_to_pem(key: &[u8; XCHACHA20_KEY_LEN]) -> Result<String> {
    return Ok(data_to_pem(key, KEYFILE_PEM_BEGIN, KEYFILE_PEM_END)?);
}

pub fn pem_to_keyfile(pem: &str) -> Result<[u8; XCHACHA20_KEY_LEN]> {
    return Ok(pem_to_data(pem, KEYFILE_PEM_BEGIN, KEYFILE_PEM_END)?);
}

pub fn signature_to_pem(signature: &[u8; ED25519_SIGNATURE_LEN]) -> Result<String> {
    return Ok(data_to_pem(
        signature,
        SIGNATURE_PEM_BEGIN,
        SIGNATURE_PEM_END,
    )?);
}

pub fn pem_to_signature(pem: &str) -> Result<[u8; ED25519_SIGNATURE_LEN]> {
    return Ok(pem_to_data(pem, SIGNATURE_PEM_BEGIN, SIGNATURE_PEM_END)?);
}

fn data_to_pem(data: &[u8], pem_begin: &str, pem_end: &str) -> Result<String> {
    let mut pem: String = String::new();

    write![
        pem,
        "{}\n{}\n{}\n",
        pem_begin,
        BASE64_STANDARD.encode(data),
        pem_end
    ]?;

    return Ok(pem);
}

fn pem_to_data<T>(pem: &str, pem_begin: &str, pem_end: &str) -> Result<T>
where
    T: TryFrom<Vec<u8>>,
{
    let pem_splitted: Vec<&str> = pem.trim().split("\n").collect();

    if pem_splitted.len() != 3 {
        return Err(anyhow::Error::msg("Invalid pem file"));
    }

    if pem_splitted[0] != pem_begin || pem_splitted[2] != pem_end {
        return Err(anyhow::Error::msg("Invalid pem file"));
    }

    let data: T = match BASE64_STANDARD.decode(pem_splitted[1])?.try_into() {
        Ok(data) => data,
        Err(_) => return Err(anyhow::Error::msg("Invalid pem file")),
    };

    return Ok(data);
}
