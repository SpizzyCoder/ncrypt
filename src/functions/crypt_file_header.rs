use std::{
    fmt,
    fs::File,
    io::{Read, Write},
};

use anyhow::Result;

use super::{ARGON2_SALT_LEN, XCHACHA20_NONCE_LEN};

const SIGNATURE: &'static str = "NCRYPT";
const SIGNATURE_LEN: u8 = SIGNATURE.len() as u8;

#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    Keyfile,
    Password,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mode::Keyfile => write![f, "keyfile"],
            Mode::Password => write![f, "password"],
        }
    }
}

impl Mode {
    fn to_u8(&self) -> u8 {
        match self {
            Mode::Keyfile => 0,
            Mode::Password => 1,
        }
    }

    fn from_u8(num: u8) -> Self {
        match num {
            0 => Mode::Keyfile,
            1 => Mode::Password,
            _ => panic!["Invalid u8 (Failed to convert u8 to Mode enum)"],
        }
    }
}

pub struct NCryptFileHeader {
    pub signature: &'static str,
    pub program_version_major: u8,
    pub program_version_minor: u8,
    pub program_version_patch: u8,
    pub mode: Mode,
    pub compression: bool,
    pub time_cost_argon2: u32,
    pub nonce: [u8; XCHACHA20_NONCE_LEN],
    pub password_salt: Option<[u8; ARGON2_SALT_LEN]>,
}

impl fmt::Display for NCryptFileHeader {
    fn fmt(&self, mut f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln![f, "=== [NCryptFileHeader]"]?;
        writeln![f, "Signature: {}", self.signature]?;
        writeln![
            f,
            "Program version: {}.{}.{}",
            self.program_version_major, self.program_version_minor, self.program_version_patch
        ]?;
        writeln![f, "Mode: {}", self.mode]?;
        writeln![f, "Compression: {}", self.compression]?;
        writeln![f, "Time cost argon2: {}", self.time_cost_argon2]?;

        write![f, "Nonce: "]?;
        write_readable_data(&mut f, &self.nonce)?;

        write![f, "Password salt: "]?;
        if let Some(password_salt) = self.password_salt {
            write_readable_data(&mut f, &password_salt)?;
        } else {
            writeln![f, "None"]?;
        }

        return Ok(());
    }
}

impl NCryptFileHeader {
    pub fn new(
        mode: Mode,
        compression: bool,
        time_cost_argon2: u32,
        nonce: [u8; XCHACHA20_NONCE_LEN],
        password_salt: Option<[u8; ARGON2_SALT_LEN]>,
    ) -> Self {
        return Self {
            signature: SIGNATURE,
            program_version_major: env!["CARGO_PKG_VERSION_MAJOR"].parse().unwrap(),
            program_version_minor: env!["CARGO_PKG_VERSION_MINOR"].parse().unwrap(),
            program_version_patch: env!["CARGO_PKG_VERSION_PATCH"].parse().unwrap(),
            mode,
            compression,
            time_cost_argon2,
            nonce,
            password_salt,
        };
    }

    pub fn read_from_file(file: &mut File) -> Result<Self> {
        let signature: String = {
            let mut signature_bytes: Vec<u8> = vec![0; SIGNATURE_LEN as usize];
            file.read_exact(&mut signature_bytes)?;

            String::from_utf8(signature_bytes)?
        };

        if signature != SIGNATURE {
            return Err(anyhow::Error::msg("Signature doesn't match"));
        }

        let mut versions: [u8; 3] = [0; 3];
        file.read_exact(&mut versions)?;

        let mut mode: [u8; 1] = [0; 1];
        file.read_exact(&mut mode)?;

        let mut compression: [u8; 1] = [0; 1];
        file.read_exact(&mut compression)?;

        let mut time_cost_argon2: [u8; 4] = [0; 4];
        file.read_exact(&mut time_cost_argon2)?;

        let mut nonce: [u8; XCHACHA20_NONCE_LEN] = [0; XCHACHA20_NONCE_LEN];
        file.read_exact(&mut nonce)?;

        let mut password_salt: Option<[u8; ARGON2_SALT_LEN]> = None;

        if Mode::from_u8(mode[0]) == Mode::Password {
            let mut salt: [u8; ARGON2_SALT_LEN] = [0; ARGON2_SALT_LEN];

            file.read_exact(&mut salt)?;

            password_salt = Some(salt);
        }

        return Ok(Self {
            signature: SIGNATURE,
            program_version_major: versions[0],
            program_version_minor: versions[1],
            program_version_patch: versions[2],
            mode: Mode::from_u8(mode[0]),
            compression: if compression[0] == 1 { true } else { false },
            time_cost_argon2: u32::from_be_bytes(time_cost_argon2),
            nonce,
            password_salt,
        });
    }

    pub fn write_to_file(&self, file: &mut File) -> Result<()> {
        file.write_all(&self.to_bytes())?;

        return Ok(());
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend_from_slice(self.signature.as_bytes());
        bytes.extend_from_slice(&[
            self.program_version_major,
            self.program_version_minor,
            self.program_version_patch,
        ]);
        bytes.extend_from_slice(&[self.mode.to_u8()]);
        bytes.extend_from_slice(&[self.compression as u8]);
        bytes.extend_from_slice(&self.time_cost_argon2.to_be_bytes());
        bytes.extend_from_slice(self.nonce.as_slice());
        if let Some(ref password_salt) = self.password_salt {
            bytes.extend_from_slice(password_salt);
        }

        return bytes;
    }
}

fn write_readable_data(mut writer: impl fmt::Write, data: &[u8]) -> fmt::Result {
    if data.len() > 6 {
        for byte in data[..3].iter() {
            write![writer, "{:02x}", byte]?;
        }

        write![writer, "..."]?;

        for byte in data[data.len() - 3..].iter() {
            write![writer, "{:02x}", byte]?;
        }
    } else {
        for byte in data.iter() {
            write![writer, "{:02x}", byte]?;
        }
    }

    writeln![writer]?;

    return Ok(());
}
