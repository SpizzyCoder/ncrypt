use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

mod functions;

#[derive(Subcommand)]
enum Command {
    /// Encrypt file
    Encrypt {
        /// Compression
        #[arg(short)]
        compression: bool,

        /// Keyfile
        #[arg(short)]
        keyfile: Option<PathBuf>,

        /// Input file
        #[arg(short)]
        inputfile: PathBuf,

        /// Output file
        #[arg(short)]
        outputfile: PathBuf,
    },

    /// Decrypt file
    Decrypt {
        /// Keyfile
        #[arg(short)]
        keyfile: Option<PathBuf>,

        /// Input file
        #[arg(short)]
        inputfile: PathBuf,

        /// Output file
        #[arg(short)]
        outputfile: PathBuf,
    },

    /// Generate a keyfile
    GenKeyfile {
        /// Destination for the keyfile
        #[arg(short)]
        outputfile: PathBuf,
    },

    /// Generate a keypair
    GenKeypair {
        /// Prefix of the keys (e.g. [PREFIX]_prvkey.pem)
        #[arg(short)]
        prefix: String,

        /// Destination folder for the keypair
        #[arg(short, default_value = ".")]
        outputdir: PathBuf,
    },

    /// Read header from ncrypt file
    ReadHeader {
        /// Input file
        #[arg(short)]
        inputfile: PathBuf,
    },

    /// Sign data
    Sign {
        /// Private key
        #[arg(short)]
        private_key: PathBuf,

        /// File to sign
        #[arg(short)]
        inputfile: PathBuf,

        /// Output file (Signature)
        #[arg(short)]
        outputfile: PathBuf,
    },

    /// Verify data
    Verify {
        /// Public key
        #[arg(short)]
        public_key: PathBuf,

        /// File to verify
        #[arg(short)]
        inputfile: PathBuf,

        /// Signaturefile
        #[arg(short)]
        signaturefile: PathBuf,
    },
}

/// A simple program for encrypting, decrypting, and signing files using modern cryptographic algorithms.
///
/// Algorithms used:
/// Encryption/Decryption: XChaCha20-Poly1305
/// Key Derivation: Argon2
/// Public-Key Cryptography: ED25519
/// Hashing: Blake3
/// Compression: Snappy
#[derive(Parser)]
#[command(version, about, verbatim_doc_comment)]
struct Args {
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    cmd: Command,
}

fn main() -> Result<()> {
    let args: Args = Args::parse();

    match args.cmd {
        Command::Encrypt {
            compression,
            keyfile,
            inputfile,
            outputfile,
        } => functions::encrypt(args.verbose, compression, keyfile, inputfile, outputfile)?,
        Command::Decrypt {
            keyfile,
            inputfile,
            outputfile,
        } => functions::decrypt(args.verbose, keyfile, inputfile, outputfile)?,
        Command::GenKeyfile { outputfile } => functions::gen_keyfile(args.verbose, outputfile)?,
        Command::GenKeypair { outputdir, prefix } => {
            functions::gen_keypair(args.verbose, outputdir, prefix)?
        }
        Command::ReadHeader { inputfile } => functions::read_header(inputfile)?,
        Command::Sign {
            private_key,
            inputfile,
            outputfile,
        } => functions::sign(args.verbose, private_key, inputfile, outputfile)?,
        Command::Verify {
            public_key,
            inputfile,
            signaturefile,
        } => functions::verify(args.verbose, public_key, inputfile, signaturefile)?,
    };

    return Ok(());
}
