# Overview
ncrypt is a simple program for encrypting, decrypting, and signing files using modern cryptographic algorithms.

## Using ncrypt (examples)
| **Command**       | **Options**              | **Description**                                | **Example**                                                                 |
|--------------------|--------------------------|------------------------------------------------|-----------------------------------------------------------------------------|
| `encrypt`          | `-i`, `-o`              | Encrypt using password                         | `ncrypt encrypt -i secret_data.txt -o secret_data.txt.enc`                 |
| `encrypt`          | `-k`, `-i`, `-o`        | Encrypt using a keyfile                        | `ncrypt encrypt -k keyfile.pem -i secret_data.txt -o secret_data.txt.enc`  |
| `encrypt`          | `-c`, `-i`, `-o`        | Compress and encrypt                           | `ncrypt encrypt -c -i secret_data.txt -o secret_data.txt.enc`              |
| `decrypt`          | `-i`, `-o`              | Decrypt a file                                 | `ncrypt decrypt -i secret_data.txt.enc -o secret_data.txt`                 |
| `gen-keyfile`      | `-o`                    | Generate a keyfile                             | `ncrypt gen-keyfile -o keyfile.pem`                                        |
| `gen-keypair`      | `-p`                    | Generate an ED25519 keypair                    | `ncrypt gen-keypair -p main`                                               |
| `read-header`      | `-i`                    | Read header from an `ncrypt` file              | `ncrypt read-header -i secret_data.txt.enc`                                |
| `sign`             | `-p`, `-i`, `-o`        | Sign a file with an ED25519 private key        | `ncrypt sign -p main_prvkey.pem -i message.txt -o message.txt.sig`         |
| `verify`           | `-p`, `-i`, `-s`        | Verify a file with an ED25519 public key       | `ncrypt verify -p main_pubkey.pem -i message.txt -s message.txt.sig`       |

## Compiling
`cargo build --release`

This will create an optimized/release executable in the `./target/release` directory.

Note: Make sure you have Rust and Cargo installed on your system before attempting to compile ncrypt.

## Used Algorithms
ncrypt uses a variety of modern cryptographic algorithms to ensure the security and integrity of the data. Here are the algorithms used and their purposes:

- **XChaCha20-Poly1305**: Used for encryption and decryption in the `encrypt` and `decrypt` commands.
- **Argon2**: Used for key derivation in the `encrypt` and `decrypt` commands when a password is provided.
- **ED25519**: Used for public-key cryptography in the `gen-keypair` command to generate keypairs, and in the `sign` and `verify` commands for signing and verifying files.
- **Blake3**: Used for hashing in the `sign` and `verify` commands to generate digital signatures.
- **Snappy**: Used for compression in the `encrypt` command when the `-c` option is specified.