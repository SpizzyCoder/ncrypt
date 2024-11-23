# Overview
ncrypt is a simple program for encrypting, decrypting, and signing files using modern cryptographic algorithms.

## Using ncrypt
ncrypt provides a variety of commands for encrypting, decrypting, and signing files. Here are some examples of how to use ncrypt:

### Simple Password Encryption
To encrypt a file using a password, use the following command:

`ncrypt encrypt -i secret_data.txt -o secret_data.txt.enc`

This will prompt you to enter a password, and then encrypt the file `secret_data.txt` and save the encrypted data to `secret_data.txt.enc`.

### Encryption with Keyfile
To encrypt a file using a keyfile, use the following command:

`ncrypt encrypt -k keyfile.pem -i secret_data.txt -o secret_data.txt.enc`

This will use the keyfile `keyfile.pem` to encrypt the file `secret_data.txt` and save the encrypted data to `secret_data.txt.enc`.

### Compressed Encryption
To compress and encrypt a file, use the following command:

`ncrypt encrypt -c -i secret_data.txt -o secret_data.txt.enc`

This will compress the file `secret_data.txt` and then encrypt it, saving the encrypted data to `secret_data.txt.enc`.

### Decryption
To decrypt a file, use the following command:

`ncrypt decrypt -i secret_data.txt.enc -o secret_data.txt`

This will decrypt the file `secret_data.txt.enc` and save the decrypted data to `secret_data.txt`.

### Generating Keyfile
To generate a keyfile, use the following command:

`ncrypt gen-keyfile -o keyfile.pem`

This will generate a new keyfile and save it to `keyfile.pem`.

### Generating a ED25519 Keypair
To generate a ED25519 keypair, use the following command:

`ncrypt gen-keypair -p main`

This will generate a new ED25519 keypair and save the private key to `main_prvkey.pem` and the public key to `main_pubkey.pem`.

### Read Header from a ncrypt File
To read the header from a ncrypt file, use the following command:

`ncrypt read-header -i secret_data.txt.enc`

This will print the header information from the file `secret_data.txt.enc`.

### Sign a File
To sign a file using a ED25519 private key, use the following command:

`ncrypt sign -p main_prvkey.pem -i message.txt -o message.txt.sig`

This will sign the file `message.txt` using the private key `main_prvkey.pem` and save the signature to `message.txt.sig`.

### Verify a File
To verify a file using a ED25519 public key, use the following command:

`ncrypt verify -p main_pubkey.pem -i message.txt -s message.txt.sig`

This will verify the signature of the file `message.txt` using the public key `main_pubkey.pem` and the signature `message.txt.sig`.

## Compiling
ncrypt can be compiled using the Rust compiler Cargo. To compile the program, navigate to the project directory and run the following command:

`cargo build`

This will compile the program and create an executable in the `target/debug` directory. To create a release build, use the following command:

`cargo build --release`

This will create an optimized executable in the `target/release` directory.

Note: Make sure you have Rust and Cargo installed on your system before attempting to compile ncrypt.

## Used Algorithms
ncrypt uses a variety of modern cryptographic algorithms to ensure the security and integrity of the data. Here are the algorithms used and their purposes:

- **XChaCha20-Poly1305**: Used for encryption and decryption in the `encrypt` and `decrypt` commands.
- **Argon2**: Used for key derivation in the `encrypt` and `decrypt` commands when a password is provided.
- **ED25519**: Used for public-key cryptography in the `gen-keypair` command to generate keypairs, and in the `sign` and `verify` commands for signing and verifying files.
- **Blake3**: Used for hashing in the `sign` and `verify` commands to generate digital signatures.
- **Snappy**: Used for compression in the `encrypt` command when the `-c` option is specified.