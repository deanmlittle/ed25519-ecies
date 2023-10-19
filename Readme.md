# Ed25519 ECIES

SIE1: A BIE1-based ECIES implementation that is compatible with Ed25519 keys on Solana.


### Encryption
The encryption protocol does the following:

1) Converts an Ed25519 public and private key to their X25519 keys. If no private key is provided, a new one is generated on the fly.
2) Computes a shared secret using ECDH
3) Creates a Public key from the shared secret
4) SHA512 hashes it and splits the resulting bytes into iv, kE and kM
5) AESCBC encrypts the desired message with kE and iv
6) Checksums the message with kM using SHA256-HMAC

### Decryption
The decryption protocol reverses this by:

1) Takes in the private key of the opposing public key provided in the encryption phase
2) Extracts the public key of the opposing private key provided/created in the encryption phase
3) Computes the same shared secret using ECDH, but with the opposing keys to those in the encryption phase
5) Creates a Public key from the shared secret
6) SHA512 hashes it and splits the resulting bytes into iv, kE and kM
7) AESCBC decrypts the ciphertext with kE and iv
8) Calculates the SHA256-HMAC of the message to ensure the provided checksum matches
