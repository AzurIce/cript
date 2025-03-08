//! This package is copied from https://github.com/phayes/ecies-ed25519/
//! 
//! ECIES-ed25519: An Integrated Encryption Scheme on Twisted Edwards Curve25519.
//!

//! ECIES can be used to encrypt data using a public key such that it can only be decrypted
//! by the holder of the corresponding private key. It is based on [curve25519-dalek](https://docs.rs/curve25519-dalek).
//!
//! There are two different backends for HKDF-SHA256 / AES-GCM operations:
//!
//!   - The `pure_rust` backend (default). It uses a collection of pure-rust implementations of SHA2, HKDF, AES, and AEAD.
//!
//!   - The `ring` backend uses [ring](https://briansmith.org/rustdoc/ring/). It uses rock solid primitives based on BoringSSL,
//!     but cannot run on all platforms. For example it won't work in web assembly. To enable it add the following to your Cargo.toml:
//!
//!     `ecies-ed25519 = { version = "0.3", features = ["ring"] }`
//!
//! ## Example Usage
//! ```rust
//! let mut csprng = rand::thread_rng();
//! let (secret, public) = ecies_ed25519::generate_keypair(&mut csprng);
//!
//! let message = "I 💖🔒";
//!
//! // Encrypt the message with the public key such that only the holder of the secret key can decrypt.
//! let encrypted = ecies_ed25519::encrypt(&public, message.as_bytes(), &mut csprng).unwrap();
//!
//! // Decrypt the message with the secret key
//! let decrypted = ecies_ed25519::decrypt(&secret, &encrypted);
//!```
//!
//! ## `serde` support
//!
//! The `serde` feature is provided for serializing / deserializing private and public keys.
//!

use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};

mod keys;
pub use keys::*;

mod pure_rust_backend;
use pure_rust_backend::*;

const HKDF_INFO: &[u8; 13] = b"ecies-ed25519";

const AES_IV_LENGTH: usize = 12;

type AesKey = [u8; 32];
type SharedSecret = [u8; 32];

/// Generate a keypair, ready for use in ECIES
pub fn generate_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (SecretKey, PublicKey) {
    let secret = SecretKey::generate(rng);
    let public = PublicKey::from_secret(&secret);
    (secret, public)
}

/// Encrypt a message using ECIES, it can only be decrypted by the receiver's SecretKey.
pub fn encrypt<R: CryptoRng + RngCore>(
    receiver_pub: &PublicKey,
    msg: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let (ephemeral_sk, ephemeral_pk) = generate_keypair(rng);

    let aes_key = encapsulate(&ephemeral_sk, receiver_pub);
    let encrypted = aes_encrypt(&aes_key, msg, rng)?;

    let mut cipher_text = Vec::with_capacity(PUBLIC_KEY_LENGTH + encrypted.len());
    cipher_text.extend(ephemeral_pk.to_bytes().iter());
    cipher_text.extend(encrypted);

    Ok(cipher_text)
}

/// Decrypt a ECIES encrypted ciphertext using the receiver's SecretKey.
pub fn decrypt(receiver_sec: &SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    if ciphertext.len() <= PUBLIC_KEY_LENGTH {
        return Err(Error::DecryptionFailedCiphertextShort);
    }

    let ephemeral_pk = PublicKey::from_bytes(&ciphertext[..PUBLIC_KEY_LENGTH])?;
    let encrypted = &ciphertext[PUBLIC_KEY_LENGTH..];
    let aes_key = decapsulate(receiver_sec, &ephemeral_pk);

    let decrypted = aes_decrypt(&aes_key, encrypted).map_err(|_| Error::DecryptionFailed)?;

    Ok(decrypted)
}

fn generate_shared(secret: &SecretKey, public: &PublicKey) -> SharedSecret {
    let public = public.to_point();
    #[allow(deprecated)]
    let secret = Scalar::from_bits(secret.to_bytes());
    let shared_point = public * secret;
    let shared_point_compressed = shared_point.compress();

    let output = shared_point_compressed.as_bytes().to_owned();

    output
}

fn encapsulate(emphemeral_sk: &SecretKey, peer_pk: &PublicKey) -> AesKey {
    let shared_point = generate_shared(emphemeral_sk, peer_pk);

    let emphemeral_pk = PublicKey::from_secret(emphemeral_sk);

    let mut master = [0u8; 32 * 2];
    master[..32].clone_from_slice(emphemeral_pk.0.as_bytes());
    master[32..].clone_from_slice(&shared_point);

    hkdf_sha256(&master)
}

fn decapsulate(sk: &SecretKey, emphemeral_pk: &PublicKey) -> AesKey {
    let shared_point = generate_shared(sk, emphemeral_pk);

    let mut master = [0u8; 32 * 2];
    master[..32].clone_from_slice(emphemeral_pk.0.as_bytes());
    master[32..].clone_from_slice(&shared_point);

    hkdf_sha256(&master)
}

/// Error types
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Encryption failed
    #[error("ecies-rd25519: encryption failed")]
    EncryptionFailed,

    /// Decryption failed
    #[error("ecies-rd25519: decryption failed")]
    DecryptionFailed,

    /// Decryption failed - ciphertext too short
    #[error("ecies-rd25519: decryption failed - ciphertext too short")]
    DecryptionFailedCiphertextShort,

    /// Invalid public key bytes
    #[error("ecies-rd25519: invalid public key bytes")]
    InvalidPublicKeyBytes,

    /// Invalid secret key bytes
    #[error("ecies-rd25519: invalid secret key bytes")]
    InvalidSecretKeyBytes,
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use rand::thread_rng as rng;
    use rand::SeedableRng;

    #[test]
    fn test_shared() {
        let (emphemeral_sk, emphemeral_pk) = generate_keypair(&mut rng());
        let (peer_sk, peer_pk) = generate_keypair(&mut rng());

        assert_eq!(
            generate_shared(&emphemeral_sk, &peer_pk),
            generate_shared(&peer_sk, &emphemeral_pk)
        );

        // Make sure it fails when wrong keys used
        assert_ne!(
            generate_shared(&emphemeral_sk, &emphemeral_pk),
            generate_shared(&peer_sk, &peer_pk)
        )
    }

    #[test]
    fn test_encapsulation() {
        let (emphemeral_sk, emphemeral_pk) = generate_keypair(&mut rng());
        let (peer_sk, peer_pk) = generate_keypair(&mut rng());

        assert_eq!(
            encapsulate(&emphemeral_sk, &peer_pk),
            decapsulate(&peer_sk, &emphemeral_pk)
        )
    }

    #[test]
    fn test_aes() {
        let mut test_rng = rand::rngs::StdRng::from_seed([0u8; 32]);
        let mut key = [0u8; 32];
        test_rng.fill_bytes(&mut key);

        let plaintext = b"ABC";
        let encrypted = aes_encrypt(&key, plaintext, &mut test_rng).unwrap();
        let decrypted = aes_decrypt(&key, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());

        // Test bad ciphertext
        assert!(aes_decrypt(&key, &[0u8; 16]).is_err());

        // Test bad secret key
        let bad_secret = SecretKey::generate(&mut rng());
        assert!(aes_decrypt(bad_secret.as_bytes(), &encrypted).is_err());
    }

    #[test]
    fn test_ecies_ed25519() {
        let (peer_sk, peer_pk) = generate_keypair(&mut rng());

        let plaintext = b"ABOLISH ICE";

        let encrypted = encrypt(&peer_pk, plaintext, &mut rng()).unwrap();
        let decrypted = decrypt(&peer_sk, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());

        // Test bad ciphertext
        assert!(decrypt(&peer_sk, &[0u8; 16]).is_err());

        // Test that it fails when using a bad secret key
        let bad_secret = SecretKey::generate(&mut rng());
        assert!(decrypt(&bad_secret, &encrypted).is_err());
    }

    #[test]
    fn test_hkdf_sha256_interop() {
        let known_key: Vec<u8> = vec![
            204, 68, 78, 7, 8, 70, 53, 136, 56, 115, 129, 183, 226, 82, 147, 253, 62, 59, 170, 188,
            131, 119, 31, 21, 249, 255, 19, 103, 230, 24, 213, 204,
        ];
        let key = hkdf_sha256(b"ABC123");

        assert_eq!(key.to_vec(), known_key);
    }

    #[test]
    fn test_aes_interop() {
        let key = [
            118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106, 229, 83, 134, 189, 40, 189, 210,
            25, 184, 160, 141, 237, 26, 168, 54, 239, 204, 139, 119, 13, 199,
        ];

        let plaintext = b"ABC";

        let known_encrypted: Vec<u8> = vec![
            218, 65, 89, 124, 81, 87, 72, 141, 119, 36, 224, 63, 149, 218, 64, 106, 159, 178, 238,
            212, 36, 223, 93, 107, 19, 211, 62, 75, 195, 46, 177,
        ];

        let decrypted = aes_decrypt(&key, &known_encrypted).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_ecies_ed25519_interop() {
        let peer_sk = SecretKey([
            118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106, 229, 83, 134, 189, 40, 189, 210,
            25, 184, 160, 141, 237, 26, 168, 54, 239, 204, 139, 119, 13, 199,
        ]);

        let plaintext = b"ABC";
        let known_encrypted: Vec<u8> = vec![
            235, 249, 207, 231, 91, 38, 106, 202, 22, 34, 114, 191, 107, 122, 99, 157, 43, 210, 46,
            229, 219, 208, 111, 176, 98, 154, 42, 250, 114, 233, 68, 8, 159, 7, 231, 190, 85, 81,
            56, 122, 152, 186, 151, 124, 246, 147, 163, 153, 29, 85, 248, 238, 194, 15, 180, 98,
            163, 36, 49, 191, 133, 242, 186,
        ];

        let decrypted = decrypt(&peer_sk, &known_encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_public_key_extract() {
        let mut test_rng = rand::rngs::StdRng::from_seed([0u8; 32]);

        let secret = SecretKey::generate(&mut test_rng);
        let public = PublicKey::from_secret(&secret);

        PublicKey::from_bytes(public.as_bytes()).unwrap();

        // Test bad bytes
        assert!(PublicKey::from_bytes(&[0u8; 16]).is_err());
        assert!(SecretKey::from_bytes(&[0u8; 16]).is_err());
    }
}