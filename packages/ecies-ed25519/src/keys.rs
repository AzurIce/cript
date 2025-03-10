use super::Error;
use base64::Engine;
use core::iter::FromIterator;
use curve25519_dalek::constants;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use hex::{FromHex, ToHex};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// The length of a `SecretKey`, in bytes.
pub const SECRET_KEY_LENGTH: usize = 32;

/// The length of a `PublicKey`, in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// Secret Key
///
/// Neither this secret key (nor it's corresponding PublicKey) should be used for signing
/// or in any other protocol other than ECIES.
#[derive(Debug)]
pub struct SecretKey(pub(crate) [u8; SECRET_KEY_LENGTH]);

/// Zero a secretKey when it's dropped
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ToHex for SecretKey {
    fn encode_hex<T: FromIterator<char>>(&self) -> T {
        self.0.encode_hex()
    }

    fn encode_hex_upper<T: FromIterator<char>>(&self) -> T {
        self.0.encode_hex_upper()
    }
}

impl FromHex for SecretKey {
    type Error = Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Error> {
        let mut bytes = Vec::<u8>::from_hex(hex).map_err(|_| Error::InvalidSecretKeyBytes)?;
        let sk = Self::from_bytes(&bytes)?;
        bytes.zeroize();
        Ok(sk)
    }
}

impl SecretKey {
    /// Convert this secret key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0
    }

    /// View this secret key as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_LENGTH] {
        &self.0
    }

    /// Construct a `SecretKey` from a slice of bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use ecies_ed25519::SecretKey;
    /// use ecies_ed25519::SECRET_KEY_LENGTH;
    /// use ecies_ed25519::Error;
    ///
    /// # fn doctest() -> Result<SecretKey, Error> {
    /// let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = [
    ///    157, 097, 177, 157, 239, 253, 090, 096,
    ///    186, 132, 074, 244, 146, 236, 044, 196,
    ///    068, 073, 197, 105, 123, 050, 105, 025,
    ///    112, 059, 172, 003, 028, 174, 127, 096, ];
    ///
    /// let secret_key: SecretKey = SecretKey::from_bytes(&secret_key_bytes)?;
    /// #
    /// # Ok(secret_key)
    /// # }
    /// #
    /// # fn main() {
    /// #     let result = doctest();
    /// #     assert!(result.is_ok());
    /// # }
    /// ```
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, Error> {
        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(Error::InvalidSecretKeyBytes);
        }
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);

        Ok(SecretKey(bits))
    }

    /// Generate a `SecretKey` from a `csprng`.
    pub fn generate<T>(csprng: &mut T) -> SecretKey
    where
        T: CryptoRng + RngCore,
    {
        let mut sk: SecretKey = SecretKey([0u8; 32]);
        csprng.fill_bytes(&mut sk.0);
        sk
    }
}

/// Public Key
///
/// Neither this public key (nor it's corresponding  PrivateKey) should be used for signing
/// or in any other protocol other than ECIES.
#[derive(Copy, Clone, Default, Eq, PartialEq, Debug)]
pub struct PublicKey(pub(crate) CompressedEdwardsY);

impl PublicKey {
    /// Convert this public key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    /// View this public key as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        self.0.as_bytes()
    }

    /// Construct a `PublicKey` from a slice of bytes.
    ///
    /// Will return None if the bytes are invalid
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let point =
            CompressedEdwardsY::from_slice(bytes).map_err(|_| Error::InvalidPublicKeyBytes)?;

        if point.decompress().is_none() {
            return Err(Error::InvalidPublicKeyBytes);
        }
        Ok(PublicKey(point))
    }

    /// Derive a public key from a private key
    pub fn from_secret(sk: &SecretKey) -> Self {
        #[allow(deprecated)]
        let point = &Scalar::from_bits(sk.to_bytes()) * constants::ED25519_BASEPOINT_TABLE;
        PublicKey(point.compress())
    }

    /// Get the Edwards Point for this public key
    pub fn to_point(&self) -> EdwardsPoint {
        self.0
            .decompress()
            .expect("ecies-ed25519: unexpected error decompressing public key")
    }
}

// Note: ToHex is implemented implicitly through impl AsRef<[u8]> for PublicKey
impl FromHex for PublicKey {
    type Error = Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Error> {
        let mut bytes = Vec::<u8>::from_hex(hex).map_err(|_| Error::InvalidPublicKeyBytes)?;
        let sk = Self::from_bytes(&bytes)?;
        bytes.zeroize();
        Ok(sk)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Error types
#[derive(Debug, Error)]
pub enum Base64ToKeyError {
    /// Encryption failed
    #[error("ecies-rd25519: invalid base64 string")]
    InvalidBase64String,

    /// Invalid key bytes
    #[error("ecies-rd25519: invalid public key bytes")]
    InvalidKeyBytes,
}

#[cfg(feature = "base64")]
impl TryFrom<String> for PublicKey {
    type Error = Base64ToKeyError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = base64::prelude::BASE64_STANDARD
            .decode(value)
            .map_err(|_| Base64ToKeyError::InvalidBase64String)?;
        PublicKey::from_bytes(&bytes).map_err(|_| Base64ToKeyError::InvalidKeyBytes)
    }
}

#[cfg(feature = "base64")]
impl Into<String> for PublicKey {
    fn into(self) -> String {
        base64::prelude::BASE64_STANDARD.encode(self.to_bytes())
    }
}

#[cfg(feature = "base64")]
impl TryFrom<String> for SecretKey {
    type Error = Base64ToKeyError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = base64::prelude::BASE64_STANDARD
            .decode(value)
            .map_err(|_| Base64ToKeyError::InvalidBase64String)?;
        SecretKey::from_bytes(&bytes).map_err(|_| Base64ToKeyError::InvalidKeyBytes)
    }
}

#[cfg(feature = "base64")]
impl Into<String> for SecretKey {
    fn into(self) -> String {
        base64::prelude::BASE64_STANDARD.encode(self.to_bytes())
    }
}
