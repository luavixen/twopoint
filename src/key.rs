use std::ops::Deref;
use std::str::FromStr;

use crate::error::InvalidKeyError;

/// A 128-bit encryption key for securing peer communications.
///
/// Keys can be created from byte arrays, byte slices, or hex strings.
/// All cryptographic operations use AES-128-GCM encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key([u8; 16]);

impl From<[u8; 16]> for Key {
  fn from(array: [u8; 16]) -> Self {
    Self(array)
  }
}

impl TryFrom<&[u8]> for Key {
  type Error = InvalidKeyError;

  fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
    Ok(Self(slice.try_into().map_err(|_| InvalidKeyError::InvalidLength)?))
  }
}

impl FromStr for Key {
  type Err = InvalidKeyError;

  /// Parses a key from a hex string.
  ///
  /// The string must represent exactly 16 bytes (32 hex characters).
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Self::try_from(hex::decode(s)?.as_ref())
  }
}

impl Deref for Key {
  type Target = [u8; 16];

  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl AsRef<[u8; 16]> for Key {
  fn as_ref(&self) -> &[u8; 16] {
    &self.0
  }
}

impl AsRef<[u8]> for Key {
  fn as_ref(&self) -> &[u8] {
    &self.0
  }
}
