use std::ops::Deref;
use std::str::FromStr;

use crate::error::InvalidKeyError;

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
