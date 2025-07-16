use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct CryptoError;

impl From<aes_gcm::Error> for CryptoError {
  fn from(_: aes_gcm::Error) -> Self {
    Self
  }
}

impl From<CryptoError> for io::Error {
  fn from(_: CryptoError) -> Self {
      io::Error::new(io::ErrorKind::Other, CryptoError)
  }
}

impl std::fmt::Display for CryptoError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "opaque crypto error")
  }
}

impl std::error::Error for CryptoError {}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InvalidKeyError {
  InvalidLength,
  InvalidHex(hex::FromHexError),
}

impl From<hex::FromHexError> for InvalidKeyError {
  fn from(e: hex::FromHexError) -> Self {
    Self::InvalidHex(e)
  }
}

impl From<InvalidKeyError> for io::Error {
  fn from(e: InvalidKeyError) -> Self {
      io::Error::new(io::ErrorKind::InvalidInput, e)
  }
}

impl std::fmt::Display for InvalidKeyError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::InvalidLength => write!(f, "invalid key length"),
      Self::InvalidHex(e) => write!(f, "invalid key hex: {e}"),
    }
  }
}

impl std::error::Error for InvalidKeyError {}
