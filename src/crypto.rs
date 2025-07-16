use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use aes_gcm::{aead::{AeadCore, AeadInOut, KeyInit}, Aes128Gcm, Key as CryptoKey, Nonce};

use crate::key::Key;
use crate::error::CryptoError;

pub struct Crypto {
  cipher: Aes128Gcm,
  csprng: ChaCha8Rng,
}

impl Crypto {

  /// AES-128-GCM tag size in bytes
  pub const TAG_SIZE: usize = 16;
  /// AES-128-GCM nonce size in bytes
  pub const NONCE_SIZE: usize = 12;

  /// Minimum buffer length in bytes for an encrypted message (tag + nonce)
  pub const MINIMUM_BUFFER_LENGTH: usize = Self::TAG_SIZE + Self::NONCE_SIZE;

  pub fn new(key: Key) -> Self {
    Self {
      cipher: Aes128Gcm::new(&CryptoKey::<Aes128Gcm>::try_from(*key).unwrap()),
      csprng: ChaCha8Rng::from_os_rng(),
    }
  }

  pub fn encrypt(&mut self, buffer: &mut Vec<u8>) -> Result<(), CryptoError> {
    let nonce = Aes128Gcm::generate_nonce_with_rng(&mut self.csprng);
    self.cipher.encrypt_in_place(&nonce, &[], buffer)?;
    buffer.extend_from_slice(nonce.as_slice());
    Ok(())
  }

  pub fn decrypt(&mut self, buffer: &mut Vec<u8>) -> Result<(), CryptoError> {
    let len = buffer.len();
    if len < Self::MINIMUM_BUFFER_LENGTH {
      return Err(CryptoError);
    }
    let nonce = Nonce::try_from(&buffer[len - Self::NONCE_SIZE..]).unwrap();
    buffer.truncate(len - Self::NONCE_SIZE);
    self.cipher.decrypt_in_place(&nonce, &[], buffer)?;
    Ok(())
  }

}

impl Clone for Crypto {
  fn clone(&self) -> Self {
    Self {
      cipher: self.cipher.clone(),
      csprng: ChaCha8Rng::from_os_rng(),
    }
  }
}
