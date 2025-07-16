use std::io;
use std::net::{ToSocketAddrs, SocketAddr, UdpSocket};
use std::time::Duration;

use crate::util::*;
use crate::key::Key;
use crate::crypto::Crypto;

/// A UDP peer that can send and receive encrypted messages.
///
/// Each peer maintains a UDP socket and can connect to at most one remote endpoint
/// at a time. All messages are encrypted using AES-128-GCM before transmission.
pub struct Peer {
  socket: UdpSocket,
  crypto: Crypto,
}

impl Peer {

  /// Creates a new peer with the given socket and encryption key.
  pub fn new(socket: UdpSocket, key: Key) -> Self {
    Self { socket, crypto: Crypto::new(key) }
  }

  /// Creates a new peer, binds to `bind_addr`, and connects to `connect_addr`.
  ///
  /// This is a convenience method that combines socket creation, binding, and connection.
  /// Use `"0.0.0.0:0"` or `"[::]:0"` for `connect_addr` to create an unconnected peer.
  pub fn setup<A1, A2>(bind_addr: A1, connect_addr: A2, key: Key) -> io::Result<Self>
  where
    A1: ToSocketAddrs,
    A2: ToSocketAddrs,
  {
    let socket = UdpSocket::bind(bind_addr)?;
    let peer = Self::new(socket, key);
    peer.connect(connect_addr)?;
    Ok(peer)
  }

  /// Returns a reference to the underlying UDP socket.
  pub fn socket(&self) -> &UdpSocket {
    &self.socket
  }

  /// Returns the local socket address.
  pub fn local_addr(&self) -> SocketAddr {
    self.socket.local_addr().expect("couldn't get local address")
  }

  /// Returns the remote socket address if connected, otherwise `None`.
  pub fn remote_addr_optional(&self) -> Option<SocketAddr> {
    match self.socket.peer_addr() {
      Ok(addr) => {
        if !is_unspecified(addr) {
          Some(addr)
        } else {
          None
        }
      }
      Err(_) => None
    }
  }

  /// Returns the remote socket address, or an unspecified address if not connected.
  pub fn remote_addr(&self) -> SocketAddr {
    self.remote_addr_optional()
      .unwrap_or_else(|| to_unspecified(self.local_addr()))
  }

  /// Connects to the specified remote address.
  ///
  /// This establishes the peer's target for communication. Both `send()` and
  /// `recv()` operations require the peer to be connected to function.
  pub fn connect<A: ToSocketAddrs>(&self, addr: A) -> io::Result<()> {
    self.socket.connect(addr)
  }

  /// Disconnects from the current remote address.
  ///
  /// After disconnecting, both `send()` and `recv()` calls will fail until
  /// the peer is reconnected to a remote address.
  pub fn disconnect(&self) -> io::Result<()> {
    self.socket.connect(to_unspecified(self.local_addr()))
  }

  /// Sets the read timeout for receive operations.
  pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
    self.socket.set_read_timeout(timeout)
  }

  /// Sets the write timeout for send operations.
  pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
    self.socket.set_write_timeout(timeout)
  }

  /// Encrypts and sends the contents of the buffer to the connected peer.
  ///
  /// The buffer is modified in-place during encryption - a 28-byte overhead
  /// (16-byte authentication tag + 12-byte nonce) is appended to the end.
  ///
  /// Returns an error if not connected to a peer, if encryption fails, or on network errors.
  pub fn send(&mut self, buffer: &mut Vec<u8>) -> io::Result<()> {
    self.crypto.encrypt(buffer)?;
    self.socket.send(buffer)?;
    Ok(())
  }

  /// Receives and decrypts a message into the buffer.
  ///
  /// The buffer must be large enough to hold the entire encrypted message.
  /// After receiving, the buffer is truncated to the message length, then
  /// the 28-byte crypto overhead is removed from the end during decryption.
  /// The buffer is resized to match the original message length.
  ///
  /// Returns an error if not connected to a peer, if decryption fails, or on network errors.
  pub fn recv(&mut self, buffer: &mut Vec<u8>) -> io::Result<()> {
    let len = self.socket.recv(buffer)?;
    buffer.truncate(len);
    self.crypto.decrypt(buffer)?;
    Ok(())
  }

}

impl Clone for Peer {
  /// Clones the peer, including its socket and encryption state.
  ///
  /// This allows for multiple mutable references to the same peer.
  /// The socket is cloned using `try_clone()`, which may fail in
  /// extreme cases if the underlying system resources are not available.
  ///
  /// Returns a new peer with the same configuration.
  fn clone(&self) -> Self {
    let socket = self.socket.try_clone().expect("couldn't clone socket");
    let crypto = self.crypto.clone();
    Self { socket, crypto }
  }
}

