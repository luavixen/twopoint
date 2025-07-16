use std::io;
use std::net::{ToSocketAddrs, SocketAddr, UdpSocket};
use std::time::Duration;

use crate::util::*;
use crate::key::Key;
use crate::crypto::Crypto;

pub struct Peer {
  socket: UdpSocket,
  crypto: Crypto,
}

impl Peer {

  pub fn new(socket: UdpSocket, key: Key) -> Self {
    Self { socket, crypto: Crypto::new(key) }
  }

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

  pub fn socket(&self) -> &UdpSocket {
    &self.socket
  }

  pub fn local_addr(&self) -> SocketAddr {
    self.socket.local_addr().expect("couldn't get local address")
  }

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

  pub fn remote_addr(&self) -> SocketAddr {
    self.remote_addr_optional()
      .unwrap_or_else(|| to_unspecified(self.local_addr()))
  }

  pub fn connect<A: ToSocketAddrs>(&self, addr: A) -> io::Result<()> {
    self.socket.connect(addr)
  }

  pub fn disconnect(&self) -> io::Result<()> {
    self.socket.connect(to_unspecified(self.local_addr()))
  }

  pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
    self.socket.set_read_timeout(timeout)
  }

  pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
    self.socket.set_write_timeout(timeout)
  }

  pub fn send(&mut self, buffer: &mut Vec<u8>) -> io::Result<()> {
    self.crypto.encrypt(buffer)?;
    self.socket.send(buffer)?;
    Ok(())
  }

  pub fn recv(&mut self, buffer: &mut Vec<u8>) -> io::Result<()> {
    let len = self.socket.recv(buffer)?;
    buffer.truncate(len);
    self.crypto.decrypt(buffer)?;
    Ok(())
  }

}

impl Clone for Peer {
  fn clone(&self) -> Self {
    let socket = self.socket.try_clone().expect("couldn't clone socket");
    let crypto = self.crypto.clone();
    Self { socket, crypto }
  }
}

