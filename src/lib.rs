//! Encrypted UDP messaging between two endpoints.
//!
//! This crate provides a simple interface for establishing encrypted UDP connections
//! between peers using AES-128-GCM encryption. Each peer can connect to one remote
//! endpoint at a time and exchange binary messages securely.
//!
//! # Encryption Overhead
//!
//! All messages have a 28-byte overhead (16-byte authentication tag + 12-byte nonce)
//! added during encryption. Ensure receive buffers are large enough to accommodate
//! this overhead plus your message data.
//!
//! # Security
//!
//! The encryption implementation was created without formal cryptography experience,
//! though I believe it is generally sound. I use AES-128-GCM with ChaCha8 CSPRNG
//! generated nonces where reuse is theoretically possible after ~2^96 nonces.
//! You probably shouldn'tput this into production.
//!
//! # Core Types
//!
//! - [`Peer`] - A UDP endpoint that can send and receive encrypted messages
//! - [`Key`] - A 128-bit encryption key for securing communications
//!
//! # Errors
//!
//! - [`CryptoError`] - Encryption/decryption failures
//! - [`InvalidKeyError`] - Invalid key format or length

mod util;
mod error;
mod key;
mod crypto;
mod peer;

pub use util::*;
pub use error::{CryptoError, InvalidKeyError};
pub use key::Key;
pub use peer::Peer;

#[cfg(test)]
mod tests {
  use super::*;
  use std::time::Duration;

  fn create_test_key() -> Key {
    // use a fixed key for deterministic testing
    "5adf5e4a8a779d4cd7985a881b270bcf".parse().unwrap()
  }

  #[test]
  fn test_peer_connect_and_disconnect() {
    let key = create_test_key();

    // create two peers on different loopback ports
    // 0.0.0.0:0 will start us off as unconnected
    let peer1 = Peer::setup("127.0.0.1:0", "0.0.0.0:0", key).expect("failed to create peer1");
    let peer2 = Peer::setup("127.0.0.1:0", "0.0.0.0:0", key).expect("failed to create peer2");

    let peer2_addr = peer2.local_addr();

    // connect peer1 to peer2
    peer1.connect(peer2_addr).expect("failed to connect");

    // verify connection
    assert_eq!(peer1.remote_addr(), peer2_addr, "peer1 should be connected to peer2");

    // disconnect
    peer1.disconnect().expect("failed to disconnect");

    // verify disconnection
    assert!(peer1.remote_addr_optional().is_none(), "peer1 should be disconnected");
  }

  #[test]
  fn test_peer_communication() {
    let key = create_test_key();

    // create two peers on different loopback ports
    let peer1 = Peer::setup("127.0.0.1:0", "0.0.0.0:0", key).expect("failed to create peer1");
    let peer2 = Peer::setup("127.0.0.1:0", "0.0.0.0:0", key).expect("failed to create peer2");

    // we should be assigned a random port
    assert_ne!(peer1.local_addr().port(), 0, "peer1 should be assigned a random port");
    assert_ne!(peer2.local_addr().port(), 0, "peer2 should be assigned a random port");

    // we should be unconnected at this point
    assert!(peer1.remote_addr_optional().is_none(), "peer1 should be unconnected");
    assert!(peer2.remote_addr_optional().is_none(), "peer2 should be unconnected");

    // get their actual addresses
    let peer1_addr = peer1.local_addr();
    let peer2_addr = peer2.local_addr();

    // connect peers to each other
    peer1.connect(peer2_addr).expect("failed to connect peer1 to peer2");
    peer2.connect(peer1_addr).expect("failed to connect peer2 to peer1");

    // we should be connected at this point
    assert!(peer1.remote_addr_optional().is_some(), "peer1 should be connected");
    assert!(peer2.remote_addr_optional().is_some(), "peer2 should be connected");

    // clone peers so we can have mutable references
    let mut peer1_sender = peer1.clone();
    let mut peer1_receiver = peer1;
    let mut peer2_sender = peer2.clone();
    let mut peer2_receiver = peer2;

    // set read timeouts to avoid hanging in tests
    peer1_receiver.set_read_timeout(Some(Duration::from_secs(1))).expect("failed to set timeout");
    peer2_receiver.set_read_timeout(Some(Duration::from_secs(1))).expect("failed to set timeout");

    // test data to send
    let message1 = b"waves my paw haiii !! i'm peer 1 !! :D";
    let message2 = b"omg hello !! i'm peer 2 !! :3c";

    // send from peer1 to peer2
    let mut send_buffer1 = message1.to_vec();
    peer1_sender.send(&mut send_buffer1).expect("failed to send from peer1");

    // receive at peer2
    let mut recv_buffer2 = vec![0u8; 1024];
    peer2_receiver.recv(&mut recv_buffer2).expect("failed to receive at peer2");

    // verify the message was received correctly
    assert_eq!(&recv_buffer2, message1, "message from peer1 to peer2 was corrupted");

    // send from peer2 to peer1
    let mut send_buffer2 = message2.to_vec();
    peer2_sender.send(&mut send_buffer2).expect("failed to send from peer2");

    // receive at peer1
    let mut recv_buffer1 = vec![0u8; 1024];
    peer1_receiver.recv(&mut recv_buffer1).expect("failed to receive at peer1");

    // verify the message was received correctly
    assert_eq!(&recv_buffer1, message2, "message from peer2 to peer1 was corrupted");
  }

  #[test]
  fn test_server_client_connection_switching() {
    let key = create_test_key();

    // create three peers - one server and two clients
    let server = Peer::setup("127.0.0.1:0", "0.0.0.0:0", key).expect("failed to create server");
    let client1 = Peer::setup("127.0.0.1:0", "0.0.0.0:0", key).expect("failed to create client1");
    let client2 = Peer::setup("127.0.0.1:0", "0.0.0.0:0", key).expect("failed to create client2");

    // get addresses
    let server_addr = server.local_addr();
    let client1_addr = client1.local_addr();
    let client2_addr = client2.local_addr();

    // create mutable clones for sending/receiving
    let mut server_sender = server.clone();
    let mut server_receiver = server.clone();
    let mut client1_sender = client1.clone();
    let mut client1_receiver = client1.clone();
    let mut client2_sender = client2.clone();
    let mut client2_receiver = client2.clone();

    // set timeouts to avoid hanging
    server_receiver.set_read_timeout(Some(Duration::from_millis(500))).expect("failed to set timeout");
    client1_receiver.set_read_timeout(Some(Duration::from_millis(500))).expect("failed to set timeout");
    client2_receiver.set_read_timeout(Some(Duration::from_millis(500))).expect("failed to set timeout");

    // phase 1 - server connects to client1
    server.connect(client1_addr).expect("failed to connect server to client1");
    client1.connect(server_addr).expect("failed to connect client1 to server");

    // verify server is connected to client1
    assert_eq!(server.remote_addr(), client1_addr, "server should be connected to client1");
    assert_eq!(client1.remote_addr(), server_addr, "client1 should be connected to server");

    // test communication between server and client1
    let server_to_client1_msg = b"hello client1 from server !! :3";
    let client1_to_server_msg = b"hello server from client1 !! :3";

    // server sends to client1
    let mut send_buffer = server_to_client1_msg.to_vec();
    server_sender.send(&mut send_buffer).expect("failed to send from server to client1");

    let mut recv_buffer = vec![0u8; 1024];
    client1_receiver.recv(&mut recv_buffer).expect("failed to receive at client1");
    assert_eq!(&recv_buffer, server_to_client1_msg);

    // client1 sends to server
    let mut send_buffer = client1_to_server_msg.to_vec();
    client1_sender.send(&mut send_buffer).expect("failed to send from client1 to server");

    let mut recv_buffer = vec![0u8; 1024];
    server_receiver.recv(&mut recv_buffer).expect("failed to receive at server");
    assert_eq!(&recv_buffer, client1_to_server_msg);

    // phase 2 - server disconnects from client1 and connects to client2
    server.disconnect().expect("failed to disconnect server from client1");

    // verify server is disconnected
    assert!(server.remote_addr_optional().is_none());

    // connect server to client2
    server.connect(client2_addr).expect("failed to connect server to client2");
    client2.connect(server_addr).expect("failed to connect client2 to server");

    // verify new connection
    assert_eq!(server.remote_addr(), client2_addr, "server should be connected to client2");
    assert_eq!(client2.remote_addr(), server_addr, "client2 should be connected to server");

    // test communication between server and client2
    let server_to_client2_msg = b"hello client2 from server !! :D";
    let client2_to_server_msg = b"hello server from client2 !! :D";

    // server sends to client2
    let mut send_buffer = server_to_client2_msg.to_vec();
    server_sender.send(&mut send_buffer).expect("failed to send from server to client2");

    let mut recv_buffer = vec![0u8; 1024];
    client2_receiver.recv(&mut recv_buffer).expect("failed to receive at client2");
    assert_eq!(&recv_buffer, server_to_client2_msg);

    // client2 sends to server
    let mut send_buffer = client2_to_server_msg.to_vec();
    client2_sender.send(&mut send_buffer).expect("failed to send from client2 to server");

    let mut recv_buffer = vec![0u8; 1024];
    server_receiver.recv(&mut recv_buffer).expect("failed to receive at server from client2");
    assert_eq!(&recv_buffer, client2_to_server_msg);

    // phase 4 - verify client1 can no longer communicate with server
    // client1 tries to send to server (this should technically send, but server won't receive it)
    let mut send_buffer = b"this should not reach server".to_vec();
    client1_sender.send(&mut send_buffer)
      .expect("failed to send from client1 to server after disconnect, should still send, UDP is connectionless");

    // server should not receive anything from client1 (should timeout)
    let mut recv_buffer = vec![0u8; 1024];
    let result = server_receiver.recv(&mut recv_buffer);

    // this should timeout since server is no longer listening to client1
    assert!(result.is_err(), "server should not receive messages from disconnected client1");

    // verify the error is a timeout
    assert!(can_retry(&result.unwrap_err()), "error was not a timeout");
  }
}
