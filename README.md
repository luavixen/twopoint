# twopoint
Encrypted UDP messaging between two endpoints using AES-128-GCM.

## Usage

```rust
use twopoint::{Peer, Key};

// create encryption key from hex string
// use $ openssl rand -hex 16
let key: Key = "371fa32e478d65c7d91b7cc431d813af".parse()?;

// create two peers
let peer1 = Peer::setup("127.0.0.1:0", "0.0.0.0:0", key)?;
let peer2 = Peer::setup("127.0.0.1:0", "0.0.0.0:0", key)?;

// connect peers to each other
peer1.connect(peer2.local_addr())?;
peer2.connect(peer1.local_addr())?;

// send encrypted message
let mut message = b"hello world".to_vec();
peer1.send(&mut message)?;

// receive and decrypt message (buffer must be large enough)
let mut buffer = vec![0u8; 1024];
peer2.recv(&mut buffer)?;
```

## Security

The encryption implementation was created without formal cryptography experience, though I believe it is generally sound.
I use AES-128-GCM with ChaCha8 CSPRNG generated nonces where reuse is theoretically possible after ~2^96 nonces.
You probably shouldn't put this into production.


## Authors

Made with ❤ by Lua ([foxgirl.dev](https://foxgirl.dev/))

## License

This crate is licensed under the [MIT License](LICENSE).
