use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const fn to_unspecified(addr: SocketAddr) -> SocketAddr {
  match addr {
    SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
  }
}

pub const fn is_unspecified(addr: SocketAddr) -> bool {
  match addr {
    SocketAddr::V4(addr) => addr.ip().is_unspecified(),
    SocketAddr::V6(addr) => addr.ip().is_unspecified(),
  }
}

pub fn can_retry(e: &io::Error) -> bool {
  match e.kind() {
    io::ErrorKind::WouldBlock => true,
    io::ErrorKind::TimedOut => true,
    io::ErrorKind::Interrupted => true,
    _ => false,
  }
}

pub fn can_reconnect(e: &io::Error) -> bool {
  if can_retry(e) {
    return true;
  }
  match e.kind() {
    io::ErrorKind::ConnectionReset => true,
    io::ErrorKind::ConnectionAborted => true,
    io::ErrorKind::ConnectionRefused => true,
    io::ErrorKind::NotConnected => true,
    io::ErrorKind::NetworkDown => true,
    io::ErrorKind::AddrInUse => true,
    io::ErrorKind::AddrNotAvailable => true,
    io::ErrorKind::HostUnreachable => true,
    io::ErrorKind::NetworkUnreachable => true,
    io::ErrorKind::BrokenPipe => true,
    io::ErrorKind::UnexpectedEof => true,
    _ => false,
  }
}
