use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Returns an unspecified address with the same IP version as the input.
pub const fn to_unspecified(addr: SocketAddr) -> SocketAddr {
  match addr {
    SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
  }
}

/// Returns `true` if the address is unspecified (0.0.0.0 or ::).
pub const fn is_unspecified(addr: SocketAddr) -> bool {
  match addr {
    SocketAddr::V4(addr) => addr.ip().is_unspecified(),
    SocketAddr::V6(addr) => addr.ip().is_unspecified(),
  }
}

/// Returns `true` if the I/O error indicates a retryable condition.
///
/// This includes timeouts, interruptions, and would-block errors.
///
/// ## Handled Errors
/// - [`std::io::ErrorKind::WouldBlock`]
/// - [`std::io::ErrorKind::TimedOut`]
/// - [`std::io::ErrorKind::Interrupted`]
pub fn can_retry(e: &io::Error) -> bool {
  match e.kind() {
    io::ErrorKind::WouldBlock => true,
    io::ErrorKind::TimedOut => true,
    io::ErrorKind::Interrupted => true,
    _ => false,
  }
}

/// Returns `true` if the I/O error indicates a reconnectable condition.
///
/// This includes all retryable errors plus connection-related failures
/// that may be resolved by reconnecting.
///
/// ## Handled Errors
/// - [`std::io::ErrorKind::WouldBlock`]
/// - [`std::io::ErrorKind::TimedOut`]
/// - [`std::io::ErrorKind::Interrupted`]
/// - [`std::io::ErrorKind::ConnectionReset`]
/// - [`std::io::ErrorKind::ConnectionAborted`]
/// - [`std::io::ErrorKind::ConnectionRefused`]
/// - [`std::io::ErrorKind::NotConnected`]
/// - [`std::io::ErrorKind::NetworkDown`]
/// - [`std::io::ErrorKind::AddrInUse`]
/// - [`std::io::ErrorKind::AddrNotAvailable`]
/// - [`std::io::ErrorKind::HostUnreachable`]
/// - [`std::io::ErrorKind::NetworkUnreachable`]
/// - [`std::io::ErrorKind::BrokenPipe`]
/// - [`std::io::ErrorKind::UnexpectedEof`]
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
