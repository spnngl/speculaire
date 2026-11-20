//! Opening a configured listener, where `[::]` means every address (D161).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use socket2::SockRef;
use tokio::net::{TcpListener, TcpSocket};

/// The backlog `TcpListener::bind` gives (mio 1.2.4 `src/net/tcp/listener.rs:87-94`).
const BACKLOG: u32 = 128;

/// Listens on `address`. `[::]` takes IPv4 too, whatever `net.ipv6.bindv6only` says, and is `0.0.0.0` on a kernel
/// without IPv6, as Go's `net.Listen` does for `:port` (go1.26.1 `src/net/ipsock_posix.go:142-150`).
pub(crate) async fn listen(address: SocketAddr) -> io::Result<TcpListener> {
    if address.ip() == Ipv6Addr::UNSPECIFIED {
        every(TcpSocket::new_v6(), address.port()).await
    } else {
        TcpListener::bind(address).await
    }
}

/// Listens on `port` of every address: with `v6` dual-stack, or on `0.0.0.0` when the kernel gave no IPv6 socket.
async fn every(v6: io::Result<TcpSocket>, port: u16) -> io::Result<TcpListener> {
    let Ok(socket) = v6 else {
        return TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).await;
    };
    SockRef::from(&socket).set_only_v6(false)?;
    socket.set_reuseaddr(true)?;
    socket.bind((Ipv6Addr::UNSPECIFIED, port).into())?;
    socket.listen(BACKLOG)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn every_address_takes_ipv4() {
        let listener = listen((Ipv6Addr::UNSPECIFIED, 0).into()).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (connected, accepted) = tokio::join!(
            tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)),
            listener.accept()
        );
        connected.unwrap();
        accepted.unwrap();
    }

    #[tokio::test]
    async fn without_ipv6_every_address_is_ipv4() {
        let listener = every(Err(io::ErrorKind::Unsupported.into()), 0)
            .await
            .unwrap();
        assert_eq!(listener.local_addr().unwrap().ip(), Ipv4Addr::UNSPECIFIED);
    }

    #[tokio::test]
    async fn one_address_is_bound_as_is() {
        let listener = listen((Ipv4Addr::LOCALHOST, 0).into()).await.unwrap();
        assert_eq!(listener.local_addr().unwrap().ip(), Ipv4Addr::LOCALHOST);
    }
}
