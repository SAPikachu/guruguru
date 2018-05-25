use std;
use std::net::{Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::io::{Read, Write};
use std::fmt::Display;
use mioco::tcp::TcpStream;
use byteorder::{ReadBytesExt, WriteBytesExt, NetworkEndian};

use Result;

#[derive(Fail, Debug)]
pub enum SocksError {
    #[fail(display = "Can't resolve address of server")]
    FailedToResolve,
    #[fail(display = "Unexpected version byte")]
    UnexpectedVersion,
    #[fail(display = "Unexpected address type")]
    UnexpectedAddressType,
    #[fail(display = "Authentication is not supported")]
    AuthenticationNotSupported,
    #[fail(display = "Socks server returned error {}", _0)]
    ServerError(u8),
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Socks5Target {
    IP4(SocketAddrV4),
    IP6(SocketAddrV6),
    Domain(String, u16),
}
impl From<SocketAddr> for Socks5Target {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(x) => Socks5Target::IP4(x),
            SocketAddr::V6(x) => Socks5Target::IP6(x),
        }
    }
}
impl ToSocketAddrs for Socks5Target {
    type Iter = std::vec::IntoIter<SocketAddr>;
    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        match *self {
            Socks5Target::IP4(ref x) => Ok(vec!((*x).into()).into_iter()),
            Socks5Target::IP6(ref x) => Ok(vec!((*x).into()).into_iter()),
            Socks5Target::Domain(ref domain, ref port) => (domain.as_str(), *port).to_socket_addrs(),
        }
    }
}
impl Display for Socks5Target {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Socks5Target::IP4(ref x) => x.fmt(f),
            Socks5Target::IP6(ref x) => x.fmt(f),
            Socks5Target::Domain(ref domain, ref port) => write!(f, "{}:{}", domain, port),
        }
    }
}

pub fn socks5_connect<T: ToSocketAddrs + Display>(server: T, target: Socks5Target) -> Result<TcpStream> {
    info!("socks5_connect: [{}] -> {}", server, target);
    let mut stream = TcpStream::connect(&server.to_socket_addrs()?.next().ok_or(SocksError::FailedToResolve)?)?;
    /*
    Handshake:
    +----+----------+----------+
    |VER | NMETHODS | METHODS  |
    +----+----------+----------+
    | 1  |    1     | 1 to 255 |
    +----+----------+----------+
    X'00' NO AUTHENTICATION REQUIRED
    */
    stream.write_all(&[5, 1, 0])?;
    /*
    The SOCKS request is formed as follows:

        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

     Where:

          o  VER    protocol version: X'05'
          o  CMD
             o  CONNECT X'01'
             o  BIND X'02'
             o  UDP ASSOCIATE X'03'
          o  RSV    RESERVED
          o  ATYP   address type of following address
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
          o  DST.ADDR       desired destination address
          o  DST.PORT desired destination port in network octet
             order
    */
    stream.write_all(&[5, 1, 0])?;
    match &target {
        &Socks5Target::IP4(x) => {
            stream.write_u8(1)?;
            stream.write_all(&x.ip().octets())?;
            stream.write_u16::<NetworkEndian>(x.port())?;
        },
        &Socks5Target::IP6(x) => {
            stream.write_u8(4)?;
            stream.write_all(&x.ip().octets())?;
            stream.write_u16::<NetworkEndian>(x.port())?;
        },
        &Socks5Target::Domain(ref domain, port) => {
            stream.write_u8(3)?;
            stream.write_u8(domain.len() as u8)?;
            stream.write_all(domain.as_bytes())?;
            stream.write_u16::<NetworkEndian>(port)?;
        },
    };
    stream.set_nodelay(true)?;
    if stream.read_u8()? != 5 {
        return Err(SocksError::UnexpectedVersion)?;
    }
    if stream.read_u8()? != 0 {
        return Err(SocksError::AuthenticationNotSupported)?;
    }
    if stream.read_u8()? != 5 {
        return Err(SocksError::UnexpectedVersion)?;
    }
    let code = stream.read_u8()?;
    if code != 0 {
        return Err(SocksError::ServerError(code))?;
    }
    stream.read_u8()?; // RSV
    let mut dummy = [0u8; 260];
    // Strip bind addr
    match stream.read_u8()? {
        1 => stream.read_exact(&mut dummy[..6])?,
        4 => stream.read_exact(&mut dummy[..18])?,
        3 => {
            let len = stream.read_u8()? as usize;
            stream.read_exact(&mut dummy[..(len + 2)])?
        },
        _ => return Err(SocksError::UnexpectedAddressType)?,
    };
    debug!("socks5_connect: [{}] -> {} - Connection established", server, target);
    Ok(stream)
}

pub fn pipe_forever(mut rx: TcpStream, mut tx: TcpStream) -> Result<()> {
    let mut buffer = [0u8; 16384];
    let mut ret = Ok(());
    loop {
        match rx.read(&mut buffer) {
            Ok(0) => break,
            Ok(num_bytes) => {
                if let Err(e) = tx.write_all(&buffer[..num_bytes]) {
                    ret = Err(e.into());
                    break;
                }
            },
            Err(e) => {
                ret = Err(e.into());
                break;
            }
        };
    }
    tx.shutdown(Shutdown::Write).is_ok();
    rx.shutdown(Shutdown::Read).is_ok();
    ret
}
