use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, Ipv4Addr};
use std::io::Cursor;
use mioco::tcp::TcpStream;
use failure::{ResultExt};
use bitstream_io::{BitReader, BE};
use mioco;

use huffman::{DomainCode, READ_TREE};
use socks5::{pipe_forever, socks5_connect, Socks5Target};
use utils::Result;

lazy_static! {
    static ref USE_DEFAULT_SERVER: Socks5Target = Socks5Target::IP4(SocketAddrV4::new(Ipv4Addr::from(0), 0));
}

struct DecodeAddr {
    server: Socks5Target,
    target: Socks5Target,
}

fn decode_addr(addr: SocketAddrV6) -> Result<DecodeAddr> {
    type R<'a> = BitReader<'a, BE>;
    let octets = addr.ip().octets();
    fn read_compressed_domain(reader: &mut R, port: Option<u16>) -> Result<Socks5Target> {
        let mut domain = String::new();
        loop {
            let code = match reader.read_huffman(&READ_TREE) {
                Ok(x) => x,
                Err(_) => break,
            };
            match code {
                DomainCode::End => break,
                DomainCode::Char(x) => domain.extend(&[x]),
                DomainCode::Composite(x) => domain += x,
            };
        }
        if domain.is_empty() {
            bail!("Domain is empty");
        }
        let port = if let Some(port) = port {
            port
        } else {
            reader.read::<u16>(16)?
        };
        Ok(Socks5Target::Domain(domain, port))
    }
    fn read_raw_ip(reader: &mut R, port: Option<u16>) -> Result<Socks5Target> {
        let ip = Ipv4Addr::from(reader.read::<u32>(32)?);
        let port = if let Some(x) = port {
            x
        } else {
            reader.read::<u16>(16)?
        };
        Ok(Socks5Target::IP4(SocketAddrV4::new(ip, port)))
    }
    let mut cursor = Cursor::new(&octets);
    let mut reader = R::new(&mut cursor);
    reader.skip(7)?;
    let target = if reader.read_bit()? {
        read_compressed_domain(&mut reader, Some(addr.port())).context("Failed to read target domain")?
    } else {
        read_raw_ip(&mut reader, Some(addr.port())).unwrap()
    };
    let ip_flag = !reader.read_bit().unwrap_or(false);
    let server = if !ip_flag {
        read_compressed_domain(&mut reader, None).context("Failed to read server domain")?
    } else {
        reader.byte_align();
        if reader.skip(56).is_err() {
            // No room for server IP and port, assume default
            USE_DEFAULT_SERVER.clone()
        } else {
            // Last 6 bytes
            read_raw_ip(&mut R::new(&mut Cursor::new(&octets[octets.len() - 6..])), None).unwrap()
        }
    };
    Ok(DecodeAddr {server: server, target: target})
}

pub fn handle_connection(stream: TcpStream, default_server: &Socks5Target) -> Result<()> {
    let log_prefix = format!("[{}] -> [{}]", stream.peer_addr()?, stream.local_addr()?);
    info!("{}", log_prefix);
    stream.set_nodelay(true)?;
    let remote = stream.local_addr()?; // With IP_TRANSPARENT our local address is encoded target address
    let DecodeAddr { mut server, target } = decode_addr(if let SocketAddr::V6(addr) = remote {
        addr
    } else {
        bail!("Unexpected remote address: {}", remote)
    })?;
    if server == *USE_DEFAULT_SERVER {
        server = default_server.clone();
    }
    let transport = socks5_connect(server, target)?;
    let stream_tx = stream.try_clone()?;
    let transport_tx = transport.try_clone()?;
    let handle = mioco::spawn(move || pipe_forever(stream_tx, transport_tx));
    mioco::spawn(move || {
        let result = pipe_forever(transport, stream)
            .and_then(|_| handle.join().map_err(|x| format_err!("{:?}", x)));
        if let Err(e) = result {
            info!("{}: {}", log_prefix, e);
        } else {
            info!("{}: Connection closed", log_prefix);
        }
    });
    Ok(())
}
