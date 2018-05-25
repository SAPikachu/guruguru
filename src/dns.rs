use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs, Ipv6Addr};
use std::io::{Write, Seek, Cursor, SeekFrom};
use mioco::udp::UdpSocket;
use failure::{ResultExt};
use bitstream_io::{BitWriter, BE};
use trust_dns_proto::op::{Message, MessageType, ResponseCode, Edns, OpCode};
use trust_dns_proto::rr::{RecordType, Record, RData};
use byteorder::{WriteBytesExt, NetworkEndian};
use mioco;

use huffman::{DomainCode, COMPOSITE_CODES, WRITE_TREE};
use socks5::Socks5Target;
use utils::Result;

fn resolve_name(name: &str) -> Result<Ipv6Addr> {
    let parts: Vec<_> = name.split(r".s---t.").collect();
    if parts.len() != 2 && parts.len() != 4 {
        bail!("Invalid name: {}", name);
    }
    fn parse_part(part: &str, port: u16) -> Result<Socks5Target> {
        match part.parse() {
            Ok(x) => Ok(Socks5Target::IP4(SocketAddrV4::new(x, port))),
            Err(_) => {
                if part.starts_with(r"r---e.") {
                    let req_domain = &part[6..];
                    return match mioco::offload(|| (req_domain, port).to_socket_addrs()) {
                        Ok(x) => match x.filter(|x| x.is_ipv4()).next() {
                            Some(addr) => Ok(addr.into()),
                            None => bail!("Unable to resolve {} to IPv4 address", req_domain),
                        },
                        Err(e) => bail!("Unable to resolve {} to IPv4 address: {}", req_domain, e),
                    };
                }
                Ok(Socks5Target::Domain(part.into(), port))
            },
        }
    }
    let target = parse_part(parts[0], 0)?;
    let server = if parts.len() == 2 {
        Socks5Target::IP4(SocketAddrV4::new(0u32.into(), 0))
    } else {
        let port = match parts[2].parse() {
            Ok(x) => x,
            Err(_) => bail!("Invalid port for proxy server: {}", parts[2]),
        };
        parse_part(parts[1], port)?
    };
    let mut octets = [0u8; 16];
    fn write_domain<'a>(writer: &mut BitWriter<'a, BE>, domain: &String) -> Result<()> {
        writer.write_bit(true)?;
        let domain = domain.to_lowercase();
        let mut remaining = &domain[..];
        while !remaining.is_empty() {
            match COMPOSITE_CODES.iter().find(|&x| remaining.starts_with(x)) {
                Some(x) => {
                    writer.write_huffman(&WRITE_TREE, DomainCode::Composite(x))?;
                    remaining = &remaining[x.len()..];
                },
                None => {
                    let ch = remaining.chars().next().unwrap();
                    if ch != '\\' {
                        if !WRITE_TREE.has_symbol(DomainCode::Char(ch)) {
                            bail!("Unencodable character: {}", ch);
                        }
                        writer.write_huffman(&WRITE_TREE, DomainCode::Char(ch))?;
                    }
                    remaining = &remaining[1..];
                },
            };
        }
        writer.write_huffman(&WRITE_TREE, DomainCode::End).is_ok();
        Ok(())
    }
    {
        let mut cursor = Cursor::new(octets.as_mut());
        {
            let mut writer = BitWriter::<BE>::new(&mut cursor);
            writer.write(7, 0xfc >> 1)?;
            match &target {
                Socks5Target::IP4(addr) => {
                    writer.write_bit(false).unwrap();
                    assert!(writer.byte_aligned());
                    writer.write_bytes(&addr.ip().octets()).unwrap();
                },
                Socks5Target::Domain(domain, _) => {
                    write_domain(&mut writer, domain)?;
                }
                _ => bail!("Not implemented"),
            };
            match &server {
                Socks5Target::IP4(_) => {
                    writer.write_bit(false).is_ok();
                },
                Socks5Target::Domain(domain, port) => {
                    write_domain(&mut writer, domain).context("Not enough space to encode domain of proxy server")?;
                    writer.write(16, *port).context("Not enough space to encode port of proxy server")?;
                }
                _ => bail!("Not implemented"),
            };
            writer.byte_align()?;
        }
        if let Socks5Target::IP4(addr) = &server {
            if !addr.ip().is_unspecified() {
                if cursor.position() > 10 {
                    bail!("Not enough space to encode server IP and port");
                }
                cursor.seek(SeekFrom::Start(10)).unwrap();
                cursor.write_all(&addr.ip().octets()).unwrap();
                cursor.write_u16::<NetworkEndian>(addr.port()).unwrap();
            }
        }
    }
    let ip = octets.into();
    debug!("{}: [{}] -> [{}] => {}", name, server, target, ip);
    Ok(ip)
}

fn resolve_dns_request(msg: &mut Message) -> Result<()> {
    msg.set_edns(Edns::default());
    msg.set_message_type(MessageType::Response);
    msg.set_recursion_available(false);
    if msg.op_code() != OpCode::Query {
        msg.set_response_code(ResponseCode::Refused);
        return Ok(());
    }
    if msg.queries().len() != 1 {
        msg.set_response_code(ResponseCode::Refused);
        return Ok(());
    }
    let name = msg.queries()[0].name().clone();
    let resolved_ip = match resolve_name(&name.to_utf8()) {
        Ok(x) => x,
        Err(e) => {
            debug!("Failed to resolve {}: {}", name, e);
            msg.set_response_code(ResponseCode::NXDomain);
            return Ok(());
        },
    };
    msg.set_response_code(ResponseCode::NoError);
    let mut rec = Record::with(name, RecordType::AAAA, 15);
    rec.set_rdata(RData::AAAA(resolved_ip));
    if msg.queries()[0].query_type() == RecordType::AAAA {
        msg.add_answer(rec);
    } else if msg.queries()[0].query_type() == RecordType::A {
        // msg.add_additional(rec);
    }
    Ok(())
}

pub fn serve_dns(addr: SocketAddr) -> Result<mioco::JoinHandle<Result<()>>> {
    let mut socket = UdpSocket::bound(&addr)?;
    info!("Serving DNS on [{}]", addr);
    Ok(mioco::spawn(move || {
        let mut buffer = [0u8; 1500];
        loop {
            let (num_bytes, addr) = socket.recv(&mut buffer).expect("Failed receive DNS request");
            let mut msg = match Message::from_vec(&buffer[..num_bytes]) {
                Ok(x) => x,
                Err(e) => {
                    warn!("Received invalid DNS request from {}: {}", addr, e);
                    continue
                },
            };
            if let Err(e) = resolve_dns_request(&mut msg) {
                msg.set_response_code(ResponseCode::ServFail);
                warn!("Failed to handle DNS request from {}: {}", addr, e);
            }
            if let Err(e) = socket.send(&msg.to_vec().expect("Failed to serialize DNS response"), &addr) {
                warn!("Failed to send DNS response to {}: {}", addr, e);
            }
        }
    }))
}
