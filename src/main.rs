extern crate env_logger;
#[macro_use] extern crate log;
extern crate mioco;
extern crate libc;
extern crate byteorder;
#[macro_use] extern crate failure;
#[macro_use] extern crate failure_derive;
extern crate bitstream_io;
#[macro_use] extern crate lazy_static;
extern crate trust_dns_proto;
#[macro_use] extern crate structopt;
extern crate privdrop;

use std::net::{SocketAddr, SocketAddrV6, SocketAddrV4};
use std::os::unix::io::{AsRawFd};
use mioco::tcp::{TcpListener};
use libc::{SOL_IP, SOL_SOCKET, SO_REUSEADDR};
use structopt::StructOpt;
use privdrop::PrivDrop;
use failure::ResultExt;

mod huffman;
mod socks5;
mod utils;
mod dns;
mod connection;

use utils::{setsockopt_bool, IP_TRANSPARENT, Result};
use dns::serve_dns;
use connection::handle_connection;
use socks5::Socks5Target;

#[derive(Debug, StructOpt)]
struct Opt {
    /// IP and port of connection handler
    #[structopt(short = "b", default_value = "[::1]:44555")]
    bind: SocketAddrV6,
    /// IP and port of DNS server
    #[structopt(short = "d", long = "bind-dns", default_value = "[::]:53")]
    bind_dns: SocketAddr,
    #[structopt(short = "u", default_value = "nobody")]
    user: String,
    #[structopt(short = "g", default_value = "nogroup")]
    group: String,
    #[structopt(long = "default-server-host", default_value = "socks.rg")]
    default_server_host: String,
    #[structopt(long = "default-server-port", default_value = "1080")]
    default_server_port: u16,
}

fn run() -> Result<()> {
    let opt = Opt::from_args();
    let listener = TcpListener::bind(&opt.bind.into())?;
    let local_addr = listener.local_addr()?;
    setsockopt_bool(listener.as_raw_fd(), SOL_SOCKET, SO_REUSEADDR, true)?;
    setsockopt_bool(listener.as_raw_fd(), SOL_IP, IP_TRANSPARENT, true)?;
    info!("Listening on [{}]", local_addr);
    serve_dns(opt.bind_dns)?;
    PrivDrop::default()
        .user(&opt.user).context(format_err!("Can't find user: {}", opt.user))?
        .group(&opt.group).context(format_err!("Can't find group: {}", opt.group))?
        .apply().context("Failed to drop privilege")?;
    let default_server = match opt.default_server_host.parse() {
        Ok(x) => Socks5Target::IP4(SocketAddrV4::new(x, opt.default_server_port)),
        Err(_) => Socks5Target::Domain(opt.default_server_host.clone(), opt.default_server_port),
    };
    loop {
        let stream = listener.accept()?;
        if let Err(e) = handle_connection(stream, &default_server) {
            warn!("{}", e);
        }
    }
}

fn main() -> Result<()> {
    env_logger::init();
    let mut config = mioco::Config::new();
    config.set_catch_panics(false);
    mioco::Mioco::new_configured(config).start(run).unwrap()
}
