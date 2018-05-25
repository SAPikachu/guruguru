use std;
use std::mem::size_of_val;
use std::io::Error as IoError;
use std::os::unix::io::RawFd;
use failure::Error;
use libc::{c_int, c_void, socklen_t, setsockopt};


pub type Result<T> = std::result::Result<T, Error>;

pub const IP_TRANSPARENT: c_int = 19;

pub fn setsockopt_bool(fd: RawFd, level: c_int, name: c_int, val: bool) -> Result<()> {
    let flag: c_int = if val { 1 } else { 0 };
    match unsafe {
        setsockopt(fd as c_int, level, name, &flag as *const _ as *const c_void, size_of_val(&flag) as socklen_t)
    } {
        0 => Ok(()),
        _ => Err(IoError::last_os_error().into()),
    }
}
