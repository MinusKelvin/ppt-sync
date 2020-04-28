use std::net::TcpStream;
use std::process::{ Command, Stdio };
use std::io::prelude::*;

pub struct PptSyncronizer {
    connection: TcpStream,
    first_frame: bool
}

impl PptSyncronizer {
    pub fn new() -> std::io::Result<Self> {
        let socket = TcpStream::connect("127.0.0.1:57236")
            .or_else(|_| Command::new("ppt-sync")
                .stdout(Stdio::piped())
                .spawn()
                .and_then(|child| child.stdout.unwrap().read_exact(&mut [0]))
                .and_then(|_| TcpStream::connect("127.0.0.1:57236"))
            )?;
        socket.set_nodelay(true)?;
        Ok(PptSyncronizer {
            connection: socket,
            first_frame: true
        })
    }

    pub fn next_frame(&mut self) -> bool {
        if !self.first_frame {
            self.connection.write_all(&[0]).ok();
        }
        self.first_frame = false;
        self.connection.read_exact(&mut [0]).is_ok()
    }
}

#[no_mangle]
pub extern "C" fn pptsync_new() -> *mut PptSyncronizer {
    match PptSyncronizer::new() {
        Ok(v) => Box::into_raw(Box::new(v)),
        Err(e) => {
            eprintln!("Failed to set up ppt-sync: {}", e);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn pptsync_wait_for_frame(sync: &mut PptSyncronizer) -> bool {
    sync.next_frame()
}

#[no_mangle]
pub extern "C" fn pptsync_destroy(sync: *mut PptSyncronizer) {
    unsafe { Box::from_raw(sync); }
}