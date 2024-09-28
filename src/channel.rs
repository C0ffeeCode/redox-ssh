mod pty;
mod shell;

use std::fs::File;
use std::io::{self, Write};
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::process;
use std::thread::JoinHandle;

pub use pty::PtyConfig;

pub type ChannelId = u32;

#[derive(Debug)]
pub struct Channel {
    id: ChannelId,
    peer_id: ChannelId,
    process: Option<process::Child>,
    pty: Option<(RawFd, PathBuf)>,
    master: Option<File>,
    window_size: u32,
    peer_window_size: u32,
    max_packet_size: u32,
    read_thread: Option<JoinHandle<()>>,
}

#[derive(Debug)]
pub enum ChannelRequest {
    Pty(PtyConfig),
    Shell,
}

impl Channel {
    pub fn new(
        id: ChannelId,
        peer_id: ChannelId,
        peer_window_size: u32,
        max_packet_size: u32,
    ) -> Self {
        Self {
            id,
            peer_id,
            process: None,
            master: None,
            pty: None,
            window_size: peer_window_size,
            peer_window_size,
            max_packet_size,
            read_thread: None,
        }
    }

    pub fn id(&self) -> ChannelId {
        self.id
    }

    pub fn window_size(&self) -> u32 {
        self.window_size
    }

    pub fn max_packet_size(&self) -> u32 {
        self.max_packet_size
    }

    pub fn handle_request(&mut self, request: ChannelRequest) {
        match request {
            ChannelRequest::Pty(ref pty) => self.setup_tty(pty),
            ChannelRequest::Shell => self.setup_shell(),
        }
        debug!("Channel Request: {:?}", request);
    }

    pub fn write_data(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some(ref mut master) = self.master {
            master.write_all(data)?;
            master.flush()
        } else {
            Ok(())
        }
    }
}
