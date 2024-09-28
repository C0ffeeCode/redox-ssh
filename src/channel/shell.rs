use std::{
    fs::OpenOptions,
    os::{
        fd::{FromRawFd, IntoRawFd},
        unix::process::CommandExt,
    },
    process::{self, Stdio},
};

use crate::sys;

use super::Channel;

impl Channel {
    pub fn setup_shell(&self) {
        if let Some((_, tty_path)) = self.pty.as_ref() {
            let stdin = OpenOptions::new()
                .read(true)
                .write(true)
                .open(tty_path)
                .unwrap()
                .into_raw_fd();

            let stdout = OpenOptions::new()
                .read(true)
                .write(true)
                .open(tty_path)
                .unwrap()
                .into_raw_fd();

            let stderr = OpenOptions::new()
                .read(true)
                .write(true)
                .open(tty_path)
                .unwrap()
                .into_raw_fd();

            unsafe {
                process::Command::new("login")
                    .stdin(Stdio::from_raw_fd(stdin))
                    .stdout(Stdio::from_raw_fd(stdout))
                    .stderr(Stdio::from_raw_fd(stderr))
                    .pre_exec(sys::before_exec)
            }
            .spawn()
            .unwrap();
        }
    }
}
