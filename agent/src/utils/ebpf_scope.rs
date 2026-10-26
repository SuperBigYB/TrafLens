/*
 * Copyright (c) 2026 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Arc, OnceLock};

// Native tracer stop is asynchronous. Retain the namespace until process exit,
// including if all Rust collector/Trident handles are dropped first.
static PROCESS_SCOPE: OnceLock<Arc<SocketTracerNetnsScope>> = OnceLock::new();

pub(crate) fn prepare_socket_tracer_scope(config: &mut crate::config::Config) -> io::Result<()> {
    config.ebpf_socket_netns_inode = None;
    let Some(path) = config.ebpf_socket_netns_scope.as_ref() else {
        return Ok(());
    };
    #[cfg(not(feature = "libtrace"))]
    {
        let _ = path;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "socket netns scope requires a Linux libtrace build",
        ));
    }
    #[cfg(feature = "libtrace")]
    {
        let scope = Arc::new(SocketTracerNetnsScope::open(path)?);
        let inode = scope.inode();
        SocketTracerNetnsScope::pin_for_process(scope)?;
        config.ebpf_socket_netns_inode = Some(inode);
        Ok(())
    }
}

/// Pins a network namespace without entering it. Socket-tracer scope is immutable
/// for the process; keep this guard alive until its tracing threads have exited.
#[derive(Debug)]
pub(crate) struct SocketTracerNetnsScope {
    _namespace: File,
    inode: u64,
}

impl SocketTracerNetnsScope {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "network namespace path must be absolute",
            ));
        }
        // Nonblocking open also rejects an accidental FIFO without hanging
        // startup. Follow namespace symlinks such as /proc/<pid>/ns/net.
        let namespace = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        // SAFETY: ioctl takes an owned valid FD and this request has no pointer
        // argument. An unsupported ioctl or non-network namespace is rejected.
        let ns_type = unsafe { libc::ioctl(namespace.as_raw_fd(), libc::NS_GET_NSTYPE) };
        if ns_type < 0 {
            return Err(io::Error::last_os_error());
        }
        if ns_type != libc::CLONE_NEWNET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "scope path is not a network namespace",
            ));
        }
        // fstat the validated FD, not the potentially replaced bootstrap path.
        let inode = validate_inode(namespace.metadata()?.ino())?;
        Ok(Self {
            _namespace: namespace,
            inode,
        })
    }

    pub(crate) fn inode(&self) -> u64 {
        self.inode
    }

    pub(crate) fn pin_for_process(scope: Arc<Self>) -> io::Result<()> {
        pin_once(&PROCESS_SCOPE, scope)
    }
}

fn pin_once(
    slot: &OnceLock<Arc<SocketTracerNetnsScope>>,
    scope: Arc<SocketTracerNetnsScope>,
) -> io::Result<()> {
    slot.set(scope).map_err(|_| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "socket network namespace scope is already pinned; restart the process to change it",
        )
    })
}

fn validate_inode(inode: u64) -> io::Result<u64> {
    if inode == 0 || inode > u32::MAX as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "network namespace inode must be a nonzero u32",
        ));
    }
    Ok(inode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_valid_netns_is_pinned_and_close_on_exec() {
        let scope = SocketTracerNetnsScope::open(Path::new("/proc/self/ns/net")).unwrap();
        assert_eq!(
            scope.inode(),
            std::fs::metadata("/proc/self/ns/net").unwrap().ino()
        );
        assert!(scope.inode() > 0 && scope.inode() <= u32::MAX as u64);
        let fd = scope._namespace.as_raw_fd();
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        // Pinning holds an open nsfs FD, not merely a sampled path/inode.
        assert_eq!(
            unsafe { libc::ioctl(fd, libc::NS_GET_NSTYPE) },
            libc::CLONE_NEWNET
        );
    }

    #[test]
    fn scope_rejects_regular_file_and_wrong_namespace_type() {
        let file = tempfile::NamedTempFile::new().unwrap();
        assert!(SocketTracerNetnsScope::open(file.path()).is_err());
        assert!(SocketTracerNetnsScope::open(Path::new("/proc/self/ns/pid")).is_err());
    }

    #[test]
    fn scope_rejects_relative_and_missing_paths() {
        assert!(SocketTracerNetnsScope::open(Path::new("/proc/self/ns/absent")).is_err());
        // The same real namespace is unsuitable as a cwd-dependent bootstrap path.
        let relative = Path::new("../../../../../../../../../../proc/self/ns/net");
        assert!(relative.exists());
        assert!(SocketTracerNetnsScope::open(relative).is_err());
    }

    #[test]
    fn scope_rejects_zero_and_out_of_range_inodes() {
        assert!(validate_inode(0).is_err());
        assert_eq!(validate_inode(1).unwrap(), 1);
        assert_eq!(validate_inode(u32::MAX as u64).unwrap(), u32::MAX as u64);
        assert!(validate_inode(u32::MAX as u64 + 1).is_err());
        assert!(validate_inode(u64::MAX).is_err());
    }

    #[test]
    fn scope_process_pin_outlives_callers_and_cannot_be_replaced() {
        let slot = OnceLock::new();
        let scope = Arc::new(SocketTracerNetnsScope::open(Path::new("/proc/self/ns/net")).unwrap());
        let fd = scope._namespace.as_raw_fd();
        pin_once(&slot, scope.clone()).unwrap();
        drop(scope);
        assert_eq!(
            unsafe { libc::ioctl(fd, libc::NS_GET_NSTYPE) },
            libc::CLONE_NEWNET
        );
        let other = Arc::new(SocketTracerNetnsScope::open(Path::new("/proc/self/ns/net")).unwrap());
        assert_eq!(
            pin_once(&slot, other).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(slot.get().unwrap()._namespace.as_raw_fd(), fd);
    }

    #[cfg(not(feature = "libtrace"))]
    #[test]
    fn scope_packet_build_refuses_requested_scope_but_none_stays_compatible() {
        let mut config = crate::config::Config::default();
        prepare_socket_tracer_scope(&mut config).unwrap();
        assert_eq!(config.ebpf_socket_netns_inode, None);
        config.ebpf_socket_netns_scope = Some("/proc/self/ns/net".into());
        assert_eq!(
            prepare_socket_tracer_scope(&mut config).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(config.ebpf_socket_netns_inode, None);
    }
}
