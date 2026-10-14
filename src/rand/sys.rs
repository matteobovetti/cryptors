//! The operating system's source of random bytes: the one place in the module
//! that is different on each platform, and the only `unsafe`.

use std::io;

/// Fills `buf` entirely with random bytes from the operating system, or says
/// why it could not.
pub(super) fn read(buf: &mut [u8]) -> io::Result<()> {
    fill_with(buf, platform::read_some)
}

/// Fills `buf` by calling `read_some` on what is left of it until nothing is.
///
/// `read_some` writes at the start of the slice it gets and says how many
/// bytes it wrote. It may write fewer than the slice holds (a system call
/// interrupted by a signal, or limited in the size of a request, does), and it
/// may be interrupted before it writes any; neither is a failure. Writing no
/// byte at all from a non-empty slice is: the platform calls used here never do
/// it, so it means the source is gone, and asking again would not end.
pub(super) fn fill_with(
    mut buf: &mut [u8],
    mut read_some: impl FnMut(&mut [u8]) -> io::Result<usize>,
) -> io::Result<()> {
    while !buf.is_empty() {
        match read_some(buf) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                buf = buf.get_mut(n..).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "cryptors::rand: the system wrote more random bytes than it was asked for",
                    )
                })?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

// `/dev/urandom` is the way in on a Unix that has no better call, and the way
// back on a Linux too old to have `getrandom`. It is compiled in the tests on
// every Unix, so that they can run it on a machine that never takes it.
cfg_select! {
    all(
        unix,
        any(test, not(any(target_vendor = "apple", target_os = "openbsd")))
    ) => {
        mod urandom {
            use std::fs::File;
            use std::io::{self, Read};
            use std::sync::OnceLock;

            /// Opened on first use and kept, so that a program that has used
            /// up its file descriptors can still draw random bytes after that.
            static DEVICE: OnceLock<io::Result<File>> = OnceLock::new();

            pub(super) fn read_some(buf: &mut [u8]) -> io::Result<usize> {
                match DEVICE.get_or_init(|| File::open("/dev/urandom")) {
                    // `Read` is implemented for `&File`, so a shared handle is
                    // enough, and threads can read from it at the same time.
                    Ok(file) => {
                        let mut device: &File = file;
                        device.read(buf)
                    }
                    // `io::Error` cannot be cloned; keep what a caller can act on.
                    Err(error) => Err(io::Error::new(error.kind(), error.to_string())),
                }
            }
        }
    }
    _ => {}
}

cfg_select! {
    // `getrandom(2)`: Linux 3.17, FreeBSD 12 and DragonFly BSD have it. With no
    // flags it waits until the kernel has gathered enough entropy to start,
    // which is once, at boot, and then never blocks.
    any(target_os = "linux", target_os = "freebsd", target_os = "dragonfly") => {
        mod platform {
            use std::ffi::{c_uint, c_void};
            use std::io;

            unsafe extern "C" {
                // The C library's wrapper: glibc 2.25, musl 1.1.20, and the
                // BSDs' own libc.
                fn getrandom(buf: *mut c_void, buflen: usize, flags: c_uint) -> isize;
            }

            /// The largest request made at once. Linux answers a bigger one
            /// with a short read (it returns at most 2^25 - 1 bytes), and
            /// FreeBSD refuses one over `IOSIZE_MAX`; this is below both.
            const MAX_REQUEST: usize = i32::MAX as usize;

            pub(super) fn read_some(buf: &mut [u8]) -> io::Result<usize> {
                let len = buf.len().min(MAX_REQUEST);
                // SAFETY: `buf` is valid for writes of `len` bytes, which is
                // at most its length, and `getrandom` writes only there.
                let result = unsafe { getrandom(buf.as_mut_ptr().cast(), len, 0) };
                match usize::try_from(result) {
                    Ok(written) => Ok(written),
                    Err(_) => after_failure(
                        io::Error::last_os_error(),
                        buf,
                        super::urandom::read_some,
                    ),
                }
            }

            /// What follows a failed `getrandom`: `ENOSYS`, which the standard
            /// library reports as `Unsupported`, means a kernel from before the
            /// call, and `/dev/urandom` is read instead. Any other error is the
            /// caller's: `EPERM` from a sandbox that forbids the call, say, is not
            /// a reason to read a file that the sandbox may allow, and the program
            /// would rather know.
            fn after_failure(
                error: io::Error,
                buf: &mut [u8],
                fallback: impl FnOnce(&mut [u8]) -> io::Result<usize>,
            ) -> io::Result<usize> {
                if error.kind() == io::ErrorKind::Unsupported {
                    fallback(buf)
                } else {
                    Err(error)
                }
            }

            #[cfg(test)]
            mod tests {
                use super::*;

                #[test]
                fn a_kernel_without_the_call_falls_back_to_the_device() {
                    let mut buf = [0u8; 4];
                    let n = after_failure(io::ErrorKind::Unsupported.into(), &mut buf, |buf| {
                        buf.fill(7);
                        Ok(3)
                    });
                    assert_eq!(n.unwrap(), 3);
                    assert_eq!(buf, [7; 4]);
                }

                #[test]
                fn any_other_failure_is_the_callers() {
                    for kind in [
                        io::ErrorKind::PermissionDenied,
                        io::ErrorKind::InvalidInput,
                        io::ErrorKind::Other,
                    ] {
                        let error = after_failure(kind.into(), &mut [0; 4], |_| {
                            panic!("fell back on {kind:?}")
                        })
                        .unwrap_err();
                        assert_eq!(error.kind(), kind);
                    }
                }

                /// The number of `ENOSYS` is the system's, and the standard
                /// library's name for it is what `after_failure` looks for.
                #[test]
                #[cfg(target_os = "linux")]
                fn enosys_is_unsupported() {
                    assert_eq!(
                        io::Error::from_raw_os_error(38).kind(),
                        io::ErrorKind::Unsupported
                    );
                }
            }
        }
    }
    // `arc4random_buf(3)`: the system's own generator for programs, which takes
    // a buffer of any size and cannot fail. Despite the name it has not used
    // RC4 on any of these systems for years.
    any(target_vendor = "apple", target_os = "openbsd") => {
        mod platform {
            use std::ffi::c_void;
            use std::io;

            unsafe extern "C" {
                fn arc4random_buf(buf: *mut c_void, nbytes: usize);
            }

            pub(super) fn read_some(buf: &mut [u8]) -> io::Result<usize> {
                // SAFETY: `buf` is valid for writes of `buf.len()` bytes, and
                // `arc4random_buf` writes only there.
                unsafe { arc4random_buf(buf.as_mut_ptr().cast(), buf.len()) };
                Ok(buf.len())
            }
        }
    }
    unix => {
        mod platform {
            pub(super) use super::urandom::read_some;
        }
    }
    _ => {
        mod platform {
            use std::io;

            pub(super) fn read_some(_buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "cryptors::rand: no source of random bytes is known for this platform",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A source that writes at most `limit` bytes of the sequence 1, 2, 3, ...
    /// at a time, and fails or writes nothing when `script` says so first.
    fn counting(
        limit: usize,
        mut script: Vec<io::Result<usize>>,
    ) -> impl FnMut(&mut [u8]) -> io::Result<usize> {
        let mut next = 1u8;
        script.reverse();
        move |buf: &mut [u8]| {
            if let Some(answer) = script.pop() {
                return answer;
            }
            let n = buf.len().min(limit);
            for byte in &mut buf[..n] {
                *byte = next;
                next = next.wrapping_add(1);
            }
            Ok(n)
        }
    }

    #[test]
    fn short_writes_continue_where_they_stopped() {
        for limit in [1, 2, 3, 7, 10, 100] {
            let mut buf = [0u8; 10];
            fill_with(&mut buf, counting(limit, vec![])).unwrap();
            assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], "limit {limit}");
        }
    }

    #[test]
    fn an_empty_buffer_asks_for_nothing() {
        let mut asked = false;
        fill_with(&mut [], |_| {
            asked = true;
            Ok(0)
        })
        .unwrap();
        assert!(!asked);
    }

    #[test]
    fn an_interrupted_call_is_made_again() {
        let interrupted = || Err(io::ErrorKind::Interrupted.into());
        let mut buf = [0u8; 5];
        let script = vec![interrupted(), interrupted(), interrupted()];
        fill_with(&mut buf, counting(usize::MAX, script)).unwrap();
        assert_eq!(buf, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn any_other_error_is_returned_at_once() {
        let mut calls = 0;
        let mut buf = [0u8; 5];
        let error = fill_with(&mut buf, |_| {
            calls += 1;
            Err(io::ErrorKind::PermissionDenied.into())
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(calls, 1);
    }

    #[test]
    fn a_source_that_writes_nothing_is_an_error_not_a_loop() {
        let mut calls = 0;
        let mut buf = [0u8; 5];
        let error = fill_with(&mut buf, |_| {
            calls += 1;
            Ok(0)
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(calls, 1);
    }

    #[test]
    fn a_source_that_claims_too_much_is_an_error_not_a_panic() {
        let mut buf = [0u8; 5];
        let error = fill_with(&mut buf, |_| Ok(6)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    #[cfg(unix)]
    fn the_device_fills_a_buffer() {
        // The route of a Unix with no better call, and of a Linux without
        // `getrandom`: run here whatever this machine takes.
        let mut buf = [0u8; 4099];
        fill_with(&mut buf, urandom::read_some).unwrap();
        assert!(buf.iter().any(|&b| b != 0));
        assert!(buf[..4096].iter().any(|&b| b != 0));
        let mut other = [0u8; 4099];
        fill_with(&mut other, urandom::read_some).unwrap();
        assert_ne!(buf, other);
    }
}
