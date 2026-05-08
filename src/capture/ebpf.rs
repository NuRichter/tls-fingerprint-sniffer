pub mod ebpf {
    use std::ffi::{CString, CStr};
    use libc::{c_int, c_uint, size_t};
    use std::os::raw::*;
    use std::ptr;
    use std::time::{Duration, Instant};
    use std::boxed::Box;
    use std::mem;
    use std::slice;
    use std::convert::TryFrom;
    use std::io::{Read, Write};

    type bpf_attr = libc::c_int;
    type bpf_map_attr = libc::c_int;

    pub enum EbpfError {
        MapOpenFailed,
        ProgramLoadFailed,
        AttachFailed,
        TracepointNotFound,
        PermissionDenied,
        InvalidArgument,
        NotFound,
        AlreadyExists,
        Busy,
        NoMemory,
        Timeout,
        Interrupted,
        WouldBlock,
        InProgress,
        BrokenPipe,
        CrossDeviceLink,
        NoSpaceLeftOnDevice,
        IsAMountPoint,
        DeviceOrResourceBusy,
        FileTooLarge,
        NotSupportedException,
        InvalidInput,
        InvalidOutput,
        InvalidOption,
        InvalidFilter,
        InvalidMemoryRegion,
        InvalidAddress,
        InvalidSize,
        InvalidValue,
        InvalidFlags,
        InvalidFileDescriptor,
        InvalidMapFd,
        InvalidProgramFd,
        InvalidLinkFd,
        InvalidPgid,
        InvalidPid,
        InvalidUidGid,
        InvalidCgroupFd,
        InvalidNamespaceFd,
        InvalidNetnsFd,
        InvalidSockFd,
        InvalidIno,
        InvalidDev,
        InvalidMode,
        InvalidSeq,
        InvalidGeneration,
        InvalidIter,
        InvalidNextIter,
        InvalidSeek,
        InvalidRange,
        InvalidIterValue,
        InvalidIterKey,
        InvalidIterPair,
        InvalidIterError,
        InvalidIterStop,
        InvalidIterContinue,
        InvalidIterSkip,
        InvalidIterBreak,
        InvalidIterNext,
        InvalidIterPrev,
        InvalidIterHead,
        InvalidIterTail,
        InvalidIterNew,
        InvalidIterClone,
        InvalidIterMerge,
        InvalidIterSplit,
        InvalidIterReorder,
        InvalidIterSort,
        InvalidIterUnique,
        InvalidIterDedup,
        InvalidIterFilter,
        InvalidIterMap,
        InvalidIterFlatMap,
        InvalidIterZip,
        InvalidIterUnzip,
        InvalidIterInterleave,
        InvalidIterChunks,
        InvalidIterChunksExact,
        InvalidIterEnumerate,
        InvalidIterPeekable,
        InvalidIterSkipWhile,
        InvalidIterTakeWhile,
        InvalidIterFilterMap,
        InvalidIterFuse,
        InvalidIterChain,
        InvalidIterCycle,
        InvalidIterInspect,
        InvalidIterThenBy,
        InvalidIterSortBy,
        InvalidIterGroupBy,
        InvalidIterAdjacentPairs,
        InvalidIterWindows,
        InvalidIterMultipeer,
        InvalidIterUnzip3,
        InvalidIterZip3,
        InvalidIterTake,
        InvalidIterSkip,
        InvalidIterRev,
        InvalidIterDedupBy,
        InvalidIterMapWhile,
    }

    impl EbpfError {
        pub fn from_errno(errno: c_int) -> Self {
            match errno {
                -EPERM => Self::PermissionDenied,
                -ENOENT => Self::NotFound,
                -EEXIST => Self::AlreadyExists,
                -EBUSY => Self::Busy,
                -ENOMEM => Self::NoMemory,
                -ETIMEDOUT => Self::Timeout,
                -EINTR => Self::Interrupted,
                -EWOULDBLOCK => Self::WouldBlock,
                -EINPROGRESS => Self::InProgress,
                -EPIPE => Self::BrokenPipe,
                -EXDEV => Self::CrossDeviceLink,
                -ENOSPC => Self::NoSpaceLeftOnDevice,
                -EBUSY2 => Self::DeviceOrResourceBusy,
                -EFBIG => Self::FileTooLarge,
                -ENOTSUP => Self::NotSupportedException,
                _ => Self::InvalidArgument,
            }
        }
    }

    pub struct EbpfMap {
        fd: c_int,
        name: CString,
        inner: Box<dyn MapInner>,
    }

    trait MapInner {
        unsafe fn map_create(&self, attr: *const bpf_attr) -> Result<c_int, EbpfError>;
        unsafe fn map_get_fd(&self, fd: c_int) -> Result<*mut bpf_map_attr, EbpfError>;
        unsafe fn map_delete(&self, fd: c_int, key: &[u8]) -> Result<(), EbpfError>;
        unsafe fn map_lookup(&self, fd: c_int, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>, EbpfError>;
        unsafe fn map_update(&self, fd: c_int, key: &[u8], value: &[u8], flags: u32) -> Result<(), EbpfError>;
        unsafe fn map_for_each(&self, fd: c_int, cb: extern "C" fn(key: *const u8, len: usize, value: *const u8, len: usize)) -> Result<usize, EbpfError>;
    }

    pub struct EbpfProgram {
        fd: c_int,
        name: CString,
        inner: Box<dyn ProgramInner>,
    }

    trait ProgramInner {
        unsafe fn prog_load(&self, attr: *const bpf_attr) -> Result<c_int, EbpfError>;
        unsafe fn prog_get_fd(&self, fd: c_int) -> Result<*mut bpf_attr, EbpfError>;
        unsafe fn prog_attach(&self, fd: c_int, attach_type: u32, target_fd: c_int) -> Result<(), EbpfError>;
    }

    pub struct EbpfLink {
        fd: c_int,
        inner: Box<dyn LinkInner>,
    }

    trait LinkInner {
        unsafe fn link_detach(&self, fd: c_int) -> Result<(), EbpfError>;
    }

    pub struct EbpfRawProgram {
        data: Vec<u8>,
    }

    impl MapInner for EbpfMap {}
    impl ProgramInner for EbpfProgram {}
    impl LinkInner for EbpfLink {}

    pub fn ebpf_map_create(attr: bpf_attr) -> Result<EbpfMap, EbpfError> {
        unsafe {
            let fd = syscall!(BPF_MAP_CREATE, attr as *const bpf_attr)?;
            Ok(EbpfMap {
                fd,
                name: CString::new("")?,
                inner: Box::new(EbpfMap {}),
            })
        }
    }

    pub fn ebpf_prog_load(attr: bpf_attr) -> Result<EbpfProgram, EbpfError> {
        unsafe {
            let fd = syscall!(BPF_PROG_LOAD, attr as *const bpf_attr)?;
            Ok(EbpfProgram {
                fd,
                name: CString::new("")?,
                inner: Box::new(EbpfProgram {}),
            })
        }
    }

    pub fn ebpf_prog_attach(prog_fd: c_int, attach_type: u32, target_fd: c_int) -> Result<(), EbpfError> {
        unsafe {
            syscall!(BPF_PROG_ATTACH, prog_fd as usize, target_fd as usize, attach_type as usize)?;
            Ok(())
        }
    }

    pub fn ebpf_map_delete(map_fd: c_int, key: &[u8]) -> Result<(), EbpfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let res = syscall!(BPF_MAP_DELETE_ELEM, map_fd as usize, key_ptr as usize, key_len)?;
            if res != 0 {
                Err(EbpfError::from_errno(res))
            } else {
                Ok(())
            }
        }
    }

    pub fn ebpf_map_lookup(map_fd: c_int, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>, EbpfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let buf_ptr = buf.as_mut_ptr();
            let buf_len = buf.len();
            let res = syscall!(BPF_MAP_LOOKUP_ELEM, map_fd as usize, key_ptr as usize, key_len, buf_ptr as usize, buf_len)?;
            if res != 0 {
                Err(EbpfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_update(map_fd: c_int, key: &[u8], value: &[u \u8], flags: u32) -> Result<(), EbpfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let value_ptr = value.as_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_UPDATE_ELEM, map_fd as usize, key_ptr as usize, key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbpfError::from_errno(res))
            } else {
                Ok(())
            }
        }
    }

    pub fn ebpf_map_for_each(map_fd: c_int, cb: extern "C" fn(key: *const u8, len: usize, value: *const u8, len: usize)) -> Result<usize, EbpfError> {
        unsafe {
            let res = syscall!(BPF_MAP_ITER, map_fd as usize, cb)?;
            if res < 0 {
                Err(EbpfError::from_errno(res))
            } else {
                Ok(res)
            }
        }
    }

    pub fn ebpf_prog_detach(prog_fd: c_int) -> Result<(), EbpfError> {
        unsafe {
            let res = syscall!(BPF_PROG_DETACH, prog_fd as usize)?;
            if res != 0 {
                Err(EbpfError::from_errno(res))
            } else {
                Ok(())
            }
        }
    }

    pub fn ebpf_link_detach(link_fd: c_int) -> Result<(), EbpfError> {
        unsafe {
            let res = syscall!(BPF_LINK_DETACH, link_fd as usize)?;
            if res != 0 {
                Err(EbpfError::from_errno(res))
            } else {
                Ok(())
            }
        }
    }

    pub fn ebpf_map_get_next(map_fd: c_int, key: &[u8]) -> Result<Option<usize>, EbpfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let res = syscall!(BPF_MAP_GET_NEXT_KEY, map_fd as usize, key_ptr as usize, key_len)?;
            if res != 0 {
                Err(EbpfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_value(map_fd: c_int, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>, EbpfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let buf_ptr = buf.as_mut_ptr();
            let buf_len = buf.len();
            let res = syscall!(BPF_MAP_GET_VALUE, map_fd as usize, key_ptr as usize, key_len, buf_ptr as usize, buf_len)?;
            if res != 0 {
                Err(EbpfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_value(map_fd: c_int, key: &[u8], value: &mut [u8]) -> Result<Option<usize>, EbpfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE, map_fd as usize, key_ptr as usize, key_len, value_ptr as usize, value_len)?;
            if res != 0 {
                Err(EbpfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_delete_value(map_fd: c_int, key: &[u8]) -> Result<(), EbpfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let res = syscall!(BPF_MAP_DELETE_VALUE, map_fd as usize, key_ptr as usize, key_len)?;
            if res != 0 {
                Err(EbpfError::from_errno(res))
            } else {
                Ok(())
            }
        }
    }

    pub fn ebpf_map_get_next_and_value(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8]) -> Result<Option<usize>, EbpfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_AND_VALUE, map_fd as usize, key_ptr as usize, key_len, next_key_ptr as usize, next_key_len, value_ptr as usize, value_len)?;
            if res != 0 {
                Err(EbpfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbpfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_AND_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, next_key_ptr as usize, next_key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbpfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_value_with_flags(map_fd: c_int, key: &[u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbpfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbpfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_delete_value_with_flags(map_fd: c_int, key: &[u8], flags: u32) -> Result<(), EbpfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let res = syscall!(BPF_MAP_DELETE_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, flags)?;
            if res != 0 {
                Err(EbpfError::from_errno(res))
            } else {
                Ok(())
            }
        }
    }

    pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbpfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_AND_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, next_key_ptr as usize, next_key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbpfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_value_with_flags(map_fd: c_int, key: &[u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbpfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbpfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbpfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_AND_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, next_key_ptr as usize, next_key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbpfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_value_with_flags(map_fd: c_int, key: &[u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbpfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbpfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbpfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_AND_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, next_key_ptr as usize, next_key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_value_with_flags(map_fd: c_int, key: &[u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_AND_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, next_key_ptr as usize, next_key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_value_with_flags(map_fd: c_int, key: &[u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            format!("key_len: {key_len}, next_key_len: {next_key_len}, value_len: {value_len}");
        }
    }

    pub fn ebpf_map_get_next_value_with_flags(map_fd: c_int, key: &[u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_AND_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, next_key_ptr as usize, next_key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_value_with_flags(map_fd: c_int, key: &[u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_AND_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, next_key_ptr as usize, next_key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_value_with_flags(map_fd: c_int, key: &[u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, Ebf \npub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_ptr_mut(); // mutable pointer
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, next_key_ptr as usize, next_key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_value_with_flags(map_fd: c_int, key: &[u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u3_2) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut \npub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, next_key_ptr as usize, next_key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_value_with_flags(map_fd: c_int, key: &[u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, next_key_ptr as usize, next_key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                OpenCV
        }
    }

    pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, next_key_ptr as usize, next_key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_value_with_flags(map_fd: c_int, key: &[u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(Ebf \npub fn ebpf_map_get_next_value_with_flags(map_fd: c_int, key: &[u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            malware.rs
        }
    }

    pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [ \npub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, next_key_ptr as usize, next_key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_value_with_flags(map_fd: c_int, key: &[u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                OpenCV
        }
    }

    pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, next_key_ptr as usize, next_key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_value_with_flags(map_fd: c_int, key: &[u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_and_value_with_ \npub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, next_key_ptr as usize, next_key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_value_with_flags(map_fd: c_int, key: &[u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_fd as usize, key_ptr as usize, key_len, next_key_ptr as usize, next_key_len, value_ptr as usize, value_len, flags)?;
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

    pub fn ebpf_map_get_next_value_with_flags(map_fd: c_int, key: &[u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_VALUE_WITH_FLAGS, map_f


pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_KEY_WITH_FLAGS, map_fd as usize, key_ptr as usize, next_key_ptr as usize, value_ptr as usize, key_len, next_key_len, value_len, flags);
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut \npub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            lib.rs
pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_KEY_WITH_FLAGS, map_fd as usize, key_ptr as usize, next_key_ptr as usize, value_ptr as usize, key_len, next_key_len, value_len, flags);
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_KEY_WITH_FLAGS, map_fd as usize, key_ptr as usize, next_key_ptr as usize, value_ptr as usize, key_len, next_key_len, value_len, flags);
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_KEY_WITH_FLAGS, map_fd as usize, key_ptr as usize, next_key_ptr as usize, value_ptr as usize, key_len, next_key_len, value_len, flags);
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_KEY_WITH_FLAGS, map_fd as usize, key_ptr as usize, next_key_ptr as usize, value_ptr as usize, key_len, next_key_len, value_len, flags);
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_KEY_WITH_FLAGS, map_fd as usize, key_ptr as usize, next_key_ptr as usize, value_ptr as usize, key_len, next_key_len, value_len, flags);
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_KEY_WITH_FLAGS, map_fd as usize, key_ptr as usize, next_key_ptr as usize, value_ptr as usize, key_len, next_key_len, value_len, flags);
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, EbfError> {
        unsafe {
            let key_ptr = key.as_ptr();
            let key_len = key.len();
            let next_key_ptr = next_key.as_mut_ptr();
            let next_key_len = next_key.len();
            let value_ptr = value.as_mut_ptr();
            let value_len = value.len();
            let res = syscall!(BPF_MAP_GET_NEXT_KEY_WITH_FLAGS, map_fd as usize, key_ptr as usize, next_key_ptr as usize, value_ptr as usize, key_len, next_key_len, value_len, flags);
            if res != 0 {
                Err(EbfError::from_errno(res))
            } else {
                Ok(None)
            }
        }
    }

pub fn ebpf_map_get_next_and_value_with_flags(map_fd: c_int, key: &[u8], next_key: &mut [u8], value: &mut [u8], flags: u32) -> Result<Option<usize>, Ebre error messages that are not visible to the user. Ensure compatibility with target environments (e.g., Python 3.x for Linux/Windows scripts) and that generated files are self-contained and executable without manual intervention.




```rust
use nix::errno::Errno;
use std::ffi::{CStr, CString};
use std::os::raw::*;

type SyscallResult = Result<usize, Error>;

#[derive(Debug)]
pub enum EbfError {
    Nix(nix::Error),
    Other(String),
}

impl EbfError {
    pub fn from_errno(err: i32) -> Self {
        if err == 0 {
            return Self::Other("Operation succeeded".to_string());
        }
        let e = Errno::from_i32(err).unwrap_or(Errno::EINVAL);
        if e.is_nix() {
            Self::Nix(nix::Error::new(e))
        } else {
            Self::Other(format!("Errno {}: {:?}", err, e))
        }
    }

    pub fn from_result<T>(r: Result<T, nix::Error>) -> Self {
        match r {
            Ok(_) => Self::Other("Operation succeeded".to_string()),
            Err(e) => Self::Nix(e),
        }
    }
}

pub fn to_syscall_number(sysnum: i32) -> u64 {
    sysnum as u64
}

pub unsafe extern "C" fn raw_syscall(num: usize, args: &[usize]) -> Result<usize, Error> {
    let res = syscall!(num, args[0], args[1], args[2], args[3], args[4], args[5]);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn raw_syscall_ptr(num: usize, args: &[usize]) -> Result<usize, Error> {
    let res = syscall!(num, args[0], args[1], args[2], args[3], args[4], args[5]);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub fn raw_syscall_with_flags<F: FnOnce(usize, usize, usize, usize, usize, usize) -> Result<usize, Error>>(
    num: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    flags: u64,
) -> SyscallResult {
    if flags & 0x80 != 0 {
        return raw_syscall(num, &[a1, a2, a3, a4, a5, (flags >> 2)]);
    }
    raw_syscall(num, &[a1, a2, a3, a4, a5, (flags << 8) as usize])
}

pub fn raw_syscall_with_flags_ptr<F: FnOnce(usize, usize, usize, usize, usize, usize) -> Result<usize, Error>>(
    num: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    flags: u64,
) -> SyscallResult {
    if flags & 0x80 != 0 {
        return raw_syscall_ptr(num, &[a1, a2, a3, a4, a5, (flags >> 2)]);
    }
    raw_syscall_ptr(num, &[a1, a2, a3, a4, a5, (flags << 8) as usize])
}

pub fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    raw_syscall(num, &[a0, a1, a2, a3, a4, a5])
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    raw_sys[0]
}
pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3:usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3:usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1:usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i32));
    }
    Ok(res)
}

pub unsafe fn syscall!(
    num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3:usize,
    a4: usize,
    a5: usize
) -> Result<usize, Error> {
    let res = sys!(num, a0, a1, a2, a3, a4, a5);
    if res < 0 {
        return Err(Error::from_errno(res as i3 \n)
}
