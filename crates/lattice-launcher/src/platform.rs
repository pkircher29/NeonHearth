//! Windows security and process boundaries. No shell is used for startup.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{OsStr, c_void},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::Command,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, ERROR_INSUFFICIENT_BUFFER, FILETIME, HANDLE,
        HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LocalFree, SetHandleInformation,
    },
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_LISTENER,
    },
    Networking::WinSock::AF_INET,
    Security::{Authorization::*, Cryptography::*, *},
    Storage::FileSystem::{
        CreateDirectoryW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_TYPE_PIPE, GetFileAttributesW,
        GetFileType, INVALID_FILE_ATTRIBUTES,
    },
    System::{Com::CoTaskMemFree, Console::*, Threading::*},
    UI::{
        Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath, ShellExecuteW},
        WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW, SW_SHOWNORMAL},
    },
};

fn wide(value: impl AsRef<OsStr>) -> Result<Vec<u16>> {
    let mut result: Vec<_> = value.as_ref().encode_wide().collect();
    ensure!(
        !result.contains(&0) && result.len() < 32767,
        "Invalid Windows path or argument"
    );
    result.push(0);
    Ok(result)
}
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

pub fn default_state() -> Result<PathBuf> {
    let mut value = ptr::null_mut();
    // SAFETY: documented out-pointer; returned buffer is freed with CoTaskMemFree.
    ensure!(
        unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, ptr::null_mut(), &mut value) }
            >= 0
            && !value.is_null(),
        "Windows local application data is unavailable"
    );
    let result = unsafe {
        let mut length = 0;
        while length < 32767 && *value.add(length) != 0 {
            length += 1;
        }
        let path = if length < 32767 {
            Some(PathBuf::from(std::ffi::OsString::from_wide(
                std::slice::from_raw_parts(value, length),
            )))
        } else {
            None
        };
        CoTaskMemFree(value.cast());
        path.context("Windows application data path exceeds the supported length")?
    };
    Ok(result.join("NeonHearthHomeHub"))
}

/// Background components have their own log handles. Inherited caller pipes
/// must not keep a scripting client's read open after the launcher exits.
pub fn prevent_stdio_inheritance() -> Result<()> {
    for kind in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: borrowed handles stay open and retain their read/write access.
        let handle = unsafe { GetStdHandle(kind) };
        if !handle.is_null()
            && handle != INVALID_HANDLE_VALUE
            && unsafe { GetFileType(handle) } == FILE_TYPE_PIPE
        {
            ensure!(
                unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } != 0,
                "Cannot isolate launcher output from background processes"
            );
        }
    }
    Ok(())
}

fn user_sid() -> Result<String> {
    let mut token = ptr::null_mut();
    ensure!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0,
        "Cannot identify the current Windows user"
    );
    let token = Handle(token);
    let mut size = 0;
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut size);
    }
    ensure!(
        (size_of::<TOKEN_USER>() as u32..=65536).contains(&size),
        "Invalid Windows user information"
    );
    let mut bytes = vec![0u64; (size as usize).div_ceil(8)];
    ensure!(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                bytes.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        } != 0,
        "Cannot read Windows user information"
    );
    let user = unsafe { &*bytes.as_ptr().cast::<TOKEN_USER>() };
    let mut sid = ptr::null_mut();
    ensure!(
        unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) } != 0,
        "Cannot encode Windows user identity"
    );
    let _sid = Local(sid.cast());
    let mut length = 0;
    unsafe {
        while length < 256 && *sid.add(length) != 0 {
            length += 1;
        }
    }
    ensure!(
        length < 256,
        "Windows user identity exceeds its supported length"
    );
    Ok(String::from_utf16(unsafe {
        std::slice::from_raw_parts(sid, length)
    })?)
}

pub fn reject_reparse(path: &Path) -> Result<()> {
    let name = wide(path)?;
    let attributes = unsafe { GetFileAttributesW(name.as_ptr()) };
    ensure!(
        attributes != INVALID_FILE_ATTRIBUTES,
        "Required local file or directory is unavailable: {}",
        path.display()
    );
    ensure!(
        attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "Links and junctions are not accepted for private state or package files"
    );
    Ok(())
}

pub fn private_directory(path: &Path) -> Result<()> {
    ensure!(
        path.parent().is_some_and(Path::is_dir),
        "The parent of the private data folder must already exist"
    );
    let name = wide(path)?;
    let sid = user_sid()?;
    let descriptor = wide(format!("O:{sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})"))?;
    let mut security = ptr::null_mut();
    ensure!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor.as_ptr(),
                1,
                &mut security,
                ptr::null_mut(),
            )
        } != 0,
        "Cannot create private file permissions"
    );
    let _security = Local(security);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security,
        bInheritHandle: 0,
    };
    if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
        ensure!(
            std::io::Error::last_os_error().raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32),
            "Cannot create the private data folder"
        );
    }
    reject_reparse(path)?;
    ensure!(path.is_dir(), "Private state path must be a directory");
    let mut owner = ptr::null_mut();
    let mut existing = ptr::null_mut();
    ensure!(
        unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut existing,
            )
        } == 0,
        "Cannot verify private directory ownership"
    );
    let _existing = Local(existing);
    let mut expected = ptr::null_mut();
    let encoded_sid = wide(sid)?;
    ensure!(
        unsafe { ConvertStringSidToSidW(encoded_sid.as_ptr(), &mut expected) } != 0,
        "Cannot verify the current user identity"
    );
    let _expected = Local(expected);
    ensure!(
        unsafe { EqualSid(owner, expected) } != 0,
        "The data folder belongs to another Windows account"
    );
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = ptr::null_mut();
    ensure!(
        unsafe { GetSecurityDescriptorDacl(security, &mut present, &mut acl, &mut defaulted) } != 0
            && present != 0
            && !acl.is_null(),
        "Cannot verify private permissions"
    );
    ensure!(
        unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                acl,
                ptr::null_mut(),
            )
        } == 0,
        "Cannot restrict the data folder to this Windows account"
    );
    Ok(())
}

pub fn protect(bytes: &[u8], decrypt: bool) -> Result<Vec<u8>> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= 16384,
        "Invalid protected credential size"
    );
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: inputs live through the call; DPAPI allocates the output for LocalFree.
    let ok = unsafe {
        if decrypt {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptProtectData(
                &input,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    ensure!(
        ok != 0,
        "Windows could not unlock this credential for the current account"
    );
    let _output = Local(output.pbData.cast());
    ensure!(
        !output.pbData.is_null() && output.cbData <= 16384,
        "Invalid Windows protected credential output"
    );
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    if decrypt {
        unsafe {
            std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
        }
    }
    Ok(result)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStamp {
    pub pid: u32,
    pub created: u64,
    pub binary: PathBuf,
}

fn inspect(handle: HANDLE, pid: u32) -> Result<ProcessStamp> {
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    ensure!(
        unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) } != 0,
        "Cannot verify process start time"
    );
    let mut name = vec![0u16; 32768];
    let mut length = name.len() as u32;
    ensure!(
        unsafe { QueryFullProcessImageNameW(handle, 0, name.as_mut_ptr(), &mut length) } != 0,
        "Cannot verify the running executable"
    );
    let binary =
        PathBuf::from(std::ffi::OsString::from_wide(&name[..length as usize])).canonicalize()?;
    Ok(ProcessStamp {
        pid,
        created: (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime),
        binary,
    })
}

pub fn process_stamp(pid: u32, binary: &Path) -> Result<ProcessStamp> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    ensure!(!handle.is_null(), "Cannot inspect the new process");
    let handle = Handle(handle);
    let stamp = inspect(handle.0, pid)?;
    ensure!(
        stamp.binary == binary.canonicalize()?,
        "The process does not match the packaged executable"
    );
    Ok(stamp)
}

pub fn process_matches(stamp: &ProcessStamp) -> bool {
    process_stamp(stamp.pid, &stamp.binary).is_ok_and(|value| value.created == stamp.created)
}

pub fn stop(stamp: &ProcessStamp) -> Result<()> {
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
            0,
            stamp.pid,
        )
    };
    if handle.is_null() {
        ensure!(
            std::io::Error::last_os_error().raw_os_error() == Some(87),
            "Cannot verify the process before stopping it"
        );
        return Ok(());
    }
    let handle = Handle(handle);
    let current = inspect(handle.0, stamp.pid)?;
    ensure!(
        current.created == stamp.created && current.binary == stamp.binary,
        "Process identity changed; no process was stopped"
    );
    ensure!(
        unsafe { TerminateProcess(handle.0, 0) } != 0,
        "The owned process could not be stopped"
    );
    ensure!(
        unsafe { WaitForSingleObject(handle.0, 5000) } == 0,
        "The owned process did not stop in time"
    );
    Ok(())
}

/// Verify listener ownership before sending a bearer token or broker password.
pub fn listener_pid(port: u16) -> Result<Option<u32>> {
    let mut size = 0;
    let rc = unsafe {
        GetExtendedTcpTable(
            ptr::null_mut(),
            &mut size,
            0,
            u32::from(AF_INET),
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    ensure!(
        rc == ERROR_INSUFFICIENT_BUFFER && size <= 4 * 1024 * 1024,
        "Cannot verify local listener ownership"
    );
    for _ in 0..3 {
        let mut bytes = vec![0u64; (size as usize).div_ceil(8)];
        let capacity = bytes.len() * 8;
        let rc = unsafe {
            GetExtendedTcpTable(
                bytes.as_mut_ptr().cast(),
                &mut size,
                0,
                u32::from(AF_INET),
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if rc == ERROR_INSUFFICIENT_BUFFER {
            ensure!(
                size <= 4 * 1024 * 1024,
                "Local listener table exceeds its bounds"
            );
            continue;
        }
        ensure!(
            rc == 0 && capacity >= size_of::<u32>(),
            "Cannot read local listener ownership"
        );
        let table = bytes.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
        let count = unsafe { (*table).dwNumEntries as usize };
        let offset = std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
        ensure!(
            count <= (capacity - offset) / size_of::<MIB_TCPROW_OWNER_PID>(),
            "Invalid local listener table"
        );
        let rows = unsafe { (*table).table.as_ptr() };
        let mut found = None;
        for i in 0..count {
            let row = unsafe { &*rows.add(i) };
            if u16::from_be(row.dwLocalPort as u16) == port
                && matches!(row.dwLocalAddr.to_ne_bytes(), [127, 0, 0, 1] | [0, 0, 0, 0])
            {
                ensure!(
                    found.is_none(),
                    "More than one process claims this local listener"
                );
                found = Some(row.dwOwningPid);
            }
        }
        return Ok(found);
    }
    bail!("Local listener ownership changed repeatedly")
}

pub fn hide(command: &mut Command) {
    command.creation_flags(CREATE_NO_WINDOW);
}

pub fn open_browser(url: &str) -> Result<()> {
    let url = wide(url)?;
    let operation = wide("open")?;
    ensure!(
        unsafe {
            ShellExecuteW(
                ptr::null_mut(),
                operation.as_ptr(),
                url.as_ptr(),
                ptr::null(),
                ptr::null(),
                SW_SHOWNORMAL,
            )
        } as isize
            > 32,
        "Open the dashboard using a configured default browser"
    );
    Ok(())
}

pub fn show_error(message: &str) {
    if let (Ok(message), Ok(title)) = (wide(message), wide("NeonHearth")) {
        unsafe {
            MessageBoxW(
                ptr::null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dpapi_round_trip_and_modified_ciphertext_rejection() {
        let secret = b"local test credential, never used by a service";
        let mut encrypted = protect(secret, false).unwrap();
        assert!(!encrypted.windows(secret.len()).any(|bytes| bytes == secret));
        assert_eq!(protect(&encrypted, true).unwrap(), secret);
        let last = encrypted.len() - 1;
        encrypted[last] ^= 1;
        assert!(protect(&encrypted, true).is_err());
    }
    #[test]
    fn listener_identification_matches_the_process_without_sending_credentials() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert_eq!(
            listener_pid(listener.local_addr().unwrap().port()).unwrap(),
            Some(std::process::id())
        );
        let stamp = process_stamp(std::process::id(), &std::env::current_exe().unwrap()).unwrap();
        assert!(process_matches(&stamp));
        assert!(!process_matches(&ProcessStamp {
            created: stamp.created + 1,
            ..stamp
        }));
    }
}
