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
        CloseHandle, ERROR_ALREADY_EXISTS, ERROR_INSUFFICIENT_BUFFER, ERROR_SERVICE_DOES_NOT_EXIST,
        FILETIME, GetLastError, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LocalFree,
        SetHandleInformation,
    },
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_LISTENER,
    },
    Networking::WinSock::AF_INET,
    Security::{Authorization::*, Cryptography::*, WinTrust::*, *},
    Storage::FileSystem::{
        CreateDirectoryW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_TYPE_PIPE, GetFileAttributesW,
        GetFileType, INVALID_FILE_ATTRIBUTES,
    },
    System::{
        Com::CoTaskMemFree, Console::*, Diagnostics::Debug::*, LibraryLoader::*, Services::*,
        Threading::*,
    },
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

struct ServiceHandle(SC_HANDLE);
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        // SAFETY: this handle was returned by OpenSCManagerW/OpenServiceW.
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

/// A running/transitioning legacy SCM collector must not silently compete with
/// the portable hub on another port and a different database. Read-only query;
/// never stop/reconfigure the installed service or send it an owner credential.
pub fn legacy_collector_active() -> Result<bool> {
    // SAFETY: null names select the local machine; only connect/query access.
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    ensure!(
        !manager.is_null(),
        "Could not check the installed NeonHearth service"
    );
    let manager = ServiceHandle(manager);
    let name = wide("NeonHearth")?;
    // SAFETY: valid SCM handle and null-terminated service name.
    let service = unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_QUERY_STATUS) };
    if service.is_null() {
        // SAFETY: read immediately after failed OpenServiceW.
        if unsafe { GetLastError() } == ERROR_SERVICE_DOES_NOT_EXIST {
            return Ok(false);
        }
        bail!("Could not check the installed NeonHearth service; no second collector was started");
    }
    let service = ServiceHandle(service);
    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    // SAFETY: valid read-only service handle and writable structure.
    ensure!(
        unsafe { QueryServiceStatus(service.0, &mut status) } != 0,
        "Could not read installed NeonHearth service status"
    );
    Ok(status.dwCurrentState != SERVICE_STOPPED)
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
    // Child loader failures must return their status for our actionable error,
    // rather than opening a blocking Windows DLL-error dialog behind the app.
    unsafe {
        SetErrorMode(
            GetErrorMode()
                | SEM_FAILCRITICALERRORS
                | SEM_NOGPFAULTERRORBOX
                | SEM_NOOPENFILEERRORBOX,
        );
    }
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

/// Application entropy mixed into every owner-credential blob (format 2).
/// DPAPI user scope is decryptable by ANY process of the same Windows account;
/// this does not change that. It only stops generic "CryptUnprotectData with
/// no entropy" credential stealers and other applications' blobs from opening
/// it. It is deliberately a constant, not a per-install file: a file beside the
/// blob would add no protection against the same account and would turn a lost
/// file into an unrecoverable credential.
pub const OWNER_ENTROPY: &[u8] = b"NeonHearth Home Hub owner credential, format 2";

pub fn protect(bytes: &[u8], decrypt: bool, entropy: Option<&[u8]>) -> Result<Vec<u8>> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= 16384,
        "Invalid protected credential size"
    );
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr().cast_mut(),
    };
    let entropy_blob = entropy.map(|value| CRYPT_INTEGER_BLOB {
        cbData: value.len() as u32,
        pbData: value.as_ptr().cast_mut(),
    });
    let entropy_ptr = entropy_blob
        .as_ref()
        .map_or(ptr::null(), |blob| blob as *const CRYPT_INTEGER_BLOB);
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: inputs live through the call; DPAPI allocates the output for LocalFree.
    let ok = unsafe {
        if decrypt {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                entropy_ptr,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptProtectData(
                &input,
                ptr::null(),
                entropy_ptr,
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

/// Load-time imports of this exe are pinned to System32 by the linker flag in
/// build.rs. This covers every later dynamic load: no current-directory and no
/// application-directory entries remain in the DLL search order.
pub fn restrict_dll_search() {
    let empty = [0u16];
    // SAFETY: a null-terminated empty string removes the current directory
    // from the search path; the flag constant is a documented value.
    unsafe {
        SetDllDirectoryW(empty.as_ptr());
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    }
}

/// True when this process runs with an elevated (administrator) token.
pub fn is_elevated() -> Result<bool> {
    let mut token = ptr::null_mut();
    ensure!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0,
        "Cannot read the Windows process token"
    );
    let token = Handle(token);
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0;
    ensure!(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
        } != 0,
        "Cannot read the Windows elevation state"
    );
    Ok(elevation.TokenIsElevated != 0)
}

const TRUSTED_WRITERS: [&str; 4] = [
    "S-1-5-18",     // SYSTEM
    "S-1-5-32-544", // Administrators
    "S-1-3-0",      // CREATOR OWNER (resolves to the owner, checked separately)
    // NT SERVICE\TrustedInstaller
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];
// FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD | DELETE | WRITE_DAC |
// WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE
const ACCESS_ALLOWED_ACE_TYPE: u32 = 0;
const MODIFYING_RIGHTS: u32 =
    0x2 | 0x4 | 0x40 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x1000_0000 | 0x4000_0000;

fn sid_from_text(text: &str) -> Result<Local> {
    let encoded = wide(text)?;
    let mut sid = ptr::null_mut();
    ensure!(
        unsafe { ConvertStringSidToSidW(encoded.as_ptr(), &mut sid) } != 0,
        "Cannot parse a Windows security identifier"
    );
    Ok(Local(sid))
}

fn sid_text(sid: *mut c_void) -> String {
    let mut text = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return "an unknown principal".into();
    }
    let _text = Local(text.cast());
    let mut length = 0;
    unsafe {
        while length < 256 && *text.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(text, length))
    }
}

/// Returns a description of the first principal, other than the current user,
/// SYSTEM, Administrators and TrustedInstaller, that owns the object or holds
/// an ALLOW entry granting it the right to modify, replace, or re-permission
/// it (None when the object can only be changed by trusted principals).
pub fn untrusted_writer(path: &Path) -> Result<Option<String>> {
    let name = wide(path)?;
    let mut owner = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    ensure!(
        unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        } == 0,
        "Cannot read the permissions of {}",
        path.display()
    );
    let _descriptor = Local(descriptor);
    let mut trusted = Vec::new();
    for text in TRUSTED_WRITERS {
        trusted.push(sid_from_text(text)?);
    }
    trusted.push(sid_from_text(&user_sid()?)?);
    let is_trusted = |sid: *mut c_void| {
        trusted
            .iter()
            .any(|known| unsafe { EqualSid(known.0, sid) } != 0)
    };
    if !is_trusted(owner) {
        return Ok(Some(format!("owner {}", sid_text(owner))));
    }
    if dacl.is_null() {
        return Ok(Some("everyone (the object has no access list)".into()));
    }
    let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe {
            GetAclInformation(
                dacl,
                (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } != 0,
        "Cannot read an access list"
    );
    for index in 0..info.AceCount {
        let mut entry = ptr::null_mut();
        ensure!(
            unsafe { GetAce(dacl, index, &mut entry) } != 0 && !entry.is_null(),
            "Cannot read an access entry"
        );
        // SAFETY: GetAce returned a pointer inside the descriptor kept alive above.
        let header = unsafe { &*(entry as *const ACE_HEADER) };
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0
        {
            continue;
        }
        let allowed = unsafe { &*(entry as *const ACCESS_ALLOWED_ACE) };
        let sid = (&allowed.SidStart as *const u32)
            .cast_mut()
            .cast::<c_void>();
        if allowed.Mask & MODIFYING_RIGHTS != 0 && !is_trusted(sid) {
            return Ok(Some(sid_text(sid)));
        }
    }
    Ok(None)
}

const WINTRUST_ACTION_GENERIC_VERIFY_V2: windows_sys::core::GUID = windows_sys::core::GUID {
    data1: 0x00aac56b,
    data2: 0xcd44,
    data3: 0x11d0,
    data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
};
const TRUST_E_NOSIGNATURE: i32 = 0x800B0100_u32 as i32;
const TRUST_E_PROVIDER_UNKNOWN: i32 = 0x800B0001_u32 as i32;
const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800B0003_u32 as i32;

/// Authenticode state of a file. Revocation is not consulted: the hub is
/// local-first and must start offline, and the signing certificates are
/// short-lived timestamped ones.
#[derive(Debug, PartialEq, Eq)]
pub enum Signature {
    Unsigned,
    Valid { signer: String },
}

pub fn authenticode(path: &Path) -> Result<Signature> {
    let name = wide(path)?;
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: name.as_ptr(),
        hFile: ptr::null_mut(),
        pgKnownSubject: ptr::null_mut(),
    };
    let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous.pFile = &mut file;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: all pointers refer to live locals; the state is always closed below.
    let status = unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    let result = if status == 0 {
        signer_name(data.hWVTStateData).map(|signer| Signature::Valid { signer })
    } else if matches!(
        status,
        TRUST_E_NOSIGNATURE | TRUST_E_PROVIDER_UNKNOWN | TRUST_E_SUBJECT_FORM_UNKNOWN
    ) {
        Ok(Signature::Unsigned)
    } else {
        Err(anyhow::anyhow!(
            "The signature of {} is not valid (0x{:08X})",
            path.display(),
            status as u32
        ))
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        );
    }
    result
}

fn signer_name(state: HANDLE) -> Result<String> {
    // SAFETY: state is the live handle returned by a successful verification.
    unsafe {
        let provider = WTHelperProvDataFromStateData(state);
        ensure!(!provider.is_null(), "Cannot read the signature details");
        let signer = WTHelperGetProvSignerFromChain(provider, 0, 0, 0);
        ensure!(!signer.is_null(), "Cannot read the signer");
        let certificate = WTHelperGetProvCertFromChain(signer, 0);
        ensure!(
            !certificate.is_null() && !(*certificate).pCert.is_null(),
            "Cannot read the signing certificate"
        );
        let mut buffer = vec![0u16; 512];
        let length = CertGetNameStringW(
            (*certificate).pCert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            ptr::null(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        );
        ensure!(length > 1, "The signing certificate has no name");
        Ok(String::from_utf16_lossy(&buffer[..length as usize - 1]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dpapi_round_trip_and_modified_ciphertext_rejection() {
        let secret = b"local test credential, never used by a service";
        let mut encrypted = protect(secret, false, None).unwrap();
        assert!(!encrypted.windows(secret.len()).any(|bytes| bytes == secret));
        assert_eq!(protect(&encrypted, true, None).unwrap(), secret);
        let last = encrypted.len() - 1;
        encrypted[last] ^= 1;
        assert!(protect(&encrypted, true, None).is_err());
    }
    #[test]
    fn entropy_blobs_do_not_open_without_the_entropy() {
        let secret = b"local test credential, never used by a service";
        let sealed = protect(secret, false, Some(OWNER_ENTROPY)).unwrap();
        assert!(protect(&sealed, true, None).is_err());
        assert!(protect(&sealed, true, Some(b"another application")).is_err());
        assert_eq!(protect(&sealed, true, Some(OWNER_ENTROPY)).unwrap(), secret);
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
    #[test]
    fn elevation_state_can_be_read() {
        assert!(is_elevated().is_ok());
    }
    #[test]
    fn microsoft_programs_verify_and_unsigned_programs_are_reported() {
        // Most system files are catalog-signed (WinVerifyTrust file mode reports
        // them as unsigned); these carry an embedded Authenticode signature.
        let candidates = [
            r"C:\Program Files\Windows Defender\MpCmdRun.exe",
            r"C:\Windows\System32\OneDriveSetup.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Windows\System32\notepad.exe",
        ];
        let verified = candidates
            .iter()
            .map(Path::new)
            .filter(|path| path.is_file())
            .filter_map(|path| authenticode(path).ok())
            .any(|signature| matches!(signature, Signature::Valid { .. }));
        let any_present = candidates.iter().any(|path| Path::new(path).is_file());
        assert!(
            verified || !any_present,
            "no embedded-signature Microsoft program verified"
        );
        assert_eq!(
            authenticode(&std::env::current_exe().unwrap()).unwrap(),
            Signature::Unsigned
        );
    }
    #[test]
    fn writability_check_accepts_private_folders_and_rejects_shared_ones() {
        let directory = tempfile::tempdir().unwrap();
        let private = directory.path().join("private");
        private_directory(&private).unwrap();
        assert_eq!(untrusted_writer(&private).unwrap(), None);
        let shared = directory.path().join("shared");
        private_directory(&shared).unwrap();
        let status = std::process::Command::new("icacls")
            .arg(&shared)
            .args(["/grant", "*S-1-1-0:(OI)(CI)M"])
            .output()
            .unwrap();
        assert!(status.status.success());
        assert!(untrusted_writer(&shared).unwrap().is_some());
    }
}
