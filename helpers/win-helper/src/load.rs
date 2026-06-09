//! Safe remote load flow built on the isolated Windows API boundary.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use proton_informer_helper_protocol::{
    HelperOptions, HelperPayload, HelperTarget, LoadLibraryResult, MAX_PAYLOAD_SIZE_BYTES,
    ProtocolArchitecture, WindowsModuleInfo,
};
use sha2::{Digest, Sha256};

use crate::error::HelperFailure;

const HEX: &[u8; 16] = b"0123456789abcdef";
const IMAGE_FILE_DLL: u16 = 0x2000;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const PE32_MAGIC: u16 = 0x010b;
const PE32_PLUS_MAGIC: u16 = 0x020b;

/// Platform-neutral payload lock retained through validation and loading.
struct LockedPayload {
    canonical_path: String,
    #[cfg(windows)]
    _lock: crate::winapi::LockedPayload,
}

/// Diagnostic result from the remote loader thread.
struct LoadThreadOutcome {
    exit_code_low32: u32,
    load_library_return: u64,
    windows_error: u32,
}

/// Validates, loads, and verifies one DLL in the resolved target.
pub fn run(
    target: &HelperTarget,
    payload: &HelperPayload,
    options: &HelperOptions,
) -> Result<LoadLibraryResult, HelperFailure> {
    if !is_absolute_windows_path(&payload.windows_path) {
        return Err(HelperFailure::InvalidWindowsPath(format!(
            "payload path is not drive-absolute or UNC: {}",
            payload.windows_path
        )));
    }
    let locked = platform_lock_payload(&payload.windows_path)?;
    validate_payload(
        payload,
        &locked.canonical_path,
        target.expected_architecture,
    )?;
    let process = crate::process::resolve(target)?;
    let modules_before = platform_modules(process.windows_pid)?;
    let dependency_warnings =
        dependency_warnings(&locked.canonical_path, &process, &modules_before)?;

    // Repeated requests are idempotent when the exact payload path is loaded
    if let Some(module) = find_module(&modules_before, &locked.canonical_path) {
        return Ok(result(
            &process,
            module.windows_path.clone(),
            None,
            dependency_warnings,
        ));
    }
    if let Some(module) = find_basename_conflict(&modules_before, &locked.canonical_path) {
        if module_matches_payload(module, payload) {
            return Ok(result(
                &process,
                module.windows_path.clone(),
                None,
                dependency_warnings,
            ));
        }
        return Err(HelperFailure::ModuleConflict(format!(
            "{} is already loaded from {}, requested {}",
            module.module_name, module.windows_path, locked.canonical_path
        )));
    }

    let thread = platform_load_library(
        process.windows_pid,
        &locked.canonical_path,
        options.timeout_ms,
    )?;
    let modules_after = platform_modules(process.windows_pid)?;
    let Some(loaded) = find_module(&modules_after, &locked.canonical_path) else {
        return if thread.load_library_return == 0 {
            Err(HelperFailure::LoadLibraryRejected {
                code: thread.windows_error,
                message: format!(
                    "LoadLibraryW failed with Windows error {}; likely causes include a missing \
                     dependency, a dependency with the wrong architecture, or DllMain returning \
                     FALSE{}",
                    thread.windows_error,
                    dependency_failure_suffix(&dependency_warnings)
                ),
            })
        } else {
            Err(HelperFailure::ModuleVerificationFailed(format!(
                "LoadLibraryW returned {:#018x}, but {} was not observed",
                thread.load_library_return, locked.canonical_path
            )))
        };
    };

    Ok(result(
        &process,
        loaded.windows_path.clone(),
        Some(thread.exit_code_low32),
        dependency_warnings,
    ))
}

/// Reports imported DLLs that are not visible through common loader paths.
fn dependency_warnings(
    payload_path: &str,
    process: &proton_informer_helper_protocol::WindowsProcessInfo,
    modules: &[WindowsModuleInfo],
) -> Result<Vec<String>, HelperFailure> {
    let payload = Path::new(payload_path);
    let payload_directory = payload.parent();
    let process_directory = process
        .executable_windows_path
        .as_deref()
        .and_then(|path| Path::new(path).parent());
    let imports = crate::imports::dll_names(payload)?;
    let mut warnings = Vec::new();

    for import in imports {
        let normalized = import.to_ascii_lowercase();
        if normalized.starts_with("api-ms-win-") || normalized.starts_with("ext-ms-win-") {
            continue;
        }
        let loaded = modules
            .iter()
            .any(|module| module.module_name.eq_ignore_ascii_case(&import));
        let adjacent = payload_directory.is_some_and(|directory| directory.join(&import).is_file())
            || process_directory.is_some_and(|directory| directory.join(&import).is_file());
        if !loaded && !adjacent && !platform_dependency_visible(&import)? {
            warnings.push(format!(
                "payload imports {import}, but no matching module or file was found in common \
                 prefix search paths"
            ));
        }
    }
    Ok(warnings)
}

/// Adds bounded preflight findings to a load failure.
fn dependency_failure_suffix(warnings: &[String]) -> String {
    if warnings.is_empty() {
        String::new()
    } else {
        format!("; dependency preflight: {}", warnings.join("; "))
    }
}

/// Confirms an already-loaded same-name module is byte-identical.
fn module_matches_payload(module: &WindowsModuleInfo, payload: &HelperPayload) -> bool {
    let path = Path::new(&module.windows_path);
    path.metadata().is_ok_and(|metadata| {
        metadata.is_file()
            && metadata.len() == payload.size_bytes
            && sha256_file(path, payload.size_bytes).is_ok_and(|hash| hash == payload.sha256)
    })
}

/// Accepts absolute drive or UNC paths without relative parent components.
fn is_absolute_windows_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    let drive_absolute = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    let unc = bytes.len() >= 5
        && matches!(bytes[0], b'\\' | b'/')
        && matches!(bytes[1], b'\\' | b'/')
        && !matches!(bytes[2], b'\\' | b'/');
    (drive_absolute || unc)
        && !path.contains('\0')
        && !path.split(['\\', '/']).any(|component| component == "..")
}

/// Confirms the helper sees the same immutable payload facts as the controller.
fn validate_payload(
    payload: &HelperPayload,
    canonical_path: &str,
    expected_architecture: ProtocolArchitecture,
) -> Result<(), HelperFailure> {
    let path = Path::new(canonical_path);
    let metadata = path
        .metadata()
        .map_err(|source| HelperFailure::io("unable to inspect payload", source))?;
    if !metadata.is_file() || metadata.len() != payload.size_bytes {
        return Err(HelperFailure::PayloadChanged(format!(
            "payload size changed: expected {}, found {}",
            payload.size_bytes,
            metadata.len()
        )));
    }
    if payload.size_bytes > MAX_PAYLOAD_SIZE_BYTES {
        return Err(HelperFailure::Validation(format!(
            "payload exceeds the {MAX_PAYLOAD_SIZE_BYTES}-byte limit"
        )));
    }
    let actual_hash = sha256_file(path, payload.size_bytes)?;
    if actual_hash != payload.sha256 {
        return Err(HelperFailure::PayloadChanged(
            "payload SHA-256 changed after controller validation".into(),
        ));
    }
    validate_pe_dll(path, expected_architecture)?;
    Ok(())
}

/// Reads only the DOS and COFF headers needed to prove PE DLL identity.
fn validate_pe_dll(
    path: &Path,
    expected_architecture: ProtocolArchitecture,
) -> Result<(), HelperFailure> {
    let mut file = File::open(path)
        .map_err(|source| HelperFailure::io("unable to open payload headers", source))?;
    let mut dos_header = [0_u8; 64];
    file.read_exact(&mut dos_header)
        .map_err(|source| HelperFailure::io("unable to read DOS header", source))?;
    if dos_header.get(..2) != Some(b"MZ") {
        return Err(HelperFailure::Validation(
            "payload does not have an MZ header".into(),
        ));
    }
    let pe_offset = u64::from(u32::from_le_bytes(
        dos_header[0x3c..0x40]
            .try_into()
            .map_err(|_| HelperFailure::Validation("invalid DOS header".into()))?,
    ));
    file.seek(SeekFrom::Start(pe_offset))
        .map_err(|source| HelperFailure::io("unable to seek to PE header", source))?;
    let mut pe_header = [0_u8; 24];
    file.read_exact(&mut pe_header)
        .map_err(|source| HelperFailure::io("unable to read PE header", source))?;
    if pe_header.get(..4) != Some(b"PE\0\0") {
        return Err(HelperFailure::Validation(
            "payload does not have a PE signature".into(),
        ));
    }

    let machine = u16::from_le_bytes([pe_header[4], pe_header[5]]);
    let section_count = u16::from_le_bytes([pe_header[6], pe_header[7]]);
    let optional_header_size = u16::from_le_bytes([pe_header[20], pe_header[21]]);
    let characteristics = u16::from_le_bytes([pe_header[22], pe_header[23]]);
    if section_count == 0 || optional_header_size < 2 {
        return Err(HelperFailure::Validation(
            "payload PE header has no sections or optional header".into(),
        ));
    }
    if characteristics & IMAGE_FILE_DLL == 0 {
        return Err(HelperFailure::Validation(
            "payload PE header is not marked as a DLL".into(),
        ));
    }
    let architecture = match machine {
        IMAGE_FILE_MACHINE_AMD64 => ProtocolArchitecture::X86_64,
        IMAGE_FILE_MACHINE_I386 => ProtocolArchitecture::X86,
        _ => ProtocolArchitecture::Unknown,
    };
    if architecture != expected_architecture {
        return Err(HelperFailure::ArchitectureMismatch(format!(
            "payload architecture {architecture:?} does not match target {expected_architecture:?}"
        )));
    }
    let mut optional_magic = [0_u8; 2];
    file.read_exact(&mut optional_magic)
        .map_err(|source| HelperFailure::io("unable to read PE optional header", source))?;
    let optional_magic = u16::from_le_bytes(optional_magic);
    let expected_magic = match architecture {
        ProtocolArchitecture::X86 => PE32_MAGIC,
        ProtocolArchitecture::X86_64 => PE32_PLUS_MAGIC,
        ProtocolArchitecture::Arm
        | ProtocolArchitecture::Aarch64
        | ProtocolArchitecture::Unknown => {
            return Err(HelperFailure::Validation(
                "payload architecture is unsupported".into(),
            ));
        }
    };
    if optional_magic != expected_magic {
        return Err(HelperFailure::Validation(format!(
            "payload optional-header magic {optional_magic:#06x} does not match architecture"
        )));
    }
    Ok(())
}

/// Hashes exactly one expected payload length with bounded memory.
fn sha256_file(path: &Path, expected_size: u64) -> Result<String, HelperFailure> {
    let mut file =
        File::open(path).map_err(|source| HelperFailure::io("unable to open payload", source))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    let mut total_bytes = 0_u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| HelperFailure::io("unable to read payload", source))?;
        if count == 0 {
            break;
        }
        total_bytes = total_bytes
            .checked_add(u64::try_from(count).map_err(|_| {
                HelperFailure::Validation("payload read count does not fit u64".into())
            })?)
            .ok_or_else(|| HelperFailure::Validation("payload size overflowed u64".into()))?;
        if total_bytes > expected_size {
            return Err(HelperFailure::PayloadChanged(
                "payload grew while it was being hashed".into(),
            ));
        }
        hasher.update(&buffer[..count]);
    }
    if total_bytes != expected_size {
        return Err(HelperFailure::PayloadChanged(
            "payload shrank while it was being hashed".into(),
        ));
    }

    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(encoded)
}

/// Finds an exact case-insensitive Windows module path.
fn find_module<'a>(
    modules: &'a [WindowsModuleInfo],
    expected_path: &str,
) -> Option<&'a WindowsModuleInfo> {
    modules
        .iter()
        .find(|module| normalized_path(&module.windows_path) == normalized_path(expected_path))
}

/// Finds a same-name module loaded from a different full path.
fn find_basename_conflict<'a>(
    modules: &'a [WindowsModuleInfo],
    expected_path: &str,
) -> Option<&'a WindowsModuleInfo> {
    let expected_name = windows_basename(expected_path)?;
    modules.iter().find(|module| {
        module.module_name.eq_ignore_ascii_case(expected_name)
            && normalized_path(&module.windows_path) != normalized_path(expected_path)
    })
}

/// Normalizes separators and extended prefixes for case-insensitive comparison.
fn normalized_path(path: &str) -> String {
    normalize_extended_path(path)
        .replace('/', "\\")
        .to_ascii_lowercase()
}

/// Removes extended prefixes while preserving a valid UNC prefix.
fn normalize_extended_path(path: &str) -> String {
    path.strip_prefix(r"\\?\UNC\").map_or_else(
        || path.strip_prefix(r"\\?\").unwrap_or(path).to_owned(),
        |path| format!(r"\\{path}"),
    )
}

/// Returns the final Windows path component.
fn windows_basename(path: &str) -> Option<&str> {
    path.rsplit(['\\', '/'])
        .find(|component| !component.is_empty())
}

/// Builds one verified result without exposing internal process types.
fn result(
    process: &proton_informer_helper_protocol::WindowsProcessInfo,
    loaded_module_path: String,
    thread_exit_code_low32: Option<u32>,
    dependency_warnings: Vec<String>,
) -> LoadLibraryResult {
    LoadLibraryResult {
        dependency_warnings,
        loaded_module_path,
        module_verified: true,
        process_name: process.process_name.clone(),
        thread_exit_code_low32,
        windows_pid: process.windows_pid,
    }
}

/// Checks Wine's Windows dependency search path.
#[cfg(windows)]
fn platform_dependency_visible(name: &str) -> Result<bool, HelperFailure> {
    crate::winapi::dependency_visible(name)
}

/// Refuses dependency search emulation from a host-native helper build.
#[cfg(not(windows))]
fn platform_dependency_visible(_name: &str) -> Result<bool, HelperFailure> {
    Err(HelperFailure::UnsupportedOperation(
        "dependency preflight requires a Windows helper build".into(),
    ))
}

/// Locks and canonicalizes a payload through the Windows API.
#[cfg(windows)]
fn platform_lock_payload(windows_path: &str) -> Result<LockedPayload, HelperFailure> {
    let lock = crate::winapi::lock_payload(windows_path)?;
    Ok(LockedPayload {
        canonical_path: lock.canonical_path().to_owned(),
        _lock: lock,
    })
}

/// Calls the Windows-only remote loader boundary.
#[cfg(windows)]
fn platform_load_library(
    windows_pid: u32,
    windows_path: &str,
    timeout_ms: u64,
) -> Result<LoadThreadOutcome, HelperFailure> {
    let result = crate::winapi::load_library(windows_pid, windows_path, timeout_ms)?;
    Ok(LoadThreadOutcome {
        exit_code_low32: result.exit_code_low32,
        load_library_return: result.load_library_return,
        windows_error: result.windows_error,
    })
}

/// Enumerates modules through the Windows-only boundary.
#[cfg(windows)]
fn platform_modules(windows_pid: u32) -> Result<Vec<WindowsModuleInfo>, HelperFailure> {
    crate::winapi::modules(windows_pid)
}

/// Refuses mutation from a host-native helper build.
#[cfg(not(windows))]
fn platform_lock_payload(_windows_path: &str) -> Result<LockedPayload, HelperFailure> {
    Err(HelperFailure::UnsupportedOperation(
        "payload locking requires a Windows helper build".into(),
    ))
}

/// Refuses mutation from a host-native helper build.
#[cfg(not(windows))]
fn platform_load_library(
    _windows_pid: u32,
    _windows_path: &str,
    _timeout_ms: u64,
) -> Result<LoadThreadOutcome, HelperFailure> {
    Err(HelperFailure::UnsupportedOperation(
        "LoadLibrary requires a Windows helper build".into(),
    ))
}

/// Refuses module inspection from a host-native helper build.
#[cfg(not(windows))]
fn platform_modules(_windows_pid: u32) -> Result<Vec<WindowsModuleInfo>, HelperFailure> {
    Err(HelperFailure::UnsupportedOperation(
        "module enumeration requires a Windows helper build".into(),
    ))
}
