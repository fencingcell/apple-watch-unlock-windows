//! DPAPI/ACL helpers adapted from this repository watchd/src/vault.rs (AGPL-3.0-only).

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, BOOL, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::Cryptography::{
    BCryptGenRandom, CryptProtectData, CryptUnprotectData, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    CRYPT_INTEGER_BLOB,
};
use windows::Win32::Security::{
    GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, DACL_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateDirectoryW, MoveFileExW, FILE_ATTRIBUTE_REPARSE_POINT, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const MAX_BLOB: u64 = 1024 * 1024;
const UI_FORBIDDEN: u32 = 1;

pub struct SecretBytes(pub Vec<u8>);

impl Drop for SecretBytes {
    fn drop(&mut self) {
        erase(&mut self.0);
    }
}

pub fn erase(value: &mut [u8]) {
    for byte in value {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

pub(crate) fn reject_reparse(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(meta) => ensure!(
                meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0,
                "Secret storage cannot use reparse points"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("Cannot inspect secret storage"),
        }
    }
    Ok(())
}

fn private_descriptor() -> Result<PSECURITY_DESCRIPTOR> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
        let mut size = 0;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut size);
        let mut buffer = vec![0usize; (size as usize + 7) / std::mem::size_of::<usize>()];
        let result = GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            size,
            &mut size,
        );
        let _ = CloseHandle(token);
        result?;
        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        let mut sid = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut sid)?;
        let sid_text = sid.to_string();
        let _ = LocalFree(HLOCAL(sid.0.cast()));
        let sddl: Vec<u16> = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{})", sid_text?)
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )?;
        Ok(descriptor)
    }
}

fn apply_private_acl(path: &Path, descriptor: PSECURITY_DESCRIPTOR) -> Result<()> {
    unsafe {
        let mut present = BOOL::default();
        let mut defaulted = BOOL::default();
        let mut dacl = std::ptr::null_mut();
        GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)?;
        ensure!(
            present.as_bool() && !dacl.is_null(),
            "Private DACL is unavailable"
        );
        let name = wide(path);
        SetNamedSecurityInfoW(
            PCWSTR(name.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            PSID::default(),
            PSID::default(),
            Some(dacl),
            None,
        )
        .ok()?;
    }
    Ok(())
}

pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    ensure!(dir.is_absolute(), "Secret directory must be absolute");
    reject_reparse(dir)?;
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent)?;
    }
    let descriptor = private_descriptor()?;
    let result = (|| {
        let name = wide(dir);
        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        let created = unsafe { CreateDirectoryW(PCWSTR(name.as_ptr()), Some(&attrs)) };
        if created.is_err() && !dir.is_dir() {
            bail!("Cannot create private directory");
        }
        reject_reparse(dir)?;
        apply_private_acl(dir, descriptor)
    })();
    unsafe {
        let _ = LocalFree(HLOCAL(descriptor.0));
    }
    result
}

/// Restrict an existing regular file without following reparse points.
pub fn ensure_private_file(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "Private file path must be absolute");
    reject_reparse(path)?;
    ensure!(
        fs::symlink_metadata(path)?.is_file(),
        "Private path must be a regular file"
    );
    let descriptor = private_descriptor()?;
    let result = apply_private_acl(path, descriptor);
    unsafe {
        let _ = LocalFree(HLOCAL(descriptor.0));
    }
    result
}

/// Bound allocation even if a file grows between metadata inspection and reading.
pub fn read_limited_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    reject_reparse(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0,
        "Private storage must be a regular file"
    );
    ensure!(metadata.len() <= maximum, "Private file is too large");
    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= maximum, "Private file is too large");
    Ok(bytes)
}

pub fn protect(data: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        !data.is_empty() && data.len() as u64 <= MAX_BLOB / 2,
        "Invalid secret size"
    );
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptProtectData(
            &input,
            PCWSTR::null(),
            None,
            None,
            None,
            UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|_| anyhow::anyhow!("CurrentUser secret encryption failed"))?;
        let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(output.pbData.cast()));
        Ok(bytes)
    }
}

pub fn unprotect(blob: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        !blob.is_empty() && blob.len() as u64 <= MAX_BLOB,
        "Invalid protected secret size"
    );
    let input = CRYPT_INTEGER_BLOB {
        cbData: blob.len() as u32,
        pbData: blob.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptUnprotectData(&input, None, None, None, None, UI_FORBIDDEN, &mut output)
            .map_err(|_| anyhow::anyhow!("CurrentUser secret decryption failed"))?;
        if output.cbData == 0 || output.pbData.is_null() {
            let _ = LocalFree(HLOCAL(output.pbData.cast()));
            bail!("Empty protected secret rejected");
        }
        let source = std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize);
        let bytes = source.to_vec();
        erase(source);
        let _ = LocalFree(HLOCAL(output.pbData.cast()));
        Ok(bytes)
    }
}

pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    unsafe {
        BCryptGenRandom(None, &mut bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG).ok()?;
    }
    Ok(bytes)
}

pub fn data_root(service: bool) -> Result<PathBuf> {
    let variable = if service {
        "ProgramData"
    } else {
        "LOCALAPPDATA"
    };
    let base = std::env::var_os(variable).context("Windows data directory unavailable")?;
    let root = PathBuf::from(base).join(if service {
        "WatchLoginProbe"
    } else {
        "WatchLoginProbe-User"
    });
    ensure!(root.is_absolute(), "Windows data path must be absolute");
    reject_reparse(&root)?;
    Ok(root)
}

pub fn parse_watch_key(bytes: &[u8]) -> Result<Vec<u8>> {
    ensure!(bytes.len() <= 132, "public key file too large");
    let text = std::str::from_utf8(bytes)?.trim_end_matches(['\r', '\n']);
    ensure!(
        text.len() == 130
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "expected 130 lowercase hex characters"
    );
    let key = hex::decode(text)?;
    watch_unlock_auth::key_fingerprint(&key)?;
    Ok(key)
}

pub fn load_watch(root: &Path) -> Result<Option<Vec<u8>>> {
    let path = root.join("secrets/watch-public-key.txt");
    if !path.try_exists()? {
        return Ok(None);
    }
    Ok(Some(parse_watch_key(&read_limited_file(&path, 132)?)?))
}

pub fn identity(root: &Path) -> Result<watch_unlock_auth::SigningKey> {
    ensure_private_dir(&root.join("secrets"))?;
    let path = root.join("secrets/computer.dpapi");
    let key = if path.try_exists()? {
        ensure_private_file(&path)?;
        let secret = SecretBytes(unprotect(&read_limited_file(&path, 4096)?)?);
        watch_unlock_auth::SigningKey::from_slice(&secret.0)
            .context("invalid protected identity")?
    } else {
        let key = loop {
            let secret = SecretBytes(random::<32>()?.to_vec());
            if let Ok(key) = watch_unlock_auth::SigningKey::from_slice(&secret.0) {
                break key;
            }
        };
        let scalar = zeroize::Zeroizing::new(key.to_bytes());
        let secret = SecretBytes(scalar.to_vec());
        let encrypted = protect(&secret.0)?;
        // create_new prevents two processes silently replacing each other's identity.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(&encrypted)?;
        file.sync_all()?;
        key
    };
    let public = watch_unlock_auth::public_key_hex(&key);
    atomic_public(
        &root.join("public"),
        "computer-public-key.txt",
        public.as_bytes(),
    )?;
    Ok(key)
}

pub fn atomic_public(root: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    ensure!(
        matches!(name, "watch-public-key.txt" | "computer-public-key.txt"),
        "invalid public filename"
    );
    reject_reparse(root)?;
    let target = root.join(name);
    reject_reparse(&target)?;
    let temp = root.join(format!("public-{}.tmp", hex::encode(random::<16>()?)));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        unsafe {
            MoveFileExW(
                PCWSTR(wide(&temp).as_ptr()),
                PCWSTR(wide(&target).as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

pub fn current_sid() -> Result<String> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
        let mut size = 0;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut size);
        let mut buffer = vec![0usize; (size as usize + 7) / std::mem::size_of::<usize>()];
        let result = GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            size,
            &mut size,
        );
        let _ = CloseHandle(token);
        result?;
        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        let mut sid = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut sid)?;
        let result = sid.to_string();
        let _ = LocalFree(HLOCAL(sid.0.cast()));
        Ok(result?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use watch_unlock_auth::{public_key_hex, SigningKey};
    #[test]
    fn key_file_is_exact_valid_uncompressed_p256() {
        let key = SigningKey::from_slice(&[2; 32]).unwrap();
        let text = public_key_hex(&key);
        assert_eq!(parse_watch_key(text.as_bytes()).unwrap().len(), 65);
        assert!(parse_watch_key(format!("{text}\r\n").as_bytes()).is_ok());
        for invalid in [
            text.to_uppercase(),
            format!(" {text}"),
            "00".repeat(65),
            "04".to_owned() + &"00".repeat(64),
            format!("{text}\n\n\n"),
        ] {
            assert!(parse_watch_key(invalid.as_bytes()).is_err());
        }
    }
    #[test]
    fn dpapi_roundtrip_and_tamper_rejection() {
        let clear = SecretBytes(random::<32>().unwrap().to_vec());
        let mut encrypted = protect(&clear.0).unwrap();
        assert_ne!(encrypted, clear.0);
        assert_eq!(unprotect(&encrypted).unwrap(), clear.0);
        let last = encrypted.len() - 1;
        encrypted[last] ^= 1;
        assert!(unprotect(&encrypted).is_err());
    }
    #[test]
    fn identity_survives_reload_without_trusting_unknown_watch() {
        let root = std::env::temp_dir().join(format!(
            "watch-login-probe-test-{}",
            hex::encode(random::<16>().unwrap())
        ));
        ensure_private_dir(&root).unwrap();
        ensure_private_dir(&root.join("public")).unwrap();
        let first = identity(&root).unwrap();
        let second = identity(&root).unwrap();
        assert_eq!(public_key_hex(&first), public_key_hex(&second));
        assert_eq!(load_watch(&root).unwrap(), None);
        let public = read_limited_file(&root.join("public/computer-public-key.txt"), 132).unwrap();
        assert_eq!(public, public_key_hex(&first).as_bytes());
        std::fs::remove_file(root.join("secrets/computer.dpapi")).unwrap();
        std::fs::remove_file(root.join("public/computer-public-key.txt")).unwrap();
        std::fs::remove_dir(root.join("secrets")).unwrap();
        std::fs::remove_dir(root.join("public")).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
