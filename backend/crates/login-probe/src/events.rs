//! Bounded local diagnostic log; no private keys, approvals or request payloads.
use anyhow::Result;
use std::{
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};
use windows::Win32::System::{RemoteDesktop::ProcessIdToSessionId, Threading::GetCurrentProcessId};
static LOG: OnceLock<PathBuf> = OnceLock::new();
static LOCK: Mutex<()> = Mutex::new(());
const LIMIT: u64 = 64 * 1024;
pub fn process_session() -> Result<u32> {
    let mut session = 0;
    unsafe {
        ProcessIdToSessionId(GetCurrentProcessId(), &mut session)?;
    }
    Ok(session)
}
pub fn initialize(public: &Path) -> Result<()> {
    let path = public.join("service-events.log");
    append(&path, "service=initializing")?;
    let _ = LOG.set(path);
    Ok(())
}
pub fn record(message: &str) {
    let _ = writeln!(std::io::stdout().lock(), "{message}");
    if let Some(path) = LOG.get() {
        if let Err(error) = append(path, message) {
            let _ = writeln!(
                std::io::stderr().lock(),
                "service event log failed: {error}"
            );
        }
    }
}
fn append(path: &Path, message: &str) -> Result<()> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let _guard = LOCK.lock().unwrap();
    crate::storage::reject_reparse(path)?;
    let clean: String = message
        .chars()
        .filter(|c| !c.is_control())
        .take(512)
        .collect();
    let line = format!(
        "utc_ms={} session_id={} {clean}\n",
        crate::gatt::wall()?,
        process_session()?
    );
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)?;
    let meta = file.metadata()?;
    anyhow::ensure!(
        meta.is_file() && meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0,
        "log must be a regular file"
    );
    if meta.len() + line.len() as u64 > LIMIT {
        file.set_len(0)?;
    }
    file.seek(SeekFrom::End(0))?;
    file.write_all(line.as_bytes())?;
    file.flush()?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_event_log_records_real_session_and_sanitizes_lines() {
        let path = std::env::temp_dir().join(format!(
            "probe-log-{}.txt",
            hex::encode(crate::storage::random::<16>().unwrap())
        ));
        for _ in 0..150 {
            append(&path, &"x".repeat(2000)).unwrap();
        }
        append(&path, "approval=validated\nforged=event").unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() <= LIMIT as usize);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains(&format!("session_id={}", process_session().unwrap())));
        assert!(!text.contains("\nforged"));
        assert!(text.contains("approval=validated"));
        std::fs::remove_file(path).unwrap();
    }
}
