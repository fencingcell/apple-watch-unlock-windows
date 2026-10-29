//! Watch Login prototype. AGPL-3.0-only. No credentials or logon submission.
mod events;
mod gatt;
mod service;
mod storage;
use anyhow::{bail, ensure, Context, Result};
use std::{
    io::{self, Write},
    path::PathBuf,
    sync::atomic::Ordering,
};
use watch_unlock_auth::{key_fingerprint, public_key_hex};
use windows::Win32::{
    Foundation::BOOL,
    System::Console::{
        SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT, CTRL_LOGOFF_EVENT,
        CTRL_SHUTDOWN_EVENT,
    },
};

unsafe extern "system" fn cancel(kind: u32) -> BOOL {
    if matches!(
        kind,
        CTRL_C_EVENT
            | CTRL_BREAK_EVENT
            | CTRL_CLOSE_EVENT
            | CTRL_LOGOFF_EVENT
            | CTRL_SHUTDOWN_EVENT
    ) {
        gatt::STOP.store(true, Ordering::Release);
        true.into()
    } else {
        false.into()
    }
}
struct Console;
impl Drop for Console {
    fn drop(&mut self) {
        unsafe {
            let _ = SetConsoleCtrlHandler(Some(cancel), false);
        }
    }
}
fn user_root() -> Result<PathBuf> {
    let root = storage::data_root(false)?;
    storage::ensure_private_dir(&root)?;
    storage::ensure_private_dir(&root.join("secrets"))?;
    storage::ensure_private_dir(&root.join("public"))?;
    Ok(root)
}
fn confirm(fingerprint: &str) -> Result<()> {
    println!("Compare this Watch key fingerprint with the value shown on your Watch/iPhone:\n{fingerprint}\nType the complete matching fingerprint to trust this Watch (a changed key is never silently trusted):");
    io::stdout().flush()?;
    let mut answer = String::new();
    use std::io::{BufRead, Read};
    io::BufReader::new(io::stdin().take(128)).read_line(&mut answer)?;
    ensure!(
        answer.trim() == fingerprint,
        "fingerprint confirmation did not match"
    );
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("doctor") if args.len()==1=>gatt::doctor(),
        Some("service") if args.len()==1=>service::dispatch(),
        Some("show-identity") if args.len()==1 || (args.len()==2 && args[1]=="--service-data")=> {
            let service=args.len()==2;
            let key=if service {storage::parse_watch_key(&storage::read_limited_file(&storage::data_root(true)?.join("public/computer-public-key.txt"),132)?)?}
                else {hex::decode(public_key_hex(&storage::identity(&user_root()?)?))?};
            println!("context={}\ncomputer_public_key={}\ncomputer_fingerprint={}",if service {"SYSTEM service (separate key; pair this fingerprint explicitly)"}else{"foreground user"},hex::encode(&key),key_fingerprint(&key)?);Ok(())
        },
        Some("trust-watch") if args.len()==2=> {
            let path=std::fs::canonicalize(&args[1]).context("cannot locate public key file")?;
            let key=storage::parse_watch_key(&storage::read_limited_file(&path,132)?)?;
            let fingerprint=key_fingerprint(&key)?; confirm(&fingerprint)?;
            let root=user_root()?;
            storage::atomic_public(&root.join("secrets"),"watch-public-key.txt",hex::encode(&key).as_bytes())?;
            println!("Watch key enrolled for foreground user; restart serve to load it. Service enrollment uses Install-ProbeService.ps1.");Ok(())
        },
        Some("forget-watch") if args.len()==1=> {
            let path=user_root()?.join("secrets/watch-public-key.txt");
            if path.try_exists()? {storage::ensure_private_file(&path)?;std::fs::remove_file(path)?;}
            println!("Foreground Watch enrollment removed; stop/restart any running serve process.");Ok(())
        },
        Some("serve") if args.len()==1 || (args.len()==3 && args[1]=="--seconds")=> {
            let seconds=if args.len()==3 {args[2].parse::<u64>()?}else{120};ensure!((1..=3600).contains(&seconds),"seconds must be 1..3600");
            let root=user_root()?;let key=storage::identity(&root)?;let watch=storage::load_watch(&root)?;
            unsafe {SetConsoleCtrlHandler(Some(cancel),true)?;}let _console=Console;
            gatt::run(key,watch,Some(seconds),||Ok(()))
        },
        _=>bail!("Usage: watch-login-probe doctor | serve [--seconds 1..3600] | service | show-identity [--service-data] | trust-watch <public-key-file> | forget-watch"),
    }
}
