//! WinRT server using Microsoft windows-rs 0.58 (MIT OR Apache-2.0).
//! Deferral/cancellation patterns derived from watchd/src/pairing.rs (AGPL-3.0-only).
use crate::storage;
use anyhow::{bail, ensure, Context, Result};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use watch_login_probe::transport::{Peers, MAX_PEERS};
use watch_unlock_auth::{key_fingerprint, public_key_hex, sign_request, Request, SigningKey};
use windows::{
    core::{RuntimeType, GUID},
    Devices::Bluetooth::{BluetoothAdapter, BluetoothError, GenericAttributeProfile::*},
    Foundation::{
        AsyncStatus, Deferral, EventRegistrationToken, IAsyncOperation, TypedEventHandler,
    },
    Storage::Streams::{DataReader, DataWriter},
    Win32::System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED},
};

pub static STOP: AtomicBool = AtomicBool::new(false);
const BASE: u128 = 0x4c23b2b0_5d5b_4b24_9c50_43320a1b0000;
const REJECT: u8 = 0x80;
pub struct Apartment;
impl Apartment {
    pub fn new() -> Result<Self> {
        unsafe {
            RoInitialize(RO_INIT_MULTITHREADED)?;
        }
        Ok(Self)
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe {
            RoUninitialize();
        }
    }
}
pub fn wall() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn wait<T: RuntimeType + 'static>(operation: IAsyncOperation<T>, end: Instant) -> Result<T> {
    loop {
        if STOP.load(Ordering::Acquire) || Instant::now() >= end {
            let _ = operation.Cancel();
            bail!("operation stopped or timed out");
        }
        match operation.Status()? {
            AsyncStatus::Completed => return Ok(operation.GetResults()?),
            AsyncStatus::Started => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                return Err(operation
                    .GetResults()
                    .err()
                    .map(anyhow::Error::from)
                    .unwrap_or_else(|| anyhow::anyhow!("WinRT operation failed")))
            }
        }
    }
}
pub fn doctor() -> Result<()> {
    let _apartment = Apartment::new()?;
    let adapter = wait(
        BluetoothAdapter::GetDefaultAsync()?,
        Instant::now() + Duration::from_secs(10),
    )?;
    let radio = wait(
        adapter.GetRadioAsync()?,
        Instant::now() + Duration::from_secs(10),
    )?;
    println!("BLE={} peripheral={} central={} radio={:?}; installation=not_checked wearer_authentication=not_tested cold_boot_logon=not_implemented",adapter.IsLowEnergySupported()?,adapter.IsPeripheralRoleSupported()?,adapter.IsCentralRoleSupported()?,radio.State()?);
    ensure!(
        adapter.IsLowEnergySupported()? && adapter.IsPeripheralRoleSupported()?,
        "Bluetooth LE peripheral role unavailable"
    );
    Ok(())
}
struct Session {
    session: GattSession,
    token: EventRegistrationToken,
    peer: String,
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.session.RemoveSessionStatusChanged(self.token);
    }
}
struct Shared {
    closing: AtomicBool,
    first_read_seen: AtomicBool,
    first_control_seen: AtomicBool,
    first_approval_seen: AtomicBool,
    peers: Mutex<Peers>,
    sessions: Mutex<HashMap<String, Session>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
    key: SigningKey,
    computer_name: String,
    process_session: u32,
}
impl Shared {
    fn session(self: &Arc<Self>, session: &GattSession, control: bool) -> Result<String> {
        ensure!(
            !self.closing.load(Ordering::Acquire)
                && session.SessionStatus()? == GattSessionStatus::Active,
            "session closed"
        );
        let id = session.DeviceId()?.Id()?.to_string();
        ensure!(id.len() <= 1024, "peer identifier too large");
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("session lock failed"))?;
        sessions.retain(|_, s| s.session.SessionStatus().ok() == Some(GattSessionStatus::Active));
        if let Some(old) = sessions.get(&id) {
            if old.session == *session {
                return Ok(old.peer.clone());
            }
            self.peers.lock().unwrap().remove(&old.peer);
            sessions.remove(&id);
        }
        ensure!(control, "fresh control required for new session");
        ensure!(sessions.len() < MAX_PEERS, "session limit reached");
        let peer = hex::encode(storage::random::<16>()?);
        let callback_peer = peer.clone();
        let weak = Arc::downgrade(self);
        let token = session.SessionStatusChanged(&TypedEventHandler::<
            GattSession,
            GattSessionStatusChangedEventArgs,
        >::new(move |_, args| {
            if args.as_ref().and_then(|a| a.Status().ok()) != Some(GattSessionStatus::Active) {
                crate::events::record("gatt_session=inactive; pending challenge cleared");
                if let Some(shared) = weak.upgrade() {
                    if let Ok(mut peers) = shared.peers.lock() {
                        peers.remove(&callback_peer);
                    }
                }
            }
            Ok(())
        }))?;
        sessions.insert(
            id,
            Session {
                session: session.clone(),
                token,
                peer: peer.clone(),
            },
        );
        crate::events::record("gatt_session=active; fresh control session registered");
        Ok(peer)
    }
    fn spawn(self: &Arc<Self>, work: impl FnOnce(Arc<Self>) + Send + 'static) {
        let Ok(mut workers) = self.workers.lock() else {
            return;
        };
        workers.retain(|w| !w.is_finished());
        if self.closing.load(Ordering::Acquire) || workers.len() >= 16 {
            return;
        }
        let shared = self.clone();
        if let Ok(worker) = std::thread::Builder::new()
            .name("probe-gatt".into())
            .spawn(move || {
                if let Ok(_apartment) = Apartment::new() {
                    work(shared);
                }
            })
        {
            workers.push(worker);
        }
    }
    fn start(&self, peer: &str, now: Instant) -> Result<()> {
        let wall = wall()?;
        let request = Request {
            protocol_version: 1,
            purpose: "probe".into(),
            computer_id: key_fingerprint(&hex::decode(public_key_hex(&self.key))?)?,
            account_sid: "S-1-0-0".into(),
            session_id: self.process_session,
            nonce: hex::encode(storage::random::<32>()?),
            expires_at_ms: wall.checked_add(30_000).context("clock overflow")?,
            computer_name: self.computer_name.clone(),
            account_name: "Authentication test".into(),
        };
        let signed = sign_request(request.clone(), &self.key)?;
        let bytes = serde_json::to_vec(&signed)?;
        self.peers
            .lock()
            .unwrap()
            .start(peer, request, bytes, wall, now)
    }
}
struct Complete(Deferral);
impl Drop for Complete {
    fn drop(&mut self) {
        let _ = self.0.Complete();
    }
}
struct Window {
    provider: GattServiceProvider,
    advertisement_token: Option<EventRegistrationToken>,
    read: Option<(GattLocalCharacteristic, EventRegistrationToken)>,
    writes: Vec<(GattLocalCharacteristic, EventRegistrationToken)>,
    shared: Arc<Shared>,
}
impl Drop for Window {
    fn drop(&mut self) {
        self.shared.closing.store(true, Ordering::Release);
        let _ = self.provider.StopAdvertising();
        if let Some(token) = self.advertisement_token.take() {
            let _ = self.provider.RemoveAdvertisementStatusChanged(token);
        }
        if let Some((c, t)) = self.read.take() {
            let _ = c.RemoveReadRequested(t);
        }
        for (c, t) in self.writes.drain(..) {
            let _ = c.RemoveWriteRequested(t);
        }
        // Removing subscriptions first prevents new jobs. Every request wait has a 2s bound.
        let workers = std::mem::take(&mut *self.shared.workers.lock().unwrap());
        for worker in workers {
            let _ = worker.join();
        }
        self.shared.sessions.lock().unwrap().clear();
        self.shared.peers.lock().unwrap().clear();
    }
}
fn characteristic(
    provider: &GattServiceProvider,
    id: u128,
    read: bool,
) -> Result<GattLocalCharacteristic> {
    let params = GattLocalCharacteristicParameters::new()?;
    params.SetCharacteristicProperties(if read {
        GattCharacteristicProperties::Read
    } else {
        GattCharacteristicProperties::Write
    })?;
    // Protocol authenticates both keys explicitly; OS BLE bonding is not enrollment.
    params.SetReadProtectionLevel(GattProtectionLevel::Plain)?;
    params.SetWriteProtectionLevel(GattProtectionLevel::Plain)?;
    let result = wait(
        provider
            .Service()?
            .CreateCharacteristicAsync(GUID::from_u128(id), &params)?,
        Instant::now() + Duration::from_secs(10),
    )?;
    ensure!(
        result.Error()? == BluetoothError::Success,
        "characteristic creation failed: {:?}",
        result.Error()?
    );
    Ok(result.Characteristic()?)
}
fn read_handler(
    shared: Arc<Shared>,
) -> TypedEventHandler<GattLocalCharacteristic, GattReadRequestedEventArgs> {
    TypedEventHandler::new(move |_, args: &Option<GattReadRequestedEventArgs>| {
        let Some(args) = args else {
            return Ok(());
        };
        let first_read = !shared.first_read_seen.swap(true, Ordering::Relaxed);
        if first_read {
            crate::events::record("gatt_read=received first=true");
        }
        let guard = Complete(args.GetDeferral()?);
        let args = args.clone();
        shared.spawn(move |state| {
            let _guard = guard;
            let operation = (|| -> Result<_> { Ok(args.GetRequestAsync()?) })();
            let Ok(request) =
                operation.and_then(|o| wait(o, Instant::now() + Duration::from_secs(2)))
            else {
                if first_read {
                    crate::events::record("gatt_read=request_unavailable first=true");
                }
                return;
            };
            let mut peer = None;
            let result = (|| -> Result<()> {
                ensure!(
                    request.Offset()? == 0 && request.Length()? >= 20,
                    "unsupported ATT offset or length"
                );
                let id = state.session(&args.Session()?, false)?;
                peer = Some(id.clone());
                let mut peers = state.peers.lock().unwrap();
                let bytes = peers.read(&id, wall()?, Instant::now())?;
                let writer = DataWriter::new()?;
                writer.WriteBytes(&bytes)?;
                let result = request.RespondWithValue(&writer.DetachBuffer()?);
                let _ = writer.Close();
                result?;
                if first_read {
                    crate::events::record("gatt_read=response_complete first=true");
                }
                Ok(())
            })();
            if result.is_err() {
                if let Some(peer) = peer {
                    state.peers.lock().unwrap().remove(&peer);
                }
                let _ = request.RespondWithProtocolError(REJECT);
                if first_read {
                    crate::events::record("gatt_read=rejected first=true");
                }
            }
        });
        Ok(())
    })
}
fn write_handler(
    shared: Arc<Shared>,
    control: bool,
) -> TypedEventHandler<GattLocalCharacteristic, GattWriteRequestedEventArgs> {
    TypedEventHandler::new(move |_, args: &Option<GattWriteRequestedEventArgs>| {
        let Some(args) = args else {
            return Ok(());
        };
        let seen = if control {
            &shared.first_control_seen
        } else {
            &shared.first_approval_seen
        };
        if !seen.swap(true, Ordering::Relaxed) {
            crate::events::record(if control {
                "gatt_control=received first=true"
            } else {
                "gatt_approval=received first=true"
            });
        }
        let guard = Complete(args.GetDeferral()?);
        let args = args.clone();
        shared.spawn(move |state| {
            let _guard = guard;
            let Ok(request) = args
                .GetRequestAsync()
                .map_err(anyhow::Error::from)
                .and_then(|o| wait(o, Instant::now() + Duration::from_secs(2)))
            else {
                return;
            };
            let mut peer = None;
            let result = (|| -> Result<bool> {
                ensure!(
                    request.Offset()? == 0
                        && request.Option()? == GattWriteOption::WriteWithResponse,
                    "write-with-response required"
                );
                let id = state.session(&args.Session()?, control)?;
                peer = Some(id.clone());
                let value = request.Value()?;
                let length = value.Length()? as usize;
                ensure!((1..=20).contains(&length), "invalid ATT length");
                let reader = DataReader::FromBuffer(&value)?;
                let mut bytes = vec![0; length];
                reader.ReadBytes(&mut bytes)?;
                reader.Close()?;
                if control {
                    state.peers.lock().unwrap().remove(&id);
                    ensure!(bytes == [1], "control must be 01");
                    state.start(&id, Instant::now())?;
                    request.Respond()?;
                    crate::events::record(
                        "challenge=created control_acknowledged=true purpose=probe",
                    );
                    return Ok(false);
                }
                let mut peers = state.peers.lock().unwrap();
                let accepted = peers.write(&id, &bytes, wall()?, Instant::now())?;
                request.Respond()?;
                Ok(accepted)
            })();
            match result {
                Ok(true) => crate::events::record(
                    "approval=validated enrolled_watch=true purpose=probe logon_submitted=false",
                ),
                Ok(false) => {}
                Err(_) => {
                    if let Some(peer) = peer {
                        state.peers.lock().unwrap().remove(&peer);
                    }
                    let _ = request.RespondWithProtocolError(REJECT);
                    crate::events::record(if control {
                        "gatt_control=rejected; fresh challenge required"
                    } else {
                        "approval=rejected; fresh challenge required"
                    });
                }
            }
        });
        Ok(())
    })
}
pub fn run(
    key: SigningKey,
    watch: Option<Vec<u8>>,
    seconds: Option<u64>,
    ready: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let _apartment = Apartment::new()?;
    let computer_name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows PC".into());
    ensure!(
        !computer_name.is_empty()
            && computer_name.len() <= 80
            && !computer_name.chars().any(char::is_control),
        "invalid computer display name"
    );
    crate::events::record(&format!(
        "computer_fingerprint={}",
        key_fingerprint(&hex::decode(public_key_hex(&key))?)?
    ));
    crate::events::record(&format!(
        "probe=starting process_session_id={}",
        crate::events::process_session()?
    ));
    crate::events::record(&format!(
        "watch_enrollment={}",
        if watch.is_some() {
            "configured; approvals require signature verification"
        } else {
            "unpaired; all approvals will reject"
        }
    ));
    let result = wait(
        GattServiceProvider::CreateAsync(GUID::from_u128(BASE | 1))?,
        Instant::now() + Duration::from_secs(10),
    )?;
    ensure!(
        result.Error()? == BluetoothError::Success,
        "GATT service creation failed: {:?}",
        result.Error()?
    );
    let shared = Arc::new(Shared {
        closing: AtomicBool::new(false),
        first_read_seen: AtomicBool::new(false),
        first_control_seen: AtomicBool::new(false),
        first_approval_seen: AtomicBool::new(false),
        peers: Mutex::new(Peers::new(watch)),
        sessions: Mutex::new(HashMap::new()),
        workers: Mutex::new(Vec::new()),
        key,
        computer_name,
        process_session: crate::events::process_session()?,
    });
    let mut window = Window {
        provider: result.ServiceProvider()?,
        advertisement_token: None,
        read: None,
        writes: Vec::new(),
        shared,
    };
    let read = characteristic(&window.provider, BASE | 2, true)?;
    let token = read.ReadRequested(&read_handler(window.shared.clone()))?;
    window.read = Some((read, token));
    for (id, control) in [(3, false), (4, true)] {
        let write = characteristic(&window.provider, BASE | id, false)?;
        let token = write.WriteRequested(&write_handler(window.shared.clone(), control))?;
        window.writes.push((write, token));
    }
    let params = GattServiceProviderAdvertisingParameters::new()?;
    params.SetIsConnectable(true)?;
    params.SetIsDiscoverable(true)?;
    let error = Arc::new(Mutex::new(None));
    let callback_error = error.clone();
    window.advertisement_token = Some(window.provider.AdvertisementStatusChanged(
        &TypedEventHandler::<
            GattServiceProvider,
            GattServiceProviderAdvertisementStatusChangedEventArgs,
        >::new(move |_, args| {
            if let Some(args) = args {
                if let Ok(value) = args.Error() {
                    crate::events::record(&format!(
                        "advertisement_event={:?} bluetooth_error={}",
                        args.Status().ok(),
                        bluetooth_error(Some(value))
                    ));
                    if args.Status().ok() == Some(GattServiceProviderAdvertisementStatus::Aborted) {
                        *callback_error.lock().unwrap() = Some(value);
                    }
                }
            }
            Ok(())
        }),
    )?);
    window.provider.StartAdvertisingWithParameters(&params)?;
    let start_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = window.provider.AdvertisementStatus()?;
        if startup_ready(
            status,
            STOP.load(Ordering::Acquire),
            Instant::now(),
            start_deadline,
        )
        .map_err(|failure| {
            anyhow::anyhow!(
                "{failure}; last Bluetooth error={}",
                bluetooth_error(*error.lock().unwrap())
            )
        })? {
            crate::events::record(&format!("advertising={status:?}"));
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    ready()?;
    let deadline = seconds.map(|s| Instant::now() + Duration::from_secs(s));
    while !STOP.load(Ordering::Acquire) && deadline.is_none_or(|d| Instant::now() < d) {
        ensure!(
            matches!(
                window.provider.AdvertisementStatus()?,
                GattServiceProviderAdvertisementStatus::Started
                    | GattServiceProviderAdvertisementStatus::StartedWithoutAllAdvertisementData
            ),
            "advertising stopped unexpectedly"
        );
        window
            .shared
            .peers
            .lock()
            .unwrap()
            .prune(wall()?, Instant::now());
        window
            .shared
            .sessions
            .lock()
            .unwrap()
            .retain(|_, s| s.session.SessionStatus().ok() == Some(GattSessionStatus::Active));
        std::thread::sleep(Duration::from_millis(100));
    }
    drop(window);
    crate::events::record("advertising=stopped; pending challenges cleared");
    Ok(())
}

fn startup_ready(
    status: GattServiceProviderAdvertisementStatus,
    stopped: bool,
    now: Instant,
    deadline: Instant,
) -> Result<bool> {
    ensure!(!stopped, "advertising startup cancelled");
    ensure!(
        now < deadline,
        "advertising did not start before deadline: {status:?}"
    );
    // Windows can briefly report Aborted before Started (observed at 250 ms).
    // Keep waiting within the same fixed window; never call ready before Started.
    Ok(matches!(
        status,
        GattServiceProviderAdvertisementStatus::Started
            | GattServiceProviderAdvertisementStatus::StartedWithoutAllAdvertisementData
    ))
}

fn bluetooth_error(error: Option<BluetoothError>) -> &'static str {
    match error {
        Some(BluetoothError::Success) => "Success",
        Some(BluetoothError::RadioNotAvailable) => "RadioNotAvailable",
        Some(BluetoothError::ResourceInUse) => "ResourceInUse",
        Some(BluetoothError::DeviceNotConnected) => "DeviceNotConnected",
        Some(BluetoothError::OtherError) => "OtherError",
        Some(BluetoothError::DisabledByPolicy) => "DisabledByPolicy",
        Some(BluetoothError::NotSupported) => "NotSupported",
        Some(BluetoothError::DisabledByUser) => "DisabledByUser",
        Some(BluetoothError::ConsentRequired) => "ConsentRequired",
        Some(BluetoothError::TransportNotSupported) => "TransportNotSupported",
        _ => "unavailable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_aborted_can_recover_before_ready() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(10);
        assert!(!startup_ready(
            GattServiceProviderAdvertisementStatus::Aborted,
            false,
            now,
            deadline
        )
        .unwrap());
        assert!(startup_ready(
            GattServiceProviderAdvertisementStatus::Started,
            false,
            now + Duration::from_millis(250),
            deadline
        )
        .unwrap());
    }

    #[test]
    fn persistent_failure_is_bounded_by_deadline() {
        let now = Instant::now();
        assert!(startup_ready(
            GattServiceProviderAdvertisementStatus::Aborted,
            false,
            now,
            now
        )
        .is_err());
        assert!(startup_ready(
            GattServiceProviderAdvertisementStatus::Created,
            false,
            now,
            now
        )
        .is_err());
        assert!(startup_ready(
            GattServiceProviderAdvertisementStatus::Started,
            false,
            now,
            now
        )
        .is_err());
    }

    #[test]
    fn cancellation_never_reports_ready() {
        let now = Instant::now();
        for status in [
            GattServiceProviderAdvertisementStatus::Created,
            GattServiceProviderAdvertisementStatus::Started,
            GattServiceProviderAdvertisementStatus::StartedWithoutAllAdvertisementData,
        ] {
            assert!(startup_ready(status, true, now, now + Duration::from_secs(10)).is_err());
        }
    }
}
