//! Bounded GATT advertisement comparison. No identity, enrollment or logon access.
//! AGPL-3.0-only. Modes change only the temporary publisher's payload.
use anyhow::{bail, ensure, Result};
use std::time::{Duration, Instant};
use windows::{
    core::{RuntimeType, GUID},
    Devices::Bluetooth::{BluetoothError, GenericAttributeProfile::*},
    Foundation::{AsyncStatus, IAsyncOperation, TypedEventHandler},
    Storage::Streams::DataWriter,
    Win32::System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED},
};
struct Apartment;
impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { RoUninitialize() }
    }
}
struct Publisher(GattServiceProvider);
impl Drop for Publisher {
    fn drop(&mut self) {
        let _ = self.0.StopAdvertising();
    }
}
fn wait<T: RuntimeType + 'static>(operation: IAsyncOperation<T>) -> Result<T> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() >= deadline {
            let _ = operation.Cancel();
            bail!("WinRT timeout");
        }
        if operation.Status()? != AsyncStatus::Started {
            return Ok(operation.GetResults()?);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn main() -> Result<()> {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "custom-list".into());
    ensure!(
        [
            "custom-list",
            "custom-data",
            "custom-data-quiet",
            "standard"
        ]
        .contains(&mode.as_str()),
        "unknown mode"
    );
    unsafe {
        RoInitialize(RO_INIT_MULTITHREADED)?;
    }
    let _apartment = Apartment;
    let service_uuid = match mode.as_str() {
        "standard" => 0x0000180f_0000_1000_8000_00805f9b34fb,
        _ => 0x4c23b2b0_5d5b_4b24_9c50_43320a1b0001,
    };
    let result = wait(GattServiceProvider::CreateAsync(GUID::from_u128(
        service_uuid,
    ))?)?;
    ensure!(
        result.Error()? == BluetoothError::Success,
        "service create error: {:?}",
        result.Error()?
    );
    let provider = Publisher(result.ServiceProvider()?);
    let began = Instant::now();
    let event_token = provider.0.AdvertisementStatusChanged(&TypedEventHandler::<
        GattServiceProvider,
        GattServiceProviderAdvertisementStatusChangedEventArgs,
    >::new(move |_, args| {
        if let Some(args) = args {
            println!(
                "event elapsed_ms={} status={:?} error={:?}",
                began.elapsed().as_millis(),
                args.Status()?,
                args.Error()?
            );
        }
        Ok(())
    }))?;
    let characteristic = GattLocalCharacteristicParameters::new()?;
    characteristic.SetCharacteristicProperties(GattCharacteristicProperties::Read)?;
    characteristic.SetReadProtectionLevel(GattProtectionLevel::Plain)?;
    let writer = DataWriter::new()?;
    writer.WriteBytes(&[1])?;
    characteristic.SetStaticValue(&writer.DetachBuffer()?)?;
    let cr = wait(provider.0.Service()?.CreateCharacteristicAsync(
        GUID::from_u128(if mode == "standard" {
            0x00002a19_0000_1000_8000_00805f9b34fb
        } else {
            0x4c23b2b0_5d5b_4b24_9c50_43320a1b0002
        }),
        &characteristic,
    )?)?;
    ensure!(
        cr.Error()? == BluetoothError::Success,
        "characteristic error: {:?}",
        cr.Error()?
    );
    let _characteristic = cr.Characteristic()?;
    let params = GattServiceProviderAdvertisingParameters::new()?;
    params.SetIsConnectable(true)?;
    params.SetIsDiscoverable(mode != "custom-data-quiet")?;
    if mode.starts_with("custom-data") {
        writer.WriteBytes(&[1])?;
        params.SetServiceData(&writer.DetachBuffer()?)?;
    }
    provider.0.StartAdvertisingWithParameters(&params)?;
    let began = Instant::now();
    let deadline = began + Duration::from_secs(10);
    let mut previous = None;
    let mut started = false;
    while Instant::now() < deadline {
        let status = provider.0.AdvertisementStatus()?;
        if previous != Some(status) {
            println!(
                "mode={mode} elapsed_ms={} status={status:?}",
                began.elapsed().as_millis()
            );
            previous = Some(status);
        }
        started |= matches!(
            status,
            GattServiceProviderAdvertisementStatus::Started
                | GattServiceProviderAdvertisementStatus::StartedWithoutAllAdvertisementData
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    writer.Close()?;
    provider.0.RemoveAdvertisementStatusChanged(event_token)?;
    drop(provider);
    println!("cleanup=stopped reached_started={started}");
    ensure!(started, "advertising never started in 10 seconds");
    Ok(())
}
