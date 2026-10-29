# Implementation progress

2026-10-29 update: user installed both apps using the iPhone signing tool “全能签”; iOS 27.2, Watch Series 9 / watchOS 27.0. Screenshots establish app launch and public-key transfer to the phone. Certificate type, expiry, renewal and physical wrist-policy behavior remain unverified. No Watch key has been trusted from the screenshot alone.

Installer race/path replacement hardening is committed at local 4cd3aed / remote 86ea594. Windows CI run 40826541975 passed seven isolated directory fixtures, including the positive elevated SYSTEM-only directory pin case, and all 29 existing focused Rust tests plus release build and license export. Final independent spec and quality re-review of 4cd3aed / cd8cacb passed; the previous P1 is closed.

Advertising diagnosis now distinguishes 16-bit standard service recovery (initial Aborted, Started at about 250 ms) from persistent failure of custom 128-bit service advertising over ten seconds. A bounded standalone diagnostic example and three startup regression tests were added at cd8cacb / remote f81df2e; production startup now tolerates a transient Aborted within its fixed deadline. Local focused tests are 32/32; Windows CI run 40831045900 passed, including separate release builds for the probe and diagnostic. This does not establish custom-service operation. A temporary short Bluetooth display-name comparison is awaiting user action; see bluetooth-advertising-diagnostics.md. No service or credential provider has been installed.

The following entries are historical checkpoints.

2026-10-28: User approved starting. Dedicated clone in the task work directory; feature branch starts at approved upstream revision 0c16912. Initial cloud destination unavailable: GitHub connector currently lists no repositories. Portable local Rust/LLVM tools are being prepared outside the source tree.

- Task 1 authentication protocol: complete at 6ad2891; independent spec and quality review passed. Auth 11/11 and backend regression 90/90 passed. Existing upstream watchd has three dead-code warnings.
- Task 2 Apple app/build: complete at 03e20a4; independent spec/quality review passed. Cloud run 40632784401 passed 7 Swift tests, 2 Python tests and unsigned device build/package checks; IPA downloaded and independently inspected.
- Task 3 Windows GATT probe/service: implementation, 18 probe tests, new-crate formatting/clippy and release build passed. Latest complete backend run has 110 passing tests including integration tests. Independent review found a service-data ownership issue; implementation now rejects untrusted existing roots and parent writes, and restores SYSTEM-only secret ACLs. Final independent re-review was interrupted by reviewer usage limits; parent inspected the fix, but does not label this an independent final approval.
- Task 4 review/package: draft PR #1 created; unsigned Apple package and Windows MSVC build available. Windows run 40686686593 passed all29 focused tests, release build and dependency notice export. Draft delivery only until final independent review and physical validation.
- Hardware/Watch installation and actual cold-boot login: not tested.

Read-only hardware query: this Windows x64 machine reports BLE, Central Role and Peripheral Role supported. This does not yet verify GATT availability in Session 0 before login.

Foreground runtime: GATT service and characteristic creation succeed, but advertising immediately reports Aborted with BluetoothError Success. An independent minimal PowerShell WinRT publisher reproduces Aborted outside the sandbox and stops cleanly. Cause remains unresolved; BLE interoperability is not established. No boot service has been installed, and no reboot/login configuration changes were made.

Full-workspace rustfmt check exposes existing upstream formatting differences. New auth/probe crates pass their scoped rustfmt check; unrelated upstream files were left unchanged. Upstream watchd retains three existing dead-code warnings.

Cloud destination: user supplied fencingcell/apple-watch-unlock-windows; repository write permission verified. Device target supplied: iOS 27.0.1 (possibly 27.2 later), Watch Series 9, watchOS 27.0. Windows account type remains to be confirmed at credential-integration time.
