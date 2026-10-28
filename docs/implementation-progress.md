# Implementation progress

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
