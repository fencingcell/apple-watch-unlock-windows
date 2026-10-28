# Watch first-login prototype implementation plan

> **For agentic workers:** Use subagent-driven-development task by task, with a spec and quality review. Preserve the first-login integration gate: installation and wearer authentication need physical-device evidence before enabling account credential submission.

**Goal:** Deliver an unsigned iPhone/Watch app, cloud build workflow, and Windows BLE probe/service that demonstrate a fresh, signed approval after wrist authentication, without collecting or submitting a Windows password.

**Architecture:** Extend the pinned existing project (`0c16912`). A portable Rust authentication crate defines a mutually signed challenge protocol. The Windows probe publishes a GATT service; a foreground Watch app reads a challenge, checks its paired computer identity, evaluates wrist authentication without allowing interaction, and signs a one-use approval. An iPhone host provides the installable companion topology. GitHub macOS builds an unsigned IPA; Windows provides signing/install tooling separately.

**Tech stack:** Rust/windows-rs 0.58, p256 0.13, sha2 0.10, serde; SwiftUI, CoreBluetooth, CryptoKit, LocalAuthentication, Security; XcodeGen, GitHub Actions.

## Global constraints

- Keep AGPL-3.0 and NOTICE; add source attribution for new components.
- Windows 10/11 x64 and watchOS 9+; an iPhone companion is required for the Windows sideload route.
- Never infer wearer state from RSSI, IRK, MAC address, a device name, or a remote boolean.
- Use P-256 ECDSA, X9.63 uncompressed public keys (65 bytes) and IEEE P1363 raw signatures (64 bytes), all hex lowercase on the JSON wire.
- Challenge expiry is at most 30 seconds. Each accepted challenge may succeed once. Identity, purpose, account and session must be bound to the signature.
- All first-stage requests have purpose `probe`, account SID `S-1-0-0`, and account display `Authentication test`. No passwords, Credential Provider registration or autologon registry changes in the prototype.
- Watch pairing keys are stored with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; a fresh LAContext uses `.deviceOwnerAuthenticationWithWristDetection` and `interactionNotAllowed = true` for every approval.
- Require explicit computer key fingerprint confirmation on the Watch and Watch key fingerprint confirmation on Windows before approval is accepted; never silently trust a changed key.
- Keep compilation, installation, wearer authentication and cold-boot login validation as separate reported states.
- User approved the draft and free-account/weekly-renewal route on 2026-10-28 by asking to start. No local Mac is available.

## Shared wire contract

GATT service UUID: `4c23b2b0-5d5b-4b24-9c50-43320a1b0001`; request characteristic ends in `0002` (read); approval ends in `0003` (write with response); control ends in `0004` (write with response).

Control byte `01` starts a fresh challenge for that peer and clears incomplete transfers. Both request reads and approval writes use `[offset: u16 BE][total: u16 BE][payload: 1..16 bytes]`, at most 20 bytes per ATT value. Total <=4096 bytes. Offsets must be contiguous; inconsistent totals, excess data, peer changes and stale transfers reject. The client repeatedly reads until total bytes are obtained. A new control write is required to restart a transfer.

Signed request JSON: `{ "request": Request, "computer_public_key": hex, "signature": hex }`. `Request` fields: `protocol_version: u8` (1), `purpose: string` (`probe` or `logon`), `computer_id: hex` (SHA-256 of computer public key), `account_sid: string`, `session_id: u32`, `nonce: hex` (32 random bytes), `expires_at_ms: u64`, `computer_name: string`, `account_name: string`.

Canonical request bytes are `WATCH-LOGIN-REQUEST-V1\0`, u8 version, u8 purpose (`probe`=0, `logon`=1), 32 decoded computer-id bytes, u16-BE-length-prefixed UTF-8 account SID, u32-BE session ID, 32 decoded nonce bytes, u64-BE expiry, then length-prefixed computer name and account name. SID <=184 bytes; each display name <=80 UTF-8 bytes; reject control characters and empty strings. Account SID must be a syntactically valid numeric `S-1-...` SID. Lowercase hex and exact lengths are required.

Approval signing bytes are `WATCH-LOGIN-APPROVAL-V1\0` followed by SHA-256 of the canonical request. Signed approval JSON fields: `nonce`, `request_hash`, `watch_public_key`, `signature`. Approval checks compare nonce/hash, verify using the enrolled Watch key (never a received arbitrary key), check time and pending session, then consume the pending challenge atomically. Replays, invalid signatures, altered identities/names/account/session, wrong purpose, unknown keys and expired requests reject.

### Task 1: Shared authenticated challenge protocol

**Files:** create `backend/crates/auth/{Cargo.toml,src/lib.rs,tests/protocol.rs}`, `protocol/v1.json`; modify `backend/Cargo.toml` and lockfile.

**Interfaces:** expose serde `Request`, `SignedRequest`, `SignedApproval`; `Request::canonical_bytes() -> Result<Vec<u8>, AuthError>`; `SignedRequest::verify(expected_computer_key: &[u8], now_ms: u64) -> Result<(), AuthError>`; `SignedApproval::verify(request: &Request, expected_watch_key: &[u8], now_ms: u64) -> Result<(), AuthError>`; `sign_request(Request, &SigningKey)`, `sign_approval(&Request, &SigningKey)`; `public_key_hex`, `key_fingerprint`; `PendingApproval` holding one request and accepting only once. Export the p256 signing type or a helper for local key generation. `protocol/v1.json` holds synthetic, non-user key and request interoperability vectors.

- [ ] Add the crate manifest/module surface and failing tests first. Test accepted round trip; then tamper `account_sid`, session, nonce, purpose and name, wrong Watch/computer key, TTL >30s, exactly expired time, malformed hex, invalid SID, replay and invalid-then-valid retry. Example: `assert!(approval.verify(&altered_request, &watch_key, now).is_err());` and `assert!(pending.accept(&approval, &watch_key, now).is_err());` after first success.
- [ ] Run `cargo test -p watch-unlock-auth`; record missing behavior failures before implementation.
- [ ] Implement canonical encoding and signing with p256/sha2; use strict serde structures, bounded fields, exact encodings, typed errors and atomic replay state. Tests must validate real cryptography rather than mocks.
- [ ] Export fixed synthetic vectors from the same canonical contract. Include public keys, canonical bytes, request digest, request signature and approval signature. Verify vectors in Rust tests.
- [ ] Run crate tests and backend baseline, self-review, and commit only owned changes. Report exact command/output and review limitations.

### Task 2: iPhone host, Watch app and unsigned cloud build

**Files:** create `apps/apple/project.yml`, `apps/apple/Host/*`, `apps/apple/Watch/*`, `apps/apple/Shared/*`, `apps/apple/Tests/*`, `.github/workflows/apple-prototype.yml`, `scripts/Build-Apple.sh`.

**Interfaces:** implement precisely the wire contract and Task 1 vector fixture, independent of Rust internals. Create an iOS 16+ host embedding a watchOS 9+ app. No Windows credentials are requested or stored by either Apple app.

- [ ] Write Swift XCTest cases for canonical vector equality, signature verification, altered account/session/name rejection, frame ordering/size errors and explicit enrollment-key changes before app implementation. Run via cloud macOS; if no repository is available, record tests as not executed and never claim compile success.
- [ ] Add shared canonical encoder, pinned identities and keychain key storage. Watch Bluetooth client scans only the fixed service, connects, starts the challenge and reads bounded frames. Unknown computer keys require a full fingerprint display and explicit pairing confirmation before a separate login action.
- [ ] Add Watch SwiftUI: scan/connect, computer identity confirmation, pending account and computer display, `Allow login`, authentication success/failure, revoke/reset enrollment. Use a fresh noninteractive LAContext immediately before each signature; failures send no approval. Write the approval in contiguous <=20-byte frames with response.
- [ ] Generate Xcode project with XcodeGen; cloud workflow selects a stable macOS runner/Xcode, runs shared logic tests on macOS when possible and builds real iOS/watchOS device binaries with signing disabled. Package `Payload/Host.app/Watch/Watch.app` as an unsigned IPA. Check embedded executable/Info.plist/bundle links and arm64 target architecture before uploading. Record SDK versions and SHA256 sums. Do not embed account, signing secrets or profiles.
- [ ] Use standard runners, manual dispatch, a bounded timeout and short artifact retention. No paid services, certificate purchase or automated Apple-account login. Cloud execution requires a user-controlled writable repository.
- [ ] Run available static/package checks and cloud tests/build if authorized repository is available. Self-review and commit owned files; report separately what was executed and what needs physical-device evidence.

### Task 3: Windows GATT probe and boot service

**Files:** create `backend/crates/login-probe/{Cargo.toml,src/{main,transport,storage,service}.rs,tests/*}`, `scripts/{Build-Probe,Install-ProbeService,Remove-ProbeService}.ps1`; modify only workspace membership/lockfile outside this crate.

**Interfaces:** use auth crate types and shared GATT UUID/framing contract. CLI commands `doctor`, `serve`, `service`, `show-identity`, `trust-watch <public-key-file>`, `forget-watch`. No `enroll` or password parameters in this stage.

- [ ] Write real frame tests for partial payloads, duplicate/out-of-order offsets, cross-peer writes, total mismatch and >4096 bytes; write state tests for failed authorization, replay and expiry. Run failing tests before implementations.
- [ ] Implement GATT server with per-peer bounded transfers, Windows system RNG, signed `probe` requests and enrolled-key verification. Status messages must distinguish unpaired Watch from validated approval; never label a received arbitrary-key signature as trusted. Print fingerprints for local enrollment without exposing private keys.
- [ ] Implement durable computer identity protected by the running account's DPAPI plus ACL. Foreground data is per-user; service data is separate under ProgramData with SYSTEM-only runtime access and administrator-mediated enrollment. An installer copies only public Watch trust material, not another account's DPAPI blob. First start in each context generates its own key, which must be paired explicitly.
- [ ] Implement SCM automatic service mode with stop handling and no interactive UI. Admin scripts install to Program Files, protect data and configure service SID. Scripts refuse unexpected directories/reparse points and provide uninstall. They do not modify system Credential Provider or Windows autologon.
- [ ] Build/tests with portable local Rust/LLVM or Windows CI. Run `doctor` read-only; exercise foreground service using mock-free crypto tests. Do not install a boot service or reboot as a side effect of building.
- [ ] Self-review and commit. Report hardware Peripheral Role support and any operating-system access limitations honestly.

### Task 4: Review, package and physical validation handoff

**Files:** `docs/first-login-prototype.md`, `docs/validation-status.md`, output ZIP and checksums under the chat's outputs directory.

- [ ] Run the backend suite, new protocol vectors, formatting/static checks and any available Apple CI. Collect exact results and source commit.
- [ ] Review all changes for identity substitution, replay, secret leakage, malformed frames, enrollment changes and failure recovery. Resolve critical/important findings.
- [ ] Package source and Windows executable separately; exclude `.git`, tools, caches, private keys and real user data. Document free-account signing/install steps and renewal limitations.
- [ ] Record remaining physical checks: Watch install and launch; approved vs locked/removed states; GATT in a Windows startup-service session. Ask for only the user action necessary to perform those checks.

## Deferred until physical validation passes

Actual password registration, cross-session Provider changes and first-login submission are the next integration stage. The existing provider remains unchanged in this prototype. Its prerequisite is evidence that the target Watch can install/renew, run the noninteractive wrist policy, and reach the Windows prelogon GATT service. The deferred work is part of the overall goal, not claimed complete by this plan.
