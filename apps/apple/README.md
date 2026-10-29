# Apple authentication-test prototype

This iPhone host embeds a watchOS 9+ single-target Watch application. The Watch
connects directly to the computer's fixed BLE service. The iPhone receives only
public enrollment information through WatchConnectivity and exports the public
key as a plain text file. No private key leaves the Watch, and neither app asks
for a Windows account password.

On a Mac with Xcode and XcodeGen, run `swift test --package-path apps/apple`,
`python3 -m unittest discover -s apps/apple/Tests -p test_package.py`, then
`bash scripts/Build-Apple.sh` from the repository root. The GitHub workflow uses
the macos-26 runner's selected stable Xcode and records its exact version/SDKs.

The build script creates unsigned **device** binaries and packages
`Payload/Host.app/Watch/Watch.app` in `build/apple/artifacts/WatchLogin-unsigned.ipa`.
It verifies executable existence, arm device architectures, application product
types, platforms and companion bundle identities before packaging. Watch device
architectures may be arm64 or arm64_32 according to the installed Watch SDK;
the iPhone executable must be arm64. SDK/tool versions, build log, package report
and SHA-256 sums accompany the IPA. Synthetic protocol keys are test inputs only
and are not copied into either application's sources or resources.

An unsigned IPA cannot be directly installed. Personal signing and installation
on a paired iPhone/Watch require a suitable user-operated signing/install tool.
This repository does not automate Apple-account sign-in or require paid services.
Free-account installation/weekly renewal and compatibility with a particular
iOS/watchOS release must be validated on the user's devices. The cloud build does
not prove installation, wearer authentication, Windows login or cold-boot login.

1. Start the computer's authentication-test BLE server and show its full public
   key fingerprint. Open Login Test on an unlocked Watch worn on your wrist.
2. Scan and select a computer. Its discovery name is not an authenticated identity.
   Compare every character of the signed computer fingerprint with the computer's
   display; confirm pairing only when all characters match. Pairing discards the
   current challenge and fetches a separate fresh challenge.
3. Compare the Watch's full fingerprint on Windows. The iPhone can export its
   public key to a `.txt` file; transfer that file to Windows and explicitly
   confirm the matching fingerprint there. Received public information alone
   does not establish trusted enrollment.
4. Check the signed computer/account/session, then press Allow authentication test.
   A new noninteractive wrist-detection LocalAuthentication context is evaluated
   immediately before signing. Locked, removed, unavailable, expired or cancelled
   states fail without an approval. No interactive fallback exists.
5. Revoke pairing and reset key on the Watch to delete its local computer pin and
   rotate its signing identity. Revoke the old Watch key separately on Windows;
   deleting a Watch key cannot remotely delete Windows enrollment. Re-enroll and
   compare the new fingerprints before another test.

The Watch pins one computer key at a time in its local Keychain. Key changes
always require explicit comparison. App inactivity, connection loss, a fresh
challenge and reset invalidate pending authentication. Requests are bounded to
30 seconds, framing is contiguous and bounded, and received request signatures
bind the protocol version, purpose, computer identity, SID, session, nonce, expiry
and displayed names. The prototype accepts only `probe` / `S-1-0-0` /
`Authentication test`; it never represents a successful BLE write as Windows
login. Windows must verify and consume the signed approval independently.

Physical device validation remains required: signing/install/renewal, Bluetooth
permissions/discovery/transfers, fingerprint comparisons/key export, watch removal
and lock/passcode behavior, inactive-scene/disconnection/expiry cancellation,
changed-key confirmation and Windows verifier round trip. Record these states
separately from compilation.
