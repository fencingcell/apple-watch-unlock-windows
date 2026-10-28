// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import Combine
import CoreBluetooth
import LocalAuthentication
import WatchConnectivity

// CoreBluetooth callbacks use the main queue. Authentication and WCSession
// callbacks explicitly re-enter that queue before touching protocol state.
final class WatchController: NSObject, ObservableObject, CBCentralManagerDelegate, CBPeripheralDelegate, WCSessionDelegate {
    struct Computer: Identifiable { let id: UUID; let name: String }
    private enum Phase { case idle, connecting, services, characteristics, control, reading, ready, authenticating, writing }
    private static let service = CBUUID(string: "4c23b2b0-5d5b-4b24-9c50-43320a1b0001")
    private static let requestID = CBUUID(string: "4c23b2b0-5d5b-4b24-9c50-43320a1b0002")
    private static let approvalID = CBUUID(string: "4c23b2b0-5d5b-4b24-9c50-43320a1b0003")
    private static let controlID = CBUUID(string: "4c23b2b0-5d5b-4b24-9c50-43320a1b0004")
    @Published var status = "Scan to start an authentication test."
    @Published var computers: [Computer] = []
    @Published var pending: SignedRequest?
    @Published var busy = false
    @Published var paired = false
    @Published var watchPublicKey = ""
    @Published var watchFingerprint = ""
    @Published var showReset = false
    private var central: CBCentralManager!
    private var discovered: [UUID: CBPeripheral] = [:]
    private var peripheral: CBPeripheral?
    private var requestCharacteristic: CBCharacteristic?
    private var approvalCharacteristic: CBCharacteristic?
    private var controlCharacteristic: CBCharacteristic?
    private var phase = Phase.idle
    private var active = false
    private var enrollment = Enrollment()
    private var frames = Frames()
    private var gate = ApprovalGate()
    private var authentication: LAContext?
    private var deadline: Timer?
    private var outgoing: [Data] = []
    private var outgoingIndex = 0
    private var outgoingExpiry: UInt64 = 0
    private var scanDeadline: Timer?
    private var now: UInt64 { UInt64(max(0, Date().timeIntervalSince1970 * 1000)) }

    override init() {
        super.init()
        central = CBCentralManager(delegate: self, queue: .main)
        if WCSession.isSupported() { WCSession.default.delegate = self; WCSession.default.activate() }
    }
    func setActive(_ value: Bool) {
        active = value
        if value {
            do { enrollment = try WatchKeychain.enrollment(); try loadPublicKey(); publishPublicKey() }
            catch { stop("Unlock the Watch to access its local pairing keys.") }
        } else { stop("Authentication cancelled because the app became inactive.") }
    }
    private func loadPublicKey() throws {
        let key = try WatchKeychain.signingKey()
        watchPublicKey = hex(key.publicKey.x963Representation)
        watchFingerprint = try fingerprint(watchPublicKey)
    }
    func publishPublicKey() {
        guard WCSession.isSupported(), WCSession.default.activationState == .activated else { return }
        do {
            try WCSession.default.updateApplicationContext(["watch_public_key": watchPublicKey, "fingerprint": watchFingerprint])
        } catch { status = "Public key could not be sent to iPhone. Compare it on this Watch." }
    }
    private func cancelPending() {
        authentication?.invalidate(); authentication = nil; gate.cancel()
        deadline?.invalidate(); deadline = nil
        pending = nil; paired = false; outgoing = []; outgoingIndex = 0; outgoingExpiry = 0
    }
    private func stop(_ message: String) {
        cancelPending(); phase = .idle; busy = false
        scanDeadline?.invalidate(); scanDeadline = nil; central?.stopScan()
        if let peripheral { central?.cancelPeripheralConnection(peripheral) }
        peripheral = nil; requestCharacteristic = nil; approvalCharacteristic = nil; controlCharacteristic = nil
        status = message
    }
    func scan() {
        guard active, central.state == .poweredOn else { status = "Enable Bluetooth and keep this app active."; return }
        stop("Scanning for the fixed authentication-test service…")
        discovered = [:]; computers = []
        central.scanForPeripherals(withServices: [Self.service], options: [CBCentralManagerScanOptionAllowDuplicatesKey: false])
        scanDeadline = Timer.scheduledTimer(withTimeInterval: 15, repeats: false) { [weak self] _ in
            self?.central.stopScan(); self?.status = "Scan finished. Select a computer or scan again."
        }
    }
    func connect(_ id: UUID) {
        guard active, let selected = discovered[id] else { return }
        stop("Connecting…")
        peripheral = selected; selected.delegate = self; phase = .connecting; busy = true
        central.connect(selected)
        deadline = Timer.scheduledTimer(withTimeInterval: 30, repeats: false) { [weak self] _ in self?.stop("Connection or challenge timed out. Start again.") }
    }
    private func fetchChallenge() {
        guard active, let peripheral, peripheral.state == .connected, let controlCharacteristic else { stop("Connection unavailable."); return }
        cancelPending(); phase = .control; busy = true; status = "Reading a fresh signed challenge…"
        deadline = Timer.scheduledTimer(withTimeInterval: 30, repeats: false) { [weak self] _ in self?.stop("Challenge expired. Start again.") }
        peripheral.writeValue(Data([1]), for: controlCharacteristic, type: .withResponse)
    }
    func confirmComputer() {
        guard active, phase == .ready, !busy, let pending else { return }
        do {
            try pending.validate(now: now)
            var updated = enrollment
            try updated.confirm(pending.computer_public_key, fingerprint: pending.request.computer_id)
            try WatchKeychain.store(Data(pending.computer_public_key.utf8), name: "computer-key")
            enrollment = updated
            // Explicit pairing never approves its current challenge.
            fetchChallenge()
        } catch { stop("Pairing failed or challenge expired. Start again and compare fingerprints.") }
    }
    func approve() {
        guard active, phase == .ready, !busy, paired, let frozen = pending,
              let peer = peripheral, peer.state == .connected, let enrolled = enrollment.key else { return }
        do {
            let token = try gate.begin(frozen, peer: peer.identifier, now: now, enrolled: enrolled)
            let context = LAContext()
            context.interactionNotAllowed = true
            authentication = context; phase = .authenticating; busy = true
            var error: NSError?
            guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithWristDetection, error: &error) else {
                stop("Wrist authentication unavailable. Unlock and wear the Watch, then start again."); return
            }
            context.evaluatePolicy(.deviceOwnerAuthenticationWithWristDetection, localizedReason: "Approve this authentication test") { [weak self] success, _ in
                DispatchQueue.main.async { self?.finishAuthentication(success, context: context, token: token, frozen: frozen, peer: peer) }
            }
        } catch { stop("Unpaired, invalid or expired challenge. Start again.") }
    }
    private func finishAuthentication(_ success: Bool, context: LAContext, token: UUID, frozen: SignedRequest, peer: CBPeripheral) {
        // A callback from a cancelled context cannot affect a later operation.
        guard authentication === context else { return }
        guard success, active, phase == .authenticating, peripheral === peer,
              peer.state == .connected, pending == frozen else { stop("Wrist authentication failed or was cancelled. No approval sent."); return }
        do {
            try enrollment.require(frozen.computer_public_key)
            let request = try gate.consume(token, peer: peer.identifier, now: now)
            // No await between the fresh wrist result, key read, signature and first write.
            let approval = try SignedApproval.make(request: request, key: WatchKeychain.signingKey())
            guard active, peripheral === peer, peer.state == .connected, now < request.expires_at_ms else { throw ProtocolError.stale }
            outgoing = try Frames.encode(JSONEncoder().encode(approval))
            outgoingIndex = 0; outgoingExpiry = request.expires_at_ms; phase = .writing
            context.invalidate(); authentication = nil; pending = nil; paired = false
            writeNext()
        } catch { stop("Approval cancelled, expired or key unavailable. No complete approval sent.") }
    }
    private func writeNext() {
        guard active, phase == .writing, let peripheral, peripheral.state == .connected,
              let approvalCharacteristic, now < outgoingExpiry else { stop("Approval transfer cancelled or expired."); return }
        guard outgoingIndex < outgoing.count else {
            stop("Signed authentication test delivered. Check the Windows verifier result."); return
        }
        peripheral.writeValue(outgoing[outgoingIndex], for: approvalCharacteristic, type: .withResponse)
    }
    func reset() {
        stop("Revoking local pairing…")
        watchPublicKey = ""; watchFingerprint = ""; enrollment = Enrollment(); publishPublicKey()
        do { try WatchKeychain.revoke(); try loadPublicKey(); publishPublicKey(); status = "New Watch key created. Revoke the old key on Windows and compare new fingerprints." }
        catch { status = "Reset failed. Unlock the Watch and retry; do not use the previous enrollment." }
    }
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state != .poweredOn { stop("Bluetooth unavailable or permission denied.") }
    }
    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard active, phase == .idle, discovered[peripheral.identifier] == nil, computers.count < 30 else { return }
        discovered[peripheral.identifier] = peripheral
        let name = peripheral.name ?? "Unnamed computer"
        computers.append(Computer(id: peripheral.identifier, name: String(name.prefix(40))))
    }
    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        guard active, self.peripheral === peripheral, phase == .connecting else { central.cancelPeripheralConnection(peripheral); return }
        phase = .services; peripheral.discoverServices([Self.service])
    }
    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        if self.peripheral === peripheral { stop("Connection failed. Start again.") }
    }
    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        if self.peripheral === peripheral { stop("Connection lost. Pending authentication cancelled.") }
    }
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard active, self.peripheral === peripheral, phase == .services else { return }
        guard error == nil, let service = peripheral.services?.first(where: { $0.uuid == Self.service }) else { stop("Required service unavailable."); return }
        phase = .characteristics
        peripheral.discoverCharacteristics([Self.requestID, Self.approvalID, Self.controlID], for: service)
    }
    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard active, self.peripheral === peripheral, phase == .characteristics, service.uuid == Self.service else { return }
        guard error == nil else { stop("Characteristic discovery failed."); return }
        requestCharacteristic = service.characteristics?.first { $0.uuid == Self.requestID && $0.properties.contains(.read) }
        approvalCharacteristic = service.characteristics?.first { $0.uuid == Self.approvalID && $0.properties.contains(.write) }
        controlCharacteristic = service.characteristics?.first { $0.uuid == Self.controlID && $0.properties.contains(.write) }
        guard requestCharacteristic != nil, approvalCharacteristic != nil, controlCharacteristic != nil,
              peripheral.maximumWriteValueLength(for: .withResponse) >= 20 else { stop("Required bounded read/write service unavailable."); return }
        fetchChallenge()
    }
    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        guard active, self.peripheral === peripheral else { return }
        guard error == nil else { stop("Transfer rejected. Start a fresh authentication test."); return }
        if phase == .control, characteristic === controlCharacteristic, let requestCharacteristic {
            frames.start(peer: peripheral.identifier, now: now); phase = .reading
            peripheral.readValue(for: requestCharacteristic)
        } else if phase == .writing, characteristic === approvalCharacteristic {
            outgoingIndex += 1; writeNext()
        }
    }
    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard active, self.peripheral === peripheral, phase == .reading, characteristic === requestCharacteristic else { return }
        do {
            guard error == nil, let frame = characteristic.value else { throw ProtocolError.invalid }
            if let data = try frames.append(frame, peer: peripheral.identifier, now: now) {
                let request = try JSONDecoder().decode(SignedRequest.self, from: data)
                try request.validate(now: now)
                guard request.request.purpose == "probe", request.request.account_sid == "S-1-0-0", request.request.account_name == "Authentication test" else { throw ProtocolError.invalid }
                pending = request; paired = (try? enrollment.require(request.computer_public_key)) != nil
                phase = .ready; busy = false
                status = paired ? "Check the signed account/computer, then allow the authentication test." : "Compare the full computer fingerprint before pairing."
            } else { peripheral.readValue(for: characteristic) }
        } catch { stop("Invalid, expired or malformed signed request. Nothing approved.") }
    }
    func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: Error?) {
        DispatchQueue.main.async { [weak self] in self?.publishPublicKey() }
    }
}
