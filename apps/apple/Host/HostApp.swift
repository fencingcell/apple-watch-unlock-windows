// SPDX-License-Identifier: AGPL-3.0-only
import SwiftUI
import WatchConnectivity
import UniformTypeIdentifiers

@main
struct HostApp: App {
    @StateObject private var model = PublicEnrollment()
    var body: some Scene {
        WindowGroup {
            NavigationStack {
                Form {
                    Section("Authentication test prototype") {
                        Text("Open Login Test on your Watch. Compare both full fingerprints before enrolling. No Windows password is needed.")
                        Text("An unsigned build requires personal signing before installation. This app does not establish Windows login support.")
                    }
                    Section("Watch public enrollment information") {
                        Text(model.status)
                        if !model.key.isEmpty {
                            Text("SHA-256 fingerprint")
                            Text(model.fingerprint).font(.system(.footnote, design: .monospaced)).textSelection(.enabled)
                            Text("P-256 public key (X9.63)")
                            Text(model.key).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                            Button("Export public key file") { model.exporting = true }
                            Text("Compare this fingerprint directly on the Watch. Save the exported text file on Windows and compare again before confirming Windows enrollment.")
                        }
                    }
                }
                .navigationTitle("Watch Login Test")
                .fileExporter(isPresented: $model.exporting, document: PublicKeyFile(text: model.key), contentType: .plainText, defaultFilename: "watch-public-key") { result in
                    if case .failure = result { model.status = "Public key export failed. Try again." }
                }
            }
        }
    }
}

struct PublicKeyFile: FileDocument {
    static var readableContentTypes: [UTType] { [.plainText] }
    var text: String
    init(text: String) { self.text = text }
    init(configuration: ReadConfiguration) throws {
        text = String(data: configuration.file.regularFileContents ?? Data(), encoding: .utf8) ?? ""
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: Data((text + "\n").utf8)) }
}

@MainActor
final class PublicEnrollment: NSObject, ObservableObject, WCSessionDelegate {
    @Published var key = ""
    @Published var fingerprint = ""
    @Published var status = "Waiting for public enrollment information from your Watch."
    @Published var exporting = false
    override init() {
        super.init()
        guard WCSession.isSupported() else { status = "WatchConnectivity unavailable."; return }
        WCSession.default.delegate = self
        WCSession.default.activate()
    }
    private func receive(_ context: [String: Any]) {
        guard let candidate = context["watch_public_key"] as? String,
              let claimed = context["fingerprint"] as? String,
              let actual = try? WatchFingerprint(candidate), actual == claimed else {
            key = ""; fingerprint = ""; status = "No current Watch public key. Open Login Test on the Watch."; return
        }
        key = candidate; fingerprint = actual
        status = "Public information received. Confirm the current fingerprint on your Watch."
    }
    nonisolated func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: Error?) {
        let context = session.receivedApplicationContext
        Task { @MainActor in self.receive(context) }
    }
    nonisolated func session(_ session: WCSession, didReceiveApplicationContext applicationContext: [String: Any]) {
        Task { @MainActor in self.receive(applicationContext) }
    }
    nonisolated func sessionDidBecomeInactive(_ session: WCSession) {
        Task { @MainActor in self.key = ""; self.fingerprint = ""; self.status = "Watch session inactive." }
    }
    nonisolated func sessionDidDeactivate(_ session: WCSession) { session.activate() }
}

// Avoid a property/function name collision inside PublicEnrollment.
private func WatchFingerprint(_ key: String) throws -> String { try fingerprint(key) }
