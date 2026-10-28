// SPDX-License-Identifier: AGPL-3.0-only
import SwiftUI

@main
struct WatchLoginApp: App {
    @StateObject private var model = WatchController()
    @Environment(\.scenePhase) private var scenePhase
    var body: some Scene {
        WindowGroup {
            NavigationStack {
                List {
                    Section("Authentication test") {
                        Text(model.status)
                        Button("Scan for computers") { model.scan() }.disabled(model.busy)
                        ForEach(model.computers) { computer in
                            Button(computer.name) { model.connect(computer.id) }.disabled(model.busy)
                        }
                    }
                    if let pending = model.pending {
                        Section("Signed request") {
                            Text(pending.request.computer_name)
                            Text(pending.request.account_name)
                            Text(pending.request.account_sid).font(.caption2)
                            Text("Session \(pending.request.session_id)").font(.caption2)
                            if !model.paired {
                                Text("Compare ALL characters with the computer's displayed SHA-256 fingerprint:")
                                Text(pending.request.computer_id).font(.system(.caption2, design: .monospaced))
                                Text("A new or changed key needs explicit comparison. Confirm only if they match.")
                                Button("Fingerprints match — pair computer") { model.confirmComputer() }.disabled(model.busy)
                            } else {
                                Button("Allow authentication test") { model.approve() }.disabled(model.busy)
                            }
                        }
                    }
                    Section("Watch enrollment") {
                        Text("Compare this full fingerprint on Windows before confirming enrollment.")
                        Text(model.watchFingerprint).font(.system(.caption2, design: .monospaced))
                        Text("Public key")
                        Text(model.watchPublicKey).font(.system(.caption2, design: .monospaced))
                        Button("Send public key to iPhone") { model.publishPublicKey() }
                        Button("Revoke pairing and reset key", role: .destructive) { model.showReset = true }
                    }
                    Section { Text("This tests authentication only. Windows login and cold-boot support require separate validation.").font(.caption2) }
                }
                .navigationTitle("Login Test")
                .confirmationDialog("Revoke this Watch key and computer pairing? Re-enroll the new key on Windows.", isPresented: $model.showReset) {
                    Button("Revoke and reset", role: .destructive) { model.reset() }
                }
            }
            .onChange(of: scenePhase) { model.setActive($0 == .active) }
            .onAppear { model.setActive(scenePhase == .active) }
        }
    }
}
