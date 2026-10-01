import SwiftUI
import CoreBluetooth

@main
struct SHAHIDApp: App {
    @StateObject private var model = AppModel()
    var body: some Scene {
        WindowGroup { ContentView().environmentObject(model) }
    }
}

final class AppModel: ObservableObject {
    @Published var apiBase = UserDefaults.standard.string(forKey: "apiBase") ?? "http://localhost:8080"
    @Published var email = ""
    @Published var password = ""
    @Published var token: String?
    @Published var role = ""
    @Published var fullName = ""
    @Published var deviceId: String?
    @Published var sessionId: String?
    @Published var ephemeralId: String?
    @Published var status = "Signed out"
    @Published var isEvidenceActive = false

    private let keyStore = DeviceKeyStore()
    private lazy var ble = BLEEvidenceController(model: self)

    func login() async {
        do {
            let response: LoginResponse = try await APIClient(baseURL: apiBase).send("/auth/login", body: ["email": email, "password": password])
            token = response.accessToken; role = response.role
            let me: MeResponse = try await APIClient(baseURL: apiBase).send("/me", token: response.accessToken)
            fullName = me.fullName
            UserDefaults.standard.set(apiBase, forKey: "apiBase")
            status = "Authenticated"
        } catch { status = error.localizedDescription }
    }

    func enrollDevice() async {
        guard let token else { status = "Login first"; return }
        do {
            let key = try keyStore.getOrCreate()
            let keyId = Canonical.keyId(key.publicKey.rawRepresentation)
            let challenge: EnrollmentChallenge = try await APIClient(baseURL: apiBase).send("/devices/enroll/challenge", token: token, body: ["publicKey": "-----BEGIN PUBLIC KEY-----\\n\\(Canonical.spki(key.publicKey.rawRepresentation).base64EncodedString())\\n-----END PUBLIC KEY-----", "keyId": keyId])
            let signature = try key.privateKey.signature(for: Canonical.data(["challengeId": challenge.challengeId, "keyId": challenge.keyId, "nonce": challenge.nonce, "purpose": "device_enrollment"]))
            let result: DeviceResponse = try await APIClient(baseURL: apiBase).send("/devices/enroll/complete", token: token, body: ["challengeId": challenge.challengeId, "signature": signature.base64EncodedString()])
            deviceId = result.deviceId
            UserDefaults.standard.set(result.deviceId, forKey: "deviceId")
            status = "Device enrolled"
        } catch { status = error.localizedDescription }
    }

    func loadDevice() { deviceId = UserDefaults.standard.string(forKey: "deviceId") }

    func checkIn() async {
        guard let token, let deviceId else { status = "Enroll device first"; return }
        guard let sessionId else { status = "Select a session"; return }
        do {
            let key = try keyStore.getOrCreate()
            let challenge: ProofChallenge = try await APIClient(baseURL: apiBase).send("/devices/proof-challenge", token: token, body: ["deviceId": deviceId, "sessionId": sessionId])
            let timestamp = ISO8601DateFormatter().string(from: Date())
            let signature = try key.privateKey.signature(for: Canonical.data(["challengeId": challenge.challengeId, "deviceId": deviceId, "nonce": challenge.nonce, "sessionId": sessionId, "timestamp": timestamp]))
            let _: EmptyResponse = try await APIClient(baseURL: apiBase).send("/sessions/\(sessionId)/check-in", token: token, body: ["deviceId": deviceId, "challengeId": challenge.challengeId, "signature": signature.base64EncodedString(), "timestamp": timestamp])
            let beacon: BeaconResponse = try await APIClient(baseURL: apiBase).send("/sessions/\(sessionId)/beacon", token: token, body: ["deviceId": deviceId])
            ephemeralId = beacon.ephemeralId
            isEvidenceActive = true
            ble.start(sessionId: sessionId, token: token, deviceId: deviceId, ephemeralId: beacon.ephemeralId)
            status = "Checked in; BLE evidence active"
        } catch { status = error.localizedDescription }
    }

    func stopEvidence() { ble.stop(); isEvidenceActive = false; status = "Evidence service stopped" }
}

struct ContentView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        NavigationStack {
            Form {
                Section("Connection") {
                    TextField("API URL", text: $model.apiBase).textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField("Email", text: $model.email).textInputAutocapitalization(.never).autocorrectionDisabled()
                    SecureField("Password", text: $model.password)
                    Button("Sign in") { Task { await model.login() } }
                }
                Section("Device") {
                    Text(model.fullName.isEmpty ? "Not authenticated" : model.fullName)
                    Button("Enroll / restore device") { Task { await model.enrollDevice() } }
                    Text(model.deviceId.map { "Device: \($0)" } ?? "No enrolled device")
                }
                Section("Attendance") {
                    TextField("Session ID", text: Binding(get: { model.sessionId ?? "" }, set: { model.sessionId = $0 }))
                    Button("Cryptographic check-in") { Task { await model.checkIn() } }
                    Button(model.isEvidenceActive ? "Stop evidence" : "Evidence inactive") {
                        if model.isEvidenceActive { model.stopEvidence() }
                    }.disabled(!model.isEvidenceActive)
                }
                Section("Status") {
                    Text(model.status)
                    Text(model.isEvidenceActive ? "BLE evidence: ACTIVE" : "BLE evidence: INACTIVE")
                        .foregroundStyle(model.isEvidenceActive ? .green : .secondary)
                }
            }
            .navigationTitle("SHAHID")
            .task { model.loadDevice() }
        }
    }
}

struct LoginResponse: Decodable { let accessToken: String; let role: String }
struct MeResponse: Decodable { let id: String; let role: String; let fullName: String; let email: String }
struct EnrollmentChallenge: Decodable { let challengeId: String; let nonce: String; let keyId: String }
struct ProofChallenge: Decodable { let challengeId: String; let nonce: String }
struct DeviceResponse: Decodable { let deviceId: String; let keyId: String; let algorithm: String }
struct BeaconResponse: Decodable { let sessionId: String; let deviceId: String; let ephemeralId: String; let expiresAt: String }
struct EmptyResponse: Decodable {}
