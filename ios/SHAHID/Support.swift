import Foundation
import CryptoKit
import Security

enum Canonical {
    static func data(_ object: [String: Any]) -> Data {
        let sorted = object.keys.sorted().reduce(into: [String: Any]()) { $0[$1] = object[$1] }
        return (try? JSONSerialization.data(withJSONObject: sorted, options: [.sortedKeys, .withoutEscapingSlashes])) ?? Data()
    }
}

struct APIClient {
    let baseURL: String
    func send<T: Decodable>(_ path: String, token: String? = nil, body: [String: Any]? = nil) async throws -> T {
        guard let url = URL(string: baseURL + path) else { throw URLError(.badURL) }
        var request = URLRequest(url: url); request.httpMethod = body == nil ? "GET" : "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let token { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        if let body { request.httpBody = Canonical.data(body) }
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        guard (200..<300).contains(http.statusCode) else {
            let message = (try? JSONDecoder().decode(APIError.self, from: data))?.error ?? "HTTP \(http.statusCode)"
            throw NSError(domain: "SHAHID", code: http.statusCode, userInfo: [NSLocalizedDescriptionKey: message])
        }
        return try JSONDecoder().decode(T.self, from: data)
    }
}
struct APIError: Decodable { let error: String }

final class DeviceKeyStore {
    struct Identity { let privateKey: Curve25519.Signing.PrivateKey; var publicKey: Curve25519.Signing.PublicKey { privateKey.publicKey } }
    private let tag = "com.shahid.device.ed25519"
    func getOrCreate() throws -> Identity {
        if let data = readKey() { return try Identity(privateKey: Curve25519.Signing.PrivateKey(rawRepresentation: data)) }
        let key = Curve25519.Signing.PrivateKey()
        try saveKey(key.rawRepresentation)
        return Identity(privateKey: key)
    }
    private func readKey() -> Data? {
        let query: [String: Any] = [kSecClass as String:kSecClassKey,kSecAttrApplicationTag as String:tag,kSecReturnData as String:true,kSecAttrAccessible as String:kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        var item: CFTypeRef?; SecItemCopyMatching(query as CFDictionary, &item)
        return item as? Data
    }
    private func saveKey(_ data: Data) throws {
        let query: [String: Any] = [kSecClass as String:kSecClassKey,kSecAttrApplicationTag as String:tag,kSecValueData as String:data,kSecAttrAccessible as String:kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else { throw NSError(domain:"SHAHID", code:Int(status), userInfo:[NSLocalizedDescriptionKey:"Keychain write failed"]) }
    }
}

final class BLEEvidenceController: NSObject, ObservableObject, CBCentralManagerDelegate, CBPeripheralManagerDelegate {
    weak var model: AppModel?
    private var central: CBCentralManager!
    private var peripheral: CBPeripheralManager!
    private var sessionId = ""; private var token = ""; private var deviceId = ""; private var ownEphemeral = ""
    private var seen = Set<String>()
    private let serviceUUID = CBUUID(string: "D9F3A100-7A8B-4B3A-9F2C-7B9F2E4A1001")
    init(model: AppModel) { self.model = model; super.init(); central = CBCentralManager(delegate:self, queue:.main); peripheral = CBPeripheralManager(delegate:self, queue:.main) }
    func start(sessionId:String, token:String, deviceId:String, ephemeralId:String) {
        self.sessionId=sessionId; self.token=token; self.deviceId=deviceId; self.ownEphemeral=ephemeralId
        guard peripheral.state == .poweredOn else { return }
        let data = ownEphemeral.data(using:.utf8) ?? Data()
        peripheral.startAdvertising([CBAdvertisementDataServiceUUIDsKey:[serviceUUID],CBAdvertisementDataServiceDataKey:[serviceUUID:data]])
        central.scanForPeripherals(withServices:[serviceUUID], options:[CBCentralManagerScanOptionAllowDuplicatesKey:false])
    }
    func stop() { central.stopScan(); peripheral.stopAdvertising() }
    func centralManagerDidUpdateState(_ central: CBCentralManager) { if central.state == .poweredOn { } }
    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) { if peripheral.state == .poweredOn, !ownEphemeral.isEmpty { start(sessionId:sessionId,token:token,deviceId:deviceId,ephemeralId:ownEphemeral) } }
    func centralManager(_ central:CBCentralManager,didDiscover peripheral:CBPeripheral,advertisementData:[String:Any],rssi RSSI:NSNumber) {
        guard let values = advertisementData[CBAdvertisementDataServiceDataKey] as? [CBUUID:Data], let data = values[serviceUUID], let ephemeral=String(data:data,encoding:.utf8), !ephemeral.isEmpty, !seen.contains(ephemeral), ephemeral != ownEphemeral else { return }
        seen.insert(ephemeral)
        Task { await submitWitness(ephemeral:ephemeral,rssi:RSSI.intValue) }
    }
    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: Error?) {}
    private func submitWitness(ephemeral:String,rssi:Int) async {
        guard let model, let token=model.token else { return }
        do {
            let challenge: WitnessChallenge = try await APIClient(baseURL:model.apiBase).send("/sessions/\(sessionId)/witness-challenge", token:token, body:nil)
            let timestamp=ISO8601DateFormatter().string(from:Date())
            let key=try DeviceKeyStore().getOrCreate()
            let payload=Canonical.data(["ephemeralId":ephemeral,"nonce":challenge.nonce,"observerDeviceId":deviceId,"observationType":"ble_proximity","protocolVersion":"1","rssi":rssi,"sessionId":sessionId,"timestamp":timestamp])
            let sig=try key.privateKey.signature(for:payload)
            let _: EmptyResponse = try await APIClient(baseURL:model.apiBase).send("/sessions/\(sessionId)/witnesses",token:token,body:["rssi":rssi,"challengeId":challenge.challengeId,"signature":sig.base64EncodedString(),"timestamp":timestamp,"observationType":"ble_proximity","protocolVersion":"1","ephemeralId":ephemeral])
        } catch { await MainActor.run { model.status = "Witness: \(error.localizedDescription)" } }
    }
}
struct WitnessChallenge: Decodable { let challengeId:String; let nonce:String }
