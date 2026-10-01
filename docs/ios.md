# iOS guide

The iOS client is native SwiftUI/CoreBluetooth.

Security:

- Ed25519-compatible signing through CryptoKit's Curve25519.Signing API.
- Private key stored in Keychain.
- Server challenge-response for enrollment and check-in.
- Session-scoped BLE identifier.
- Signed witness observations.

Bluetooth:

- CoreBluetooth central + peripheral roles are used.
- The app declares the Bluetooth privacy usage description.
- Background BLE execution is subject to iOS platform rules.
- Continuous background operation is not guaranteed by this repository.

A physical iPhone must be used to validate actual advertising/scanning behavior before deployment.
