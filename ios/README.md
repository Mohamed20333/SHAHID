# SHAHID iOS

Native SwiftUI/CoreBluetooth student client.

## Requirements

- Xcode 16+ / current supported Xcode
- iOS 16+
- Physical iPhone for BLE validation
- A reachable SHAHID HTTPS API

## Implemented workflow

Login -> Keychain Ed25519 identity -> server enrollment challenge -> signed enrollment -> session challenge -> signed cryptographic check-in -> session-scoped BLE advertising/scanning -> signed witness observations.

The app intentionally does not claim unrestricted background BLE. iOS controls background execution and CoreBluetooth behavior. Physical-device validation is required before claiming continuous background evidence collection.

For local LAN development, use an HTTPS endpoint reachable from the iPhone. Do not use production credentials in a development build.
