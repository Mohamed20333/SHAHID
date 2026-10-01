# Android guide

Workflow:

1. Install the native Android app.
2. Sign in.
3. Enroll the device; the private Ed25519 key remains on-device.
4. Select an active session.
5. Complete the server challenge and cryptographic check-in.
6. Receive a session-scoped ephemeral BLE identifier.
7. Start the foreground evidence service.
8. Grant the Android Bluetooth/Nearby Devices permissions requested by the app.
9. Nearby SHAHID participants can produce signed witness observations.
10. Signed heartbeats provide continuity evidence.

The app does not silently enable Bluetooth. Android requires the relevant user permission/state handling.

Physical-device testing is required for radio behavior and background execution.
