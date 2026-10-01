# SHAHID Privacy Model

SHAHID processes identity, attendance, device and proximity evidence for attendance-integrity review.

## Data minimization
- BLE identifiers should be ephemeral.
- No continuous GPS tracking is required.
- Cryptographic private keys remain on the Android device.
- RSSI is stored as noisy proximity evidence, not as a location coordinate.

## Access
Students can access their own attendance context. Professors can access sessions they own. Administrators receive only the management access required by role.

## Retention
Deployments must configure an explicit retention period for raw proximity observations and audit records. The reference implementation does not silently claim a universal legal retention period.

## Human review
Risk assessments are review assistance. SHAHID must not automatically label a student as cheating or impose disciplinary action.

## Limitations
Cryptographic device identity does not prove that a human was physically holding the device. BLE does not provide deterministic physical presence proof.
