# Zigbee Feature Licensing

This licensing path is independent of the existing Millennium Base activation. It adds a permanent offline Zigbee entitlement for an already Base-licensed panel and its embedded UART coordinator.

## Commercial model

- `Issuer.allowed_licenses` remains the Base-license quota.
- `Issuer.allowed_zigbee_licenses` is the separate Zigbee-feature quota.
- A Base-only sale consumes one Base quota.
- A Full sale consumes one Base quota and, when Zigbee is requested, one Zigbee quota.
- An existing Base customer can request Zigbee later if the Base license's issuer has Zigbee quota available.

Existing issuers start with zero Zigbee quota so deployment cannot accidentally grant the new paid feature.

## Database migration and recovery

Startup performs an additive migration:

1. The existing SQLite file is backed up once as `instance/my_database.db.pre_zigbee_migration.bak`.
2. The existing `issuer` table receives `allowed_zigbee_licenses INTEGER NOT NULL DEFAULT 0`.
3. A separate `instance/zigbee_licenses.db` SQLite database is created with its own `zigbee_licenses` table.

No existing table is replaced and no Base issuer or license row is rewritten. Issuance uses one SQLite `ATTACH` transaction so decrementing the Zigbee quota in the Base database and inserting the entitlement in the Zigbee database succeed or roll back together. Keep both SQLite databases and the Zigbee signing key in the normal backup process.

## Signing key

Zigbee entitlements use a dedicated 3072-bit RSA key. By default it is generated once and persisted at:

```text
/app/instance/zigbee_license_private.pem
```

The existing Docker volume persists this path. A custom mounted-secret path can be supplied with:

```text
ZIGBEE_LICENSE_PRIVATE_KEY_PATH=/run/secrets/zigbee_license_private.pem
```

The private key must never be committed or copied to the Android app. Losing it prevents reliable reissue after an app reinstall, so it must be backed up securely.

## Activation API

`POST /zigbee/activate` requires:

- A fresh device-bound access JWT in `Authorization`.
- The Android device code.
- The coordinator EUI-64 read directly over UART.
- The locally stored Base-license signature as proof of an active Base installation.

Example body:

```json
{
  "code": "android-device-id",
  "coordinator_eui64": "00124B0001ABCDEF",
  "base_license": "base64-base-license-signature"
}
```

The server independently loads the active Base record and derives its issuer, owner, and project. The client cannot select a different issuer for Zigbee activation.

For a first request, the endpoint atomically consumes one Zigbee quota and creates a `zigbee_licenses` row. A repeated request for the same panel and coordinator returns the existing entitlement without consuming quota. A request with a different coordinator is rejected and requires an administrative hardware-replacement procedure.

## Signed entitlement

The compact signed entitlement includes:

- Issuer identity for the licensing service.
- Android device code.
- Feature name (`zigbee`).
- Coordinator EUI-64.
- Stable license ID.
- Issue time.
- Schema version.
- Signing-key ID.

It deliberately has no expiry, preserving offline operation after activation.

## Android enforcement

The Android app stores the Zigbee entitlement and public key separately from the existing Base license using encrypted preferences. It verifies the RSA signature and device binding before exposing licensed UI.

Enforcement is applied at multiple layers:

- Settings > Network hides Zigbee Manager without a valid entitlement.
- Direct navigation to Zigbee Manager or Zigbee Debug is rejected.
- Zigbee Debug remains technician-only and additionally requires the entitlement.
- `ZigbeeManager.ensureConnected()` verifies both the device and the currently connected coordinator EUI-64 before normal Zigbee operations.
- The coordinator can be connected only through a special identity-reading path before activation; network formation and normal feature operations remain blocked.

Debug builds retain the project's existing `SKIP_LICENSE_CHECK` developer behavior. Release builds enforce Zigbee licensing.

## Administrative workflow

1. As an administrator, open the **Zigbee Quotas** screen and assign the purchased Zigbee quota. Ordinary issuer accounts cannot alter this quota.
2. Ensure the panel already has an active Base license.
3. On the panel, open Settings > General and select **Request Zigbee feature**.
4. The app reads the coordinator EUI-64, requests the entitlement, verifies it, and stores it.
5. Zigbee Manager becomes visible under Settings > Network. Zigbee Debug becomes visible in General Settings while technician mode is active.
6. Issued entitlements are visible in the separate **Zigbee Licenses** admin screen.

Setting a Zigbee license inactive prevents online restoration but does not revoke an entitlement already stored on an offline panel. Supporting revocation would require a signed lease with an expiry and periodic renewal.

## Security boundary

The signed, device-and-coordinator-bound entitlement prevents copying or fabricating a Zigbee license in an unmodified release app. It also places the authorization check below the screens, at the common Zigbee connection path.

No check implemented only inside an offline Android APK can be made completely resistant to a determined attacker who patches and re-signs that APK. R8, tamper checks, native code, and certificate checks can increase the effort, but they cannot create a trustworthy enforcement boundary on a device controlled by the attacker.

The strongest future enforcement is in the coordinator firmware: provision the Zigbee public key in firmware, send the signed entitlement over UART, and make the coordinator itself reject network formation, permit-join, and Zigbee commands until it verifies an entitlement containing its own EUI-64. That also requires secure boot or locked firmware/debug access on the coordinator. The current entitlement format already contains the fields needed for that firmware verification, but coordinator-firmware work is outside these two repositories.
