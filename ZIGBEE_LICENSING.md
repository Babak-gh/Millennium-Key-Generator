# Zigbee Feature Licensing

This adds a permanent offline Zigbee entitlement alongside the existing Millennium Base license. The signed entitlement also records the purchased product capability so the Android app can distinguish Base, Full, and Zigbee-only installations.

## Commercial model

- `Issuer.allowed_licenses` remains the Base-license quota.
- `Issuer.allowed_zigbee_licenses` is the separate Zigbee-feature quota.
- A Base-only sale consumes one Base quota.
- A Full sale is one activation and atomically consumes one Base quota plus one Zigbee quota.
- A Zigbee-only sale consumes one Zigbee quota and creates no Base license. The app is enabled, but RS485/Bus hardware access is disabled.
- An existing Base customer can request Zigbee later. An administrator chooses which issuer owns the sale and whose Zigbee quota is consumed; the historical Base issuer does not need to be known in advance.

Existing issuers start with zero Zigbee quota so deployment cannot accidentally grant the new paid feature.

## Database migration and recovery

Startup performs an additive migration:

1. The existing SQLite file is backed up once as `instance/my_database.db.pre_zigbee_migration.bak`.
2. The existing `issuer` table receives `allowed_zigbee_licenses INTEGER NOT NULL DEFAULT 0`.
3. A separate `instance/zigbee_licenses.db` SQLite database is created with `zigbee_licenses` and `zigbee_license_requests` tables.
4. Existing Zigbee rows receive additive `base_issuer` and `license_type` columns and are preserved as `addon` licenses.

No existing table is replaced and no Base issuer or license row is rewritten. Startup makes one pre-workflow backup at `instance/zigbee_licenses.db.pre_workflow_migration.bak`. Issuance and approval use SQLite `ATTACH` transactions so all required quota decrements, license inserts, and request updates succeed or roll back together. Keep both SQLite databases and the Zigbee signing key in the normal backup process.

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

## New-product activation API

`POST /activate` accepts `license_type` with one of:

- `base` (the default, preserving compatibility with existing app versions)
- `full`, which also requires `coordinator_eui64`
- `zigbee_only`, which also requires `coordinator_eui64`

Full and Zigbee-only responses include the signed Zigbee entitlement. Repeating an identical Full or Zigbee-only activation restores the existing license without consuming quota again.

## Existing-Base upgrade API

`POST /zigbee/request` requires:

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

The server independently loads the active Base record and derives its historical Base issuer, owner, and project. The client cannot select a billing issuer.

For a first request, the endpoint creates a pending request and returns HTTP 202. It does not consume any quota. Repeating the same request checks its status. After approval, the same call returns the signed entitlement without consuming quota again. A request with a different coordinator is rejected and requires an administrative hardware-replacement procedure. `/zigbee/activate` remains for installed older app builds: it creates/checks the same request but returns a handled 409 message while pending, then returns the entitlement after approval. Deploy the server before distributing the new Android build.

## Signed entitlement

The compact signed entitlement includes:

- Issuer identity for the licensing service.
- Android device code.
- Feature name (`zigbee`).
- Coordinator EUI-64.
- Stable license ID.
- Product type (`addon`, `full`, or `zigbee_only`).
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
- A central verified capability gate records the effective product (`base`, `full`, `zigbee_only`, or `unlicensed`) for later UI filtering.
- Every `RS485Manager` hardware variant rejects both UART initialization and writes unless a valid Base license is present. A Zigbee-only entitlement therefore cannot operate Bus devices even though shared Bus/Zigbee screens remain visible for now.

Debug builds retain the project's existing `SKIP_LICENSE_CHECK` developer behavior. Release builds enforce Zigbee licensing.

## Administrative workflow

For a new customer, select Base, Full, or Zigbee-only in the normal registration dialog. Full performs one activation for both features.

For an existing Base customer:

1. On the panel, open Settings > General and select **Request Zigbee feature**.
2. The app reads the coordinator EUI-64 and sends the Base proof. The screen shows that approval is pending; tapping again checks status.
3. In the portal, open **Zigbee Requests**. Select the issuer responsible for this Zigbee sale and approve it.
4. Approval atomically consumes one Zigbee quota from that selected issuer and records both the historical Base issuer and billing issuer.
5. On the panel, tap **Check Zigbee request**. The app verifies and stores the entitlement.
6. Zigbee Manager becomes visible under Settings > Network. Zigbee Debug becomes visible in General Settings while technician mode is active.

The **Licenses**, **Zigbee Licenses**, **Issuers**, and **Zigbee Requests** screens are searchable. Issued entitlements remain visible in **Zigbee Licenses**.

Setting a Zigbee license inactive prevents online restoration but does not revoke an entitlement already stored on an offline panel. Supporting revocation would require a signed lease with an expiry and periodic renewal.

## Security boundary

The signed, device-and-coordinator-bound entitlement prevents copying or fabricating a Zigbee license in an unmodified release app. It also places the authorization check below the screens, at the common Zigbee connection path.

No check implemented only inside an offline Android APK can be made completely resistant to a determined attacker who patches and re-signs that APK. R8, tamper checks, native code, and certificate checks can increase the effort, but they cannot create a trustworthy enforcement boundary on a device controlled by the attacker.

The strongest future enforcement is in the coordinator firmware: provision the Zigbee public key in firmware, send the signed entitlement over UART, and make the coordinator itself reject network formation, permit-join, and Zigbee commands until it verifies an entitlement containing its own EUI-64. That also requires secure boot or locked firmware/debug access on the coordinator. The current entitlement format already contains the fields needed for that firmware verification, but coordinator-firmware work is outside these two repositories.
