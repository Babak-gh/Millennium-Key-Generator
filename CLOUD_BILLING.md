# Cloud billing reconciliation

The cloud owns cloud plans and manual payment records. Offline activation, permanent signatures, issuer limits and local panel verification are unchanged. A paid cloud purchase covers only matching features on its purchased panel. Quotas are activation limits and are never refunded by this integration.

Set `LICENSING_SERVICE_TOKEN` (the same random 32+ character server secret in both applications) and `CLOUD_LICENSING_URL=https://your-cloud-host`. On cloud set `LEGACY_LICENSING_URL=https://your-key-generator-host` and the same token. The Compose file passes these variables through. Proxy `/internal/` to the appropriate app; endpoints require the bearer token.

The super admin records a payment in cloud, looks up the paired panel's legacy licenses, and confirms matching coverage after checking panel and issuer. This service exposes only license metadata at `GET /internal/cloud/licenses?code=...`, never signing keys or license signatures. No network calls are added to activation.

Use **Export billing reconciliation (Bus + Zigbee)** from the Licenses screen when preparing collection. It checks live cloud coverage and produces three worksheets:

- All licenses, with settlement status and payment reference.
- Offline payment review: active licenses not covered by a cloud purchase. Check existing offline payments before billing; absence of cloud coverage is not proof of debt.
- Cloud review required: a matching cloud purchase exists but its license linkage needs administrator review. Hold these records out of collection.

A service outage, missing configuration, incomplete response, or invalid result aborts the report. The Base-only inventory export remains available and is explicitly not a bill. Record historical cloud receipts and reconcile them before the first collection run. Paid coverage survives cloud unpairing/home deletion, while a deliberate payment correction removes coverage without revoking any offline license.

For tests use `LICENSING_INSTANCE_PATH` pointing at a disposable absolute directory; it isolates both SQLite databases and the Zigbee signing key from real installations. The default instance path is unchanged.
