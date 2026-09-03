# Millennium License Activation Review

Reviewed: 2026-09-02

License service: `Millennium-Key-Generator`, `main` at `70b4f9c`
Android client: `../smart-home`, `feature/zigbee` at `ac14f1a`

## Purpose and intended model

The service provides license activation for Millennium Android installations distributed outside Google Play. Its current model is:

1. An administrator creates an issuer and assigns it an activation quota.
2. A release build of Millennium derives a device code from Android's `ANDROID_ID`.
3. An unlicensed installation connects to the service, obtains a JWT, and downloads the service's RSA public key.
4. The installer supplies an issuer, owner, project, and whether the installation is new.
5. The service validates the issuer and quota, signs the device code, records the activation, and decrements the quota.
6. The app stores the signature and public key in encrypted preferences.
7. Future launches verify the signature locally, allowing the app to operate without an Internet connection.

This is therefore a **one-time online activation followed by offline verification**, rather than a continuously connected entitlement system.

## Components

### License service

The Flask application in `app.py` provides:

- Admin login and management of users, issuers, licenses, and application versions.
- `POST /register_device` for issuing access and refresh JWTs.
- `GET /public_key` for returning the current RSA public key.
- `POST /activate` for creating or updating a license and returning a signature.
- `POST /is_active` for reading the database activation flag.
- A legacy-device lookup using `past.csv`.
- Excel export of license records.
- APK version and download endpoints.
- A release webhook for adding version records.

The SQLite database is stored under `instance/` and persisted by the Docker volume configured in `docker-compose.yml`.

### Millennium Android client

The Android client uses the following main pieces:

- `DeviceUtil.getUniqueID()` obtains `Settings.Secure.ANDROID_ID`.
- `MainActivity` controls the registration dialogs and license gate.
- `AuthRepositoryImp` requests and caches the JWT.
- `RegistrationRepositoryImp` downloads the public key and requests activation.
- `SecureLicenseStorage` stores the public key and signature using `EncryptedSharedPreferences` and verifies `SHA256withRSA` signatures.
- Release builds enforce the check; debug builds set `SKIP_LICENSE_CHECK=true`.

## Detailed activation flow

### First launch without a license

1. `MainActivity.checkLicense()` obtains the Android ID and checks encrypted preferences.
2. If no signature is stored, the app displays the device ID.
3. The app posts the ID to `/register_device` and receives:
   - A 60-minute access token.
   - A 20-day refresh token.
4. The app sends the access token to `/public_key` and stores the returned public key.
5. The registration form collects `issuer`, `owner`, `project`, and `new`.
6. The app sends those values and the device code to `/activate`.
7. The service checks the issuer and available quota.
8. The service signs the exact device-code string with RSA PKCS#1 v1.5 and SHA-256.
9. The service inserts or updates the license record, decrements the issuer quota, and returns the Base64 signature as `encrypted_license`.
10. The app stores the signature and immediately verifies it with the downloaded public key.
11. A successful verification sets `isRegistered=true` and unlocks the application.

Despite the response field name, `encrypted_license` is a digital signature, not encrypted license data.

### Later launches

The app reads the stored signature and public key and verifies the signature over the current Android ID. No server request is required. Consequently, temporary Internet or service outages do not prevent an already activated installation from starting.

### Legacy-device path

The registration form defaults `new` to true. When it is false, the service checks the first nine characters of the device code against `past.csv`. A match sets `is_manual_license=true`, which permits the activation path even when an active database record already exists. The issuer quota is still decremented.

## Findings

### Critical: the RSA signing key is ephemeral

`app.py` generates a new RSA key pair whenever the application process starts:

```python
private_key = RSA.generate(2048)
public_key = private_key.publickey()
```

The key is not stored in the database, Docker volume, a secret manager, or a mounted file. Therefore:

- Every container or process restart creates a different signing authority.
- A license stored in the database cannot be verified using a newly generated public key.
- Clearing app data or reinstalling the app can make recovery impossible for an already-active device.
- Running multiple application workers or replicas would let different requests use different key pairs.
- A restart between downloading the public key and requesting activation can make the returned signature fail immediately.

An already activated client retains its old public key and can continue verifying its stored signature, provided its application data is not lost.

### Critical: activation authorization is not connected to a purchase

`/register_device` accepts any caller-supplied device code and issues a signed JWT without authenticating the caller. `/activate` then treats possession of a valid JWT and knowledge of an issuer name as sufficient authorization.

There is no unique activation key, order identifier, customer credential, issuer secret, reseller session, or server-side pending entitlement. A caller who knows or guesses an issuer name can consume that issuer's quota.

### Critical: JWTs are not bound to the requested device

The access token includes a `device_id`, but `token_required` only checks whether the token is cryptographically valid and unexpired. It does not compare the token's `device_id` with the `code` in `/activate` or `/is_active`.

A token obtained for one value can therefore authorize a request concerning another device code. Access and refresh tokens also have no token-type claim, so a refresh token can be accepted by endpoints protected with `token_required`.

### High: revocation is not enforced by the app

The service exposes `/is_active`, and the admin can set a license to inactive. However, the Android call to `registrationViewModel.isActivated(uuid)` is commented out and the normal launch path only performs local signature verification.

Once activated, an installation remains usable even when its database record is deactivated. This may be acceptable for permanent offline licenses, but it means the current `is_active` field is not an effective revocation mechanism.

### High: legitimate reinstall and recovery are unreliable

Uninstalling or clearing application data removes the stored signature and public key. `ANDROID_ID` can remain the same for an app signed with the same signing key. When the client asks to activate again, the service normally responds with `Already activated` instead of safely returning or reissuing the existing entitlement.

A factory reset or other Android-ID change has the opposite problem: the same physical unit appears to be a new device and can consume another quota unit.

### High: a license is not bound to a Millennium edition

The signed payload contains only the device code. It does not contain the application flavor, package version, issuer, owner, project, issue time, expiry, or license identifier.

The `basic`, `pro`, `pro7`, and `advance` flavors share the same application ID. A stored device signature can therefore remain valid after installing another flavor signed with the same Android signing certificate. The database metadata does not affect client-side verification.

### High: authenticated non-admin users can change issuer quotas

`IssuerAdmin` inherits from `AuthenticatedModelView`, not `AdminOnlyModelView`. Any authenticated user can access issuer records and edit `allowed_licenses`, including increasing quotas. This bypasses the intended commercial quota control unless every authenticated account is fully trusted as an administrator.

### High: license export is not restricted to administrators

The License admin page is admin-only, but `/admin/license/export_excel` is protected only by `@login_required`. A non-admin authenticated user who calls the URL directly can export every license, including customer metadata and signature data.

### Medium: token expiry recovery is incomplete

The client receives a refresh token but never stores or uses it. `AuthRepositoryImp` caches the access token for the lifetime of the process and does not replace it when it expires. A later protected request can fail until the app process is restarted, and the repository does not automatically retry after a 401 or 403 response.

### Medium: the public key is learned at activation time

The app downloads and trusts the public key from the same service that returns the license. HTTPS protects this under normal conditions, but the public key is not pinned or embedded in the APK. The initial trust decision therefore depends completely on the TLS connection and device trust store.

A stable verification public key embedded in the release APK would create a clearer trust anchor. Key rotation would then require an explicit, signed migration strategy.

### Medium: quota updates can race

The service reads `allowed_licenses`, creates a license, decrements the quota, and commits without an atomic conditional update or explicit locking. Concurrent activations can observe the same remaining quota and can produce over-allocation, uniqueness errors, or database-locking failures.

The quota check also rejects only exactly zero; a negative quota remains eligible for activation.

### Medium: sensitive HTTP bodies are logged by the release client

The Android `HttpLoggingInterceptor` is configured at `BODY` level for all builds. Registration requests and responses can therefore log JWTs, device identifiers, owner/project data, public keys, and license signatures. Release builds should normally disable body logging.

### Medium: unsafe fallback secrets

The service has known fallback values for the Flask secret, JWT secret, admin password, and release-webhook secret. `docker-compose.yml` supplies the first three environment variables but does not supply `WEBHOOK_SECRET`, so the webhook uses its source-code default unless deployment configuration adds it separately.

Production startup should fail when required secrets are missing instead of silently using defaults.

### Medium: admin credential management is incomplete

The initial administrator password is hashed correctly. However, `UserAdmin` exposes the password field directly and has no create/update hook that hashes a newly entered password. Creating or editing users through Flask-Admin can therefore store plaintext or otherwise unusable password values.

The login form also has no visible CSRF protection or rate limiting.

### Low: input validation and error handling are limited

Examples include:

- `/activate` can call `len(code)` before validating that `code` exists.
- `issuer`, `owner`, and `project` have no explicit format or length validation before database work.
- Some Android repository operations force nullable response bodies with `!!`, which can crash on unexpected responses.
- The raw server error body is displayed to the user.
- Repeated observation registration inside dialog button handlers can accumulate observers across attempts.

### General limitation: APK-side enforcement can be patched

The verification design prevents copying a valid signature to a device with a different Android ID. It does not prevent a determined attacker from modifying the APK to skip `validateLicense`, forcing `isRegistered=true`, or changing `BuildConfig.SKIP_LICENSE_CHECK` behavior. R8 optimization increases reverse-engineering effort but cannot make client-side enforcement unpatchable.

This is a general limitation of offline licensing, not a defect unique to this project.

## What the system currently enforces

The current implementation successfully provides:

- A license signature tied to an Android ID.
- Protection against casually copying a stored signature to another device ID.
- Offline operation after activation.
- Issuer quota tracking under non-concurrent normal use.
- Administrative visibility and Excel export.
- A path for legacy identifiers stored in `past.csv`.

It does **not** currently guarantee:

- That an activation corresponds to a paid order.
- That the JWT holder owns the device code in the request.
- That issuer quotas cannot be changed by non-admin accounts.
- Reliable reactivation after reinstall or app-data loss.
- Revocation of already activated installations.
- Separation between Millennium editions.
- Stable verification across server key loss or process scaling.

## Recommended remediation order

### Phase 1: stabilize the cryptographic identity

1. Generate one production signing key outside the application.
2. Store the private key in a secret manager or a read-only mounted secret, not in Git or SQLite.
3. Back it up securely and define a controlled rotation process.
4. Embed the corresponding public key in the Android release or ship a trusted key ring.
5. Add a key identifier to issued licenses so future key rotation is possible.

### Phase 2: introduce real activation entitlements

1. Create unique, high-entropy activation codes representing purchased seats.
2. Store only a secure hash of each activation code on the server.
3. Bind redemption atomically to a device ID and an allowed product/edition.
4. Make activation codes single-use or explicitly control their allowed activation count.
5. Permit authenticated recovery/reissue for the same entitlement and device.

An issuer name should be metadata, not a secret or proof of purchase.

### Phase 3: define the offline and revocation policy

Choose one explicit model:

- **Permanent offline license:** revocation is intentionally unavailable after issuance.
- **Periodic lease:** issue a signed entitlement with an expiry and require renewal after a defined offline grace period.
- **Online check:** periodically query the server, with clear behavior during outages.

The data model, user messaging, and `is_active` behavior should reflect the chosen policy.

### Phase 4: bind the complete entitlement

Sign a canonical payload containing at least:

- License/entitlement ID.
- Device ID or a privacy-preserving device binding.
- Product and allowed edition.
- Issue time.
- Optional expiry or lease deadline.
- Key ID and schema version.

The client should parse and validate the signed payload rather than separately trusting unsigned database metadata.

### Phase 5: harden administration and operations

1. Restrict issuer management and Excel export according to explicit roles.
2. Hash passwords on every create/update path.
3. Add CSRF protection, login throttling, and secure session-cookie settings.
4. Remove all production fallback secrets and supply `WEBHOOK_SECRET` through deployment.
5. Disable Android body logging in release builds.
6. Validate request bodies and return structured, user-safe errors.
7. Make quota redemption atomic and idempotent.
8. Add audit records for quota changes, activation, reissue, revocation, and administrative export.

## Suggested tests

The licensing system should have automated coverage for:

- First activation and local verification.
- Server restart before and after activation.
- Two simultaneous attempts to consume the final quota unit.
- Reinstall or cleared app data on the same device.
- Factory reset or changed Android ID.
- Activation using a token issued for a different code.
- Expired access and refresh tokens.
- Attempted use of a refresh token as an access token.
- Non-admin access to issuer management and Excel export.
- Revoked license behavior under the chosen offline policy.
- Installing a different Millennium flavor over an activated installation.
- Legacy `past.csv` activation and repeated activation.
- Signing-key rotation and old-license verification.

## Conclusion

The design correctly applies asymmetric signatures to allow a server-issued, device-bound license to be verified offline without placing the private signing secret in the APK. That is a suitable foundation for non-Play-Store distribution.

The current implementation should not yet be treated as a strong commercial entitlement boundary. The highest-priority changes are persisting and protecting the RSA signing key, replacing issuer-name authorization with purchase-backed activation entitlements, binding tokens and licenses to the correct device and edition, and explicitly defining reinstall and revocation behavior.
