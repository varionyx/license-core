# license-core

License validation library for the platform. **Validation is never skipped;** only the public key source (DEV vs PROD) changes by environment.

## Production (PROD)

- Set `PROD_PUBLIC_KEY` (base64 Ed25519 public key, 32 bytes).
- Do **not** set `LICENSE_DEV_MODE`.
- License file path: `LICENSE_PATH` (default `license.json`). File must be signed with the private key matching `PROD_PUBLIC_KEY`.
- Ed25519 signature is always verified.

## Local development (DEV)

- Set `LICENSE_DEV_MODE=true` and `DEV_PUBLIC_KEY` (base64; from the dev license generator).
- Set `LICENSE_PATH` to your signed dev license file (e.g. `config/license.json`).
- Signature is still verified; only the public key used is the DEV key from env.
- **DEV key is not compiled in.** It is read from the environment at runtime only when `LICENSE_DEV_MODE=true`.

## Safety

- No bypass flags. `validate_license()` always verifies the signature.
- No key is compiled into the binary; both PROD and DEV keys come from environment variables.
- Production builds must set `PROD_PUBLIC_KEY`; DEV mode is opt-in via `LICENSE_DEV_MODE=true`.

## Signed license format

The license file must contain:

- `payload`: license fields (license_id, tenant_id, issued_at, expires_at, grace_days, optional platform_version).
- `signed_payload_utf8`: exact UTF-8 string that was signed (deterministic).
- `signature_base64`: Ed25519 signature (64 bytes) in base64.

Use the dev license generator in `platform-integration/scripts` to produce a valid signed license for local dev.
