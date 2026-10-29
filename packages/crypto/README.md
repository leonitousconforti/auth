# @yielded/crypto

Bounded password derivation for Effect applications: Argon2id, scrypt, and
PBKDF2-SHA256. Effect is its only runtime package dependency. Use `effect/crypto`
for randomness, digests, HMAC, encryption, signatures, and key formats.

```sh
bun add @yielded/crypto@beta effect
```

Import `Kdf` and `KdfAdmission` from the root. Choose a password backend:

- `/Portable`: portable Argon2id and Effect WebCrypto PBKDF2; no scrypt.
- `/platform-node`, `/platform-bun`: native Argon2id and scrypt, plus Effect PBKDF2.
- `/platform-workerd`: bundled Wasm Argon2id, native scrypt, and Effect PBKDF2.
  Requires Workers Node.js compatibility; Wrangler bundles the Wasm automatically.

Share one `KdfAdmission` Layer between the backend and password operations.
Admission covers work and cleanup; noncancelable native work finishes before
releasing its permit. Portable Argon2id yields on the calling thread.
Applications own password strength, normalization, and stored-hash formats.

Inputs and derived material use `Redacted`; secret schemas reject JSON encoding.
Errors contain fixed classifications without native causes or secret payloads.

See the [runtime and resource limits](../../docs/src/content/docs/reference/crypto.md)
and [third-party notices](THIRD_PARTY_NOTICES.md).
