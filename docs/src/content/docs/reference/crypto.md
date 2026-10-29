---
title: Cryptography
description: Supply Effect crypto services and bounded password-derivation backends.
---

Auth and JOSE use `effect/crypto` for secure randomness, digests, message
authentication, authenticated encryption, signatures, and key formats. Applications
own keys, nonce uniqueness, accepted algorithms, and credential policy.
`@yielded/crypto` supplies password derivation with shared resource limits,
including portable Argon2id and native scrypt.

## Compose a backend

Use the Effect platform Layer for your runtime:

```ts
import { NodeCrypto } from "@effect/platform-node";
import { Effect } from "effect";
import { Aead, SecureRandom } from "effect/crypto";

// Read a cryptographically random application key from secret configuration.
declare const keyBytes: Uint8Array;

const protect = Effect.gen(function* () {
  const random = yield* SecureRandom.SecureRandom;
  const aead = yield* Aead.Aead;
  const key = yield* Aead.key(Aead.aes256Gcm, keyBytes);
  const nonce = yield* random.randomBytes(12);
  const ciphertext = yield* aead.encrypt(
    key,
    new TextEncoder().encode("private data"),
    { nonce, aad: new TextEncoder().encode("application/purpose/v1") },
  );
  return { nonce, ciphertext };
}).pipe(Effect.provide(NodeCrypto.layer));
```

Never reuse a nonce with the same key.
Use `BunCrypto` from `@effect/platform-bun` on Bun. For WebCrypto hosts,
`@yielded/auth/WebCrypto` exports `layerWebCrypto`, supplying `SecureRandom`,
`Digest`, `Mac`, `Aead`, and `Signature`. Its `layerCryptoWeb` supplies only
`SecureRandom` and `Digest`.

Effect keys are opaque snapshots. `Mac.key` and `Aead.key` import raw bytes;
`KeyFormat` imports and exports asymmetric keys as JWK, PKCS8, or SPKI.
Keep private material out of telemetry. Effect crypto errors can carry native
causes: translate them at your application's public boundary.

## Use with Auth

Choose the services your application needs:

| Auth concern                       | Effect services                                               |
| ---------------------------------- | ------------------------------------------------------------- |
| Stateful sessions and token proofs | `SecureRandom`, `Digest`                                      |
| Signed sessions and numeric proofs | `SecureRandom`, `Digest`, `Mac`                               |
| TOTP                               | `SecureRandom`, `Digest`, `Mac`, `Aead`                       |
| OAuth protection                   | `SecureRandom`, `Aead`                                        |
| OIDC verification                  | `Signature`, plus the provider's HTTP and digest requirements |

Auth owns keyring validation, key IDs, token serialization, and authenticated
context. Its OAuth protectors use XChaCha20-Poly1305; TOTP uses AES-256-GCM.
Effect's WebCrypto AEAD Layer supplies both. Existing application configuration
continues to use redacted key bytes or base64url keyring material.

For Cloudflare Workers, provide `WorkerdPasswordlessServices.layer` from
`@yielded/auth/WorkerdPasswordlessServices`. It includes these crypto services
and a Fetch `HttpClient`, with no Wasm or Node.js compatibility requirement.
Use `WorkerdServices.layer` from `@yielded/auth/WorkerdServices` for passwords;
that Layer also supplies password hashing, Wasm Argon2id, native scrypt, and
bounded admission. Enable `nodejs_compat` and bundle with Wrangler.

Provide the selected Layer to the application once. Storage, account policy,
keys, delivery, and protocol adapters remain application-owned. Direct callers of
`Sessions.makeSessionSigningCodec` and numeric `Proofs.makeProofCrypto` must keep
the construction Scope open while using their operations. Auth Layers own that
scope when constructing them.

For manual password composition:

```ts
import * as WebCrypto from "@yielded/auth/WebCrypto";
import * as KdfAdmission from "@yielded/crypto/KdfAdmission";
import * as Portable from "@yielded/crypto/Portable";
import { Layer } from "effect";

const Admission = KdfAdmission.layer();
export const CryptoLive = Layer.merge(
  WebCrypto.layerWebCrypto,
  Portable.layer(globalThis.crypto.subtle).pipe(Layer.provideMerge(Admission)),
);
```

Provide `CryptoLive` to `Password.PasswordHashing.layer()` and the Auth Layer.
TOTP additionally requires `TotpSecretKeys`; OAuth protector Layers take an
application keyring. Provider Layers also need `HttpClient`.

## Backends and resource limits

`@yielded/crypto` exposes `Kdf` and `KdfAdmission`. Its Layers provide bounded
password operations, not general encryption or signing services:

| Backend                                                       | Argon2id                | Scrypt         | PBKDF2-SHA256    |
| ------------------------------------------------------------- | ----------------------- | -------------- | ---------------- |
| `Portable.layer(subtle, limits?)`                             | Portable implementation | Unsupported    | Effect WebCrypto |
| `platform-node.layer(limits?)`, `platform-bun.layer(limits?)` | Native runtime          | Native runtime | Effect WebCrypto |
| `platform-workerd.layer(subtle, limits?)`                     | Bundled Wasm            | Native runtime | Effect WebCrypto |

The native Argon2id backend requires runtime support for `crypto.argon2`.
Workers require `nodejs_compat` for scrypt. Wrangler bundles the supplied Wasm;
consumers need no C compiler. An unavailable algorithm fails with
`CryptoUnsupportedAlgorithm`; it never silently changes password algorithms.

`Kdf.defaultLimits` sets per-operation input, output, memory, and work ceilings.
These bound resource use; Auth's password configuration owns strength and
rehash policy. Argon2id uses version 19, memory in KiB, and byte lengths.
Scrypt uses `cost` (N), `blockSize` (r), and `parallelism` (p). Its allocation
must fit `maximumMemoryKiB`, including scratch buffers, and `N*r*p/8` must fit
`maximumMemoryPasses`. PBKDF2 uses SHA-256 and a positive signed 32-bit iteration
count. Inputs are bytes; the backend does not normalize passwords.

Share one `KdfAdmission.layer()` between password hashing and its backend.
Defaults permit one running derivation, sixteen queued operations, and five
seconds to acquire capacity. Waiting is interruptible; native operations retain
their permit through completion and cleanup. Portable Argon2id yields between
batches on the calling thread. Nested operations in the same fiber share a
permit; child fibers acquire independently. Retain the built Layer for the
application's lifetime to share these limits. They do not coordinate isolates
or replace a distributed rate limiter.

Password backend errors contain fixed classifications without native causes:
`CryptoInvalidInput`, `CryptoUnsupportedAlgorithm`, `CryptoUnavailable`, and
`CryptoKdfBusy`. Secret-bearing KDF schemas reject JSON encoding. Owned copies
are cleared after work; JavaScript and native engines cannot guarantee erasure
of every copy.

See the [password guide](../guide/passwords.md) and the
[shipped notices](https://github.com/yielded-dev/auth/blob/main/packages/crypto/THIRD_PARTY_NOTICES.md)
for the retained Argon2 implementation's attribution.
