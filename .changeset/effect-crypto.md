---
"@yielded/auth": patch
"@yielded/crypto": patch
"@yielded/jose": patch
"@yielded/oauth": patch
---

Use Effect crypto for HMAC, authenticated encryption, signatures, and key formats while retaining bounded password backends for Argon2id and scrypt. BEHAVIOR CHANGE: supply `effect/crypto` services or Effect platform crypto Layers; `@yielded/crypto` now exposes only password KDFs, and JOSE key material uses opaque Effect keys.
