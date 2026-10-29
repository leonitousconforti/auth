---
"@yielded/auth": patch
"@yielded/auth-electron": patch
"@yielded/auth-persistence": patch
"@yielded/auth-persistence-drizzle": patch
"@yielded/auth-react-native": patch
"@yielded/auth-simplewebauthn": patch
"@yielded/crypto": patch
"@yielded/jose": patch
"@yielded/oauth": patch
---

Require Effect 4.1 and matching SQL drivers. BEHAVIOR CHANGE: supply `SecureRandom.SecureRandom` and `Digest.Digest` from `effect/crypto` in place of `Crypto.Crypto`; the existing `WebCrypto.layerCryptoWeb` and `WebCrypto.layerWebCrypto` layers supply both.
