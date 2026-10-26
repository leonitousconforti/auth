---
"@yielded/auth": patch
"@yielded/auth-persistence": patch
---

Maintain session idle expiry automatically through authenticated HTTP requests, retaining stateful credentials until absolute expiry while preserving authentication age and server-enforced idle limits. Implement `refresh` in custom session strategies and stateful persistence services; keep `renewSession` for explicit credential rotation.
