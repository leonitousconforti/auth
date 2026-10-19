---
"@yielded/auth": patch
"@yielded/auth-persistence": patch
---

Maintain session idle expiry automatically through authenticated HTTP requests while preserving stateful credentials, authentication age, and absolute expiry. Implement `refresh` in custom session strategies and stateful persistence services; keep `renewSession` for explicit credential rotation.
