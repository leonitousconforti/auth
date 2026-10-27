---
"@yielded/auth": minor
"@yielded/auth-persistence": minor
---

Enable phone account creation after SMS verification with `PhoneOtp.make({ allowSignUp: true })` through the ordinary `signIn` and `completeSignIn` methods. Keep explicit registration and number management independently opt-in with `lifecycle`.
