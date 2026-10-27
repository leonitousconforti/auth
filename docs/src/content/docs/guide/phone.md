---
title: Phone codes
description: Sign in or create an account through one SMS-code flow.
---

Use `PhoneOtp` to sign in or create an account through one SMS-code flow. The
server signs in an existing verified number or registers an unused number after
code verification. Both paths return the same challenge and authentication result.

For managed or application-declared SQL storage, the [composed persistence Layer](../reference/adapters#compose-persistence-once)
supplies phone and proof services together, including enabled lifecycle operations.
The explicit mappings below support specialized storage layouts.

The [shared contract](./http-and-client#expose-another-method) below gives server
and browser callers the same API. Server calls run inside an Effect request
handler with `AppAuth` and the HTTP request boundary provided.

## Enable phone sign-in

```ts title="packages/domain/auth-contract.ts"
import { Schema } from "effect";
import { AuthContract, PhoneOtp } from "@yielded/auth";

export const AuthApi = AuthContract.make("app/Auth", {
  claims: Schema.Struct({ phoneNumber: PhoneOtp.PhoneNumber }),
  actions: (sessions) => ({
    signInOrSignUp: AuthContract.phoneSignInOrSignUp(),
    completeSignInOrSignUp: AuthContract.phoneCompleteSignInOrSignUp(sessions),
  }),
});
```

Bind the contract to the phone strategy on the server:

```ts title="apps/server/auth.ts"
import { Auth, PhoneOtp, Sessions } from "@yielded/auth";
import { AuthApi } from "@app/domain/auth-contract";

export const AppAuth = Auth.make(AuthApi, {
  sessions: Sessions.stateful(),
  strategies: {
    phone: PhoneOtp.make({ lifecycle: true }),
  },
  defaultStrategy: "phone",
});
```

The default code has six digits and expires after five minutes. Override `digits`
or `policy` only to change that behavior. Keys and delivery come from Layers.
Use `PhoneOtp.make()` with `signIn` and `completeSignIn` when only existing
accounts may sign in.

## Send a code

With `Effect` imported from `effect`, supply the request's host-verified network key:

```ts
const auth = yield* AppAuth;
const started = yield* auth.signInOrSignUp({ phoneNumber, locale: "en" }).pipe(
  Effect.provideService(PhoneOtp.PhoneRequestContext, { networkKey }),
);
```

`networkKey` is a `Redacted<string>` used for admission limits. Derive it on the
server per request; the HTTP auth adapter does not supply it.
Use an international number such as `+14155550123`. The result contains a `flowId`
and proof `reference`. The request binder goes through private credential delivery;
your SMS service receives the code.

## Complete sign-in

Use the original `flowId` and `reference`. The contract supplies `requestBinding`
from private request credentials, so the browser sends only the public fields.

```ts
const auth = yield* AppAuth;
const result = yield* auth.completeSignInOrSignUp({
  flowId,
  phoneNumber,
  reference,
  code,
}).pipe(
  Effect.provideService(PhoneOtp.PhoneRequestContext, { networkKey }),
);
```

Grant access only when the result is `Authenticated`; otherwise complete the
required additional factor. If the number's ownership changes while a code is
outstanding, request a new code. A consumed code cannot be reused if session
issuance fails. The strategy's lower-level `operations.SignInOrSignUp` accepts the
original flow and private `requestBinding` for resends after cooldown. The
convenience `signInOrSignUp` call starts a new flow, which cannot replace a live
code. SMS proves possession, without phishing resistance.

`PhoneAdmission.layer(policy)` controls network and message limits. Defaults are
10 requests and 100 attempts per network per minute, plus 10 message reservations
per instance per minute. Suppressed requests count too. [Share network limits](./passwords#share-rate-limits)
across replicas or per-request runtimes; the message budget stays per instance.
See [proof limits](./codes#proof-expiry-and-rate-limits) for expiry and cooldown.

## Supply the services

The strategy handles code generation and verification. Supply these implementations:

- **`PhonePersistenceLive`**: Finds the account and owns protected number changes. Your database, using a library adapter below.
- **`ProofPersistenceLive`**: Stores code digests, expiry, failed attempts, and consumption. Your database, using a library adapter below.
- **`PhoneDeliveryEligibility`**: Decides which destination numbers you support. Your application policy.
- **`PhoneActionEvidence`**: Authorizes number verification and changes. The example below rejects them.
- **`SessionClaims`**: Returns the session fields declared in `AppAuth.claims`. Your application.
- **`SmsDelivery`**: Sends the message. `Twilio.layer` or another transport.

`PhonePersistenceLive` and `ProofPersistenceLive` are names for the Layers you build
below, not package exports. The adapters implement the storage operations; you
supply your table mappings and migrations.

For managed or mapped account signup, supply `Persistence.Provisioning` under the
phone strategy's name. Its `values({ requestId, identifier })` prepares the new
account's native ID, active status, initial security revision, and application
fields. `identifier` contains the `phone` namespace and verified number.
Preparation must not write to the database or perform external side effects;
persistence commits the account, identifier, credential, and proof consumption
together. See the [provisioning example](../reference/adapters#compose-persistence-once).

<details>
<summary>Build the database Layers — SQLite on Bun</summary>

<!--@include: ../reference/adapters.md#phone-layers-->

</details>

Wire those Layers with a sending policy and session claims:

```ts title="apps/server/phone-live.ts"
import { Config, Effect, Layer } from "effect";
import { PhoneOtp } from "@yielded/auth";
import * as Twilio from "@yielded/auth/adapters/Twilio";
import { FetchHttpClient } from "effect/http";

import { AppAuth } from "./auth";
import { AuthDependencies } from "./auth-dependencies";
import { PhonePersistenceLive, ProofPersistenceLive } from "./auth-persistence";

const TwilioConfigLive = Layer.effect(
  Twilio.TwilioConfig,
  Config.all({
    accountSid: Config.String("TWILIO_ACCOUNT_SID"),
    authToken: Config.Redacted("TWILIO_AUTH_TOKEN"),
    from: Config.String("TWILIO_FROM"),
  }),
);

const SmsLive = Twilio.layer.pipe(
  Layer.provide(TwilioConfigLive),
  Layer.provide(FetchHttpClient.layer),
);

export const PhoneLive = Layer.mergeAll(
  PhonePersistenceLive,
  ProofPersistenceLive,
  Layer.succeed(PhoneOtp.PhoneDeliveryEligibility, {
    allowed: (number) => Effect.succeed(number.startsWith("+1")),
  }),
  Layer.succeed(PhoneOtp.PhoneActionEvidence, {
    verify: () => Effect.fail(PhoneOtp.PhoneActionRequired.make({})),
  }),
  Layer.succeed(AppAuth.strategies.phone.SessionClaims, {
    resolve: ({ credential }) => Effect.succeed({ phoneNumber: credential.phoneNumber }),
  }),
  SmsLive,
);

export const AuthLive = AppAuth.layer.pipe(
  Layer.provide(PhoneLive),
  Layer.provide(AuthDependencies),
);
```

This example allows `+1` destinations and stores the **verified** phone number
in the session. Replace the prefix check with your supported destinations. To add
account fields to claims, accept `resolve: ({ subjectId }) => …` and query your account by that ID and return the fields declared in `AppAuth.claims`.

`TwilioConfigLive` loads credentials from Effect Config; use `messagingServiceSid`
instead of `from` for a Twilio Messaging Service. The adapter uses Effect HTTP and
requires no Twilio SDK.

`AuthDependencies` supplies shared [crypto, session, account, and key configuration](../reference/adapters#compose-the-application-layer).
Build Auth in a scope that outlives requests so its SMS delivery worker can finish.
The [delivery lifetime and retry limits](./email-delivery#compose-auth) also apply
to SMS.

<details>
<summary>Customize the SMS message</summary>

Add this optional Layer to `PhoneLive`:

```ts
PhoneOtp.Template.layer({
  render: (code) => `Your Acme sign-in code is ${code}.`,
});
```

The default is `Your sign-in code is 123456.` The renderer also receives locale
and expiry as its second argument. Text stays private through delivery.

</details>

<details>
<summary>Explicit registration and phone-number changes</summary>

The enabled lifecycle also exposes separate registration, verification, and
number-change operations. Use a lifecycle policy object instead of `true` to
customize its behavior. With `Sessions.stateful()`, managed and mapped composition supplies the required
`PhonePersistence` and `PhoneSignInTargets` without additional tables.

For a separate signup flow, call `auth.begin({ action: "register", ... })`, then
pass the code, reference, original flow and command IDs, and private request binding to
`auth.completeLifecycle(input)`. A `Registered` result contains `completion`;
grant access only when that completion is `Authenticated`, as for sign-in.

Verifying an existing account's number (`action: "verify"`) or replacing it
(`action: "change"`, with `sourcePhoneNumber`) requires an authenticated caller
and independent authorization. Replace the rejecting `PhoneActionEvidence` Layer
in `PhoneLive` with your application's check:

```ts
Layer.succeed(PhoneOtp.PhoneActionEvidence, { verify: authorizePhoneChange });
```

`authorizePhoneChange` is your application's check of fresh, independent evidence;
the SMS code alone cannot authorize these changes. Both use `auth.begin(input)`
and `auth.completeLifecycle(input)`. Supply `PhoneRequestContext` for every
lifecycle request, as for sign-in. Delivery and session claims remain
application-owned.

Changing a number permanently retires its old identifier; a later registration
cannot adopt it. Reassignment requires independently authorized recovery, never
account linking based only on matching phone strings. See the
[complete phone composition](https://github.com/yielded-dev/auth/blob/main/examples/auth/src/phone-sqlite-bun.ts).

</details>
