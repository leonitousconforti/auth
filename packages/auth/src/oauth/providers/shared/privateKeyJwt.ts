import { Hmac } from "@yielded/crypto/Hmac";
import { Signature } from "@yielded/crypto/Signature";
import { Jwk, Jwt } from "@yielded/jose";
import type { PrivateKey } from "@yielded/jose/Jwk";
import { Unavailable } from "@yielded/oauth/Errors";
import { Clock, Context, Effect, Layer, Redacted, Result, Schema } from "effect";
import { Base64 } from "effect/encoding";

import {
  isPrivateKeyAuthentication,
  type OpenIdConnectAuthentication,
  type PrivateKeyJwt,
} from "./models";

const Claims = Schema.Struct({
  iss: Schema.NonEmptyString,
  sub: Schema.NonEmptyString,
  aud: Schema.NonEmptyString,
  iat: Schema.Finite,
  exp: Schema.Finite,
});

/** Sign one ES256 client-secret JWT. The caller owns key wiping. */
export const signPrivateKeyJwt = Effect.fn("OpenIdConnect.signPrivateKeyJwt")(function* (
  policy: Omit<PrivateKeyJwt, "privateKey">,
  key: PrivateKey,
) {
  const now = Math.floor((yield* Clock.currentTimeMillis) / 1000);

  return yield* Jwt.sign(
    Claims,
    {
      iss: policy.issuer,
      sub: policy.subject,
      aud: policy.audience,
      iat: now,
      exp: now + policy.lifetimeSeconds,
    },
    key,
    { alg: "ES256", kid: policy.keyId },
  ).pipe(Effect.mapError(() => Unavailable.make({})));
});

/** Import the stored PKCS8 DER and sign a client secret for this token request. */
export const mintStoredPrivateKeyJwt = Effect.fn("OpenIdConnect.mintStoredPrivateKeyJwt")(
  function* (policy: PrivateKeyJwt) {
    const der = Result.getOrUndefined(Base64.decode(Redacted.value(policy.privateKey)));

    if (der === undefined || der.length === 0) return yield* Unavailable.make({});

    const key = yield* Jwk.importPkcs8(Redacted.make(der), policy.algorithm, {
      kid: policy.keyId,
    }).pipe(
      Effect.mapError(() => Unavailable.make({})),
      Effect.ensuring(Effect.sync(() => der.fill(0))),
    );

    return yield* signPrivateKeyJwt(policy, key).pipe(
      Effect.ensuring(Effect.sync(() => Redacted.wipeUnsafe(key.material))),
    );
  },
);

/** Per-request client_secret_post material. Static secrets stay on the OAuth client. */
export const postedClientSecret = Effect.fn("OpenIdConnect.postedClientSecret")(function* (
  authentication: OpenIdConnectAuthentication,
) {
  if (!isPrivateKeyAuthentication(authentication)) return undefined;

  return yield* mintStoredPrivateKeyJwt(authentication.privateKeyJwt);
});

/** Inward client-authentication port. Concrete policy is provided at composition. */
export class PrivateKeyClientSecret extends Context.Service<
  PrivateKeyClientSecret,
  {
    readonly mint: (
      authentication: OpenIdConnectAuthentication,
    ) => Effect.Effect<Redacted.Redacted<string> | undefined, Unavailable>;
  }
>()("effect-auth/oauth/providers/PrivateKeyClientSecret") {
  /** Static client secrets stay on the OAuth client. */
  static readonly layerUnused = Layer.succeed(PrivateKeyClientSecret, {
    mint: () => Effect.succeed(undefined),
  });

  /** Mint one ES256 client secret per token request. Requires Signature and Hmac. */
  static readonly layer = Layer.effect(
    PrivateKeyClientSecret,
    Effect.gen(function* () {
      const signature = yield* Signature;
      const hmac = yield* Hmac;

      return PrivateKeyClientSecret.of({
        mint: (authentication) =>
          postedClientSecret(authentication).pipe(
            Effect.provideService(Signature, signature),
            Effect.provideService(Hmac, hmac),
          ),
      });
    }),
  );
}
