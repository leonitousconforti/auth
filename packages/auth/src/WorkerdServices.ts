import type { Aead } from "@yielded/crypto/Aead";
import type { InvalidInput } from "@yielded/crypto/Errors";
import type { Hmac } from "@yielded/crypto/Hmac";
import type { Kdf, Limits } from "@yielded/crypto/Kdf";
import * as KdfAdmission from "@yielded/crypto/KdfAdmission";
import * as WorkerdCrypto from "@yielded/crypto/platform-workerd";
import type { Signature } from "@yielded/crypto/Signature";
import { layerCryptoWeb } from "@yielded/crypto/WebCrypto";
import { type Crypto, Layer } from "effect";
import { FetchHttpClient, type HttpClient } from "effect/http";

import type { PasswordHashingConfig } from "./password/configuration";
import type { PasswordConfigurationError } from "./password/errors";
import { PasswordHashing } from "./password/PasswordHashing";

/** Runtime services for Auth on Cloudflare Workers. Application-owned storage,
 * keys, account policy, delivery, and protocol adapters remain separate.
 */
export type WorkerdServices =
  | Crypto.Crypto
  | Aead
  | Hmac
  | Kdf
  | KdfAdmission.KdfAdmission
  | Signature
  | PasswordHashing
  | HttpClient.HttpClient;

export interface Options {
  readonly passwordHashing?: PasswordHashingConfig;
  readonly kdfLimits?: Partial<Limits>;
  readonly kdfAdmission?: KdfAdmission.Options;
}

/** Configure password hashing and KDF resource bounds. The backend and hasher
 * share admission through password preparation, derivation, and cleanup.
 */
export const layerWith = (
  options: Options,
): Layer.Layer<WorkerdServices, InvalidInput | PasswordConfigurationError> => {
  const platform = Layer.mergeAll(
    layerCryptoWeb,
    FetchHttpClient.layer,
    WorkerdCrypto.layer(globalThis.crypto.subtle, options.kdfLimits).pipe(
      Layer.provideMerge(KdfAdmission.layer(options.kdfAdmission)),
    ),
  );

  return PasswordHashing.layer(options.passwordHashing).pipe(Layer.provideMerge(platform));
};

/** Provide once to the application Layer. Includes entropy/digests, crypto,
 * Argon2id password hashing, bounded KDF admission, and a Fetch HttpClient.
 * Bundle with Wrangler and enable nodejs_compat. This direct entrypoint is not
 * exported from the browser-safe package root.
 *
 * Admission is shared within the built Layer's lifetime. To bound concurrent
 * requests in an isolate, retain the built services at that lifetime and supply
 * them to request-scoped auth/database Layers; rebuilding per request creates
 * independent admission services. This is not a distributed rate limiter.
 */
export const layer: Layer.Layer<WorkerdServices, InvalidInput | PasswordConfigurationError> =
  layerWith({});
