import type * as Aead from "effect/crypto/Aead";
import type * as Digest from "effect/crypto/Digest";
import type * as Mac from "effect/crypto/Mac";
import type * as SecureRandom from "effect/crypto/SecureRandom";
import type * as Signature from "effect/crypto/Signature";
import * as FetchHttpClient from "effect/http/FetchHttpClient";
import type * as HttpClient from "effect/http/HttpClient";
import * as Layer from "effect/Layer";

import { layerWebCrypto } from "./WebCrypto";

/** Runtime services for OAuth, sessions, passkeys and proofs on Cloudflare Workers. */
export type WorkerdPasswordlessServices =
  | SecureRandom.SecureRandom
  | Digest.Digest
  | Aead.Aead
  | Mac.Mac
  | Signature.Signature
  | HttpClient.HttpClient;

/** Entropy/digests, XChaCha-capable AEAD, HMAC, signatures and a Fetch HttpClient.
 * Imports no Wasm or Node built-ins and needs no nodejs_compat flag.
 * Provide to the application Layer; storage, keys, policy, delivery and protocol
 * adapters remain application-owned. Passwords use WorkerdServices instead.
 */
export const layer: Layer.Layer<WorkerdPasswordlessServices> = Layer.mergeAll(
  layerWebCrypto,
  FetchHttpClient.layer,
);
