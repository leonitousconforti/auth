import * as Layer from "effect/Layer";

import { makeArgon2 } from "./internal/argon2-wasm";
import module from "./internal/argon2.wasm";
import { makeKdfLayer } from "./internal/layer";
import * as Scrypt from "./internal/scrypt";
import type { Limits } from "./Kdf";

/** Wasm Argon2id, native scrypt and bounded password derivation.
 * Bundle with Wrangler and enable Node.js compatibility.
 */
export const layer = (subtle: SubtleCrypto, limits: Partial<Limits> = {}) =>
  makeKdfLayer(subtle, limits, makeArgon2(module)).pipe(Layer.provide(Scrypt.layer));
