import * as Layer from "effect/Layer";

import { argon2 } from "./internal/argon2";
import { makeKdfLayer } from "./internal/layer";
import { layerUnsupported } from "./internal/scrypt-backend";
import type { Limits } from "./Kdf";

/** Portable Argon2id and bounded password derivation. Scrypt requires a native backend. */
export const layer = (subtle: SubtleCrypto, limits: Partial<Limits> = {}) =>
  makeKdfLayer(subtle, limits, argon2).pipe(Layer.provide(layerUnsupported));
