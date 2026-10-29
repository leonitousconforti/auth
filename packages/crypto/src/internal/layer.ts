import * as EffectKdf from "effect/crypto/Kdf";
import * as WebCrypto from "effect/crypto/WebCrypto";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";

import { defaultLimits, Kdf, Limits } from "../Kdf";
import { decode } from "./common";
import { type Argon2, makeKdf } from "./kdf";

export const makeKdfLayer = (subtle: SubtleCrypto, input: Partial<Limits>, argon2?: Argon2) => {
  const snapshot = { ...defaultLimits, ...input };

  const standard = EffectKdf.layerWebCrypto.pipe(
    Layer.provide(
      WebCrypto.layer({
        subtle,
        getRandomValues: (array) => globalThis.crypto.getRandomValues(array),
        randomUUID: () => globalThis.crypto.randomUUID(),
      }),
    ),
  );

  return Layer.effect(Kdf)(
    Effect.gen(function* () {
      const limits = yield* decode(Limits, snapshot, "parameters");

      return yield* makeKdf(limits, argon2);
    }),
  ).pipe(Layer.provide(standard));
};
