import { it } from "@effect/vitest";
import { Kdf } from "@yielded/crypto/Kdf";
import * as Effect from "effect/Effect";
import * as Hex from "effect/encoding/Hex";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import { describe, expect } from "vite-plus/test";

import { backends } from "./backends";
import { argon2Vector, pbkdf2Vectors } from "./vectors";

const bytes = Schema.decodeSync(Schema.Uint8ArrayFromHex);

// Independent known answers for the password derivation profiles retained here.
for (const backend of backends) {
  describe(`${backend.name}`, () => {
    for (const vector of pbkdf2Vectors) {
      it.effect(`derives byte-preserving ${vector.id}`, () =>
        Effect.gen(function* () {
          const kdf = yield* Kdf;
          const password = bytes(vector.passwordHex);
          const salt = bytes(vector.saltHex);

          const result = yield* kdf.pbkdf2({
            password: Redacted.make(password),
            salt,
            iterations: vector.iterations,
            length: vector.lengthBytes,
          });

          expect(Hex.encode(Redacted.value(result))).toBe(vector.expectedHex);
          expect(Hex.encode(password)).toBe(vector.passwordHex);
          expect(Hex.encode(salt)).toBe(vector.saltHex);
          expect(JSON.stringify(result)).not.toContain(vector.expectedHex);
        }).pipe(Effect.provide(backend.layer)),
      );
    }

    if (backend.extended) {
      it.effect("derives RFC9106 Argon2id v19 with lanes, secret and associated data", () =>
        Effect.gen(function* () {
          const kdf = yield* Kdf;
          const password = bytes(argon2Vector.passwordHex);

          const result = yield* kdf.argon2id({
            password: Redacted.make(password),
            salt: bytes(argon2Vector.saltHex),
            secret: Redacted.make(bytes(argon2Vector.secretHex)),
            associatedData: bytes(argon2Vector.associatedDataHex),
            memoryKiB: argon2Vector.memoryKiB,
            passes: argon2Vector.iterations,
            parallelism: argon2Vector.parallelism,
            length: argon2Vector.lengthBytes,
          });

          expect(Hex.encode(Redacted.value(result))).toBe(argon2Vector.expectedHex);
          expect(Hex.encode(password)).toBe(argon2Vector.passwordHex);
        }).pipe(Effect.provide(backend.layer)),
      );
    }
  });
}
