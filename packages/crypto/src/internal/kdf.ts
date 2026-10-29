import * as Digest from "effect/crypto/Digest";
import * as EffectKdf from "effect/crypto/Kdf";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";

import {
  CryptoUnavailable,
  InvalidInput,
  type OperationError,
  UnsupportedAlgorithm,
} from "../Errors";
import { Argon2idInput, Kdf, type Limits, Pbkdf2Input, ScryptInput } from "../Kdf";
import { KdfAdmission } from "../KdfAdmission";
import { copy, decode, withSecret } from "./common";
import { ScryptBackend } from "./scrypt-backend";

export interface Argon2Parameters {
  readonly password: Uint8Array<ArrayBuffer>;
  readonly salt: Uint8Array<ArrayBuffer>;
  readonly memoryKiB: number;
  readonly passes: number;
  readonly parallelism: number;
  readonly length: number;
  readonly secret?: Uint8Array<ArrayBuffer>;
  readonly associatedData: Uint8Array<ArrayBuffer>;
}

export type Argon2 = (input: Argon2Parameters) => Effect.Effect<Uint8Array, OperationError>;

export const makeKdf = Effect.fnUntraced(function* (limits: Limits, argon2?: Argon2) {
  const admission = yield* KdfAdmission;
  const standard = yield* EffectKdf.Kdf;
  const scrypt = yield* ScryptBackend;
  const boundedBytes = Schema.Uint8Array.check(Schema.isMaxLength(limits.maximumInputBytes));

  const output = Schema.Int.check(
    Schema.isBetween({ minimum: 1, maximum: limits.maximumOutputBytes }),
  );

  const inputBytes = (input: Uint8Array) => decode(boundedBytes, input, "data");
  const outputLength = (input: number) => decode(output, input, "parameters");

  return Kdf.of({
    scrypt: (input) =>
      admission.run(
        Effect.gen(function* () {
          const value = yield* decode(ScryptInput, input, "parameters");

          yield* outputLength(value.length);
          yield* inputBytes(Redacted.value(value.password));
          yield* inputBytes(value.salt);

          const memoryBytes = 128 * value.blockSize * (value.cost + value.parallelism + 2);

          if (
            !Number.isInteger(Math.log2(value.cost)) ||
            Math.log2(value.cost) >= 16 * value.blockSize ||
            value.blockSize * value.parallelism >= 2 ** 30 ||
            memoryBytes > limits.maximumMemoryKiB * 1024 ||
            (value.cost * value.blockSize * value.parallelism) / 8 > limits.maximumMemoryPasses
          )
            return yield* InvalidInput.make({ reason: "parameters" });
          const salt = yield* copy(value.salt);

          return yield* withSecret(value.password, (password) =>
            scrypt
              .derive({
                password,
                salt,
                cost: value.cost,
                blockSize: value.blockSize,
                parallelism: value.parallelism,
                length: value.length,
                maximumMemoryBytes: limits.maximumMemoryKiB * 1024,
              })
              .pipe(Effect.map(Redacted.make)),
          );
        }),
      ),
    pbkdf2: (input) =>
      admission.run(
        Effect.gen(function* () {
          const value = yield* decode(Pbkdf2Input, input, "parameters");

          yield* decode(
            Schema.Int.check(Schema.isBetween({ minimum: 1, maximum: limits.maximumIterations })),
            value.iterations,
            "parameters",
          );
          yield* outputLength(value.length);
          yield* inputBytes(Redacted.value(value.password));
          yield* inputBytes(value.salt);
          const salt = yield* copy(value.salt);

          return yield* withSecret(value.password, (password) =>
            standard
              .derive(
                EffectKdf.pbkdf2({ hash: Digest.sha256, iterations: value.iterations }),
                password,
                {
                  salt,
                  length: value.length,
                },
              )
              .pipe(
                Effect.map(Redacted.make),
                Effect.mapError(() => CryptoUnavailable.make({})),
                Effect.uninterruptible,
              ),
          );
        }),
      ),
    argon2id: (input) =>
      admission.run(
        Effect.gen(function* () {
          const value = yield* decode(Argon2idInput, input, "parameters");

          yield* outputLength(value.length);
          yield* inputBytes(Redacted.value(value.password));
          yield* inputBytes(value.salt);
          if (value.secret !== undefined) yield* inputBytes(Redacted.value(value.secret));
          if (value.associatedData !== undefined) yield* inputBytes(value.associatedData);

          if (
            value.memoryKiB < 8 * value.parallelism ||
            value.memoryKiB > limits.maximumMemoryKiB ||
            value.passes > limits.maximumPasses ||
            value.parallelism > limits.maximumParallelism ||
            value.memoryKiB * value.passes > limits.maximumMemoryPasses
          )
            return yield* InvalidInput.make({ reason: "parameters" });
          if (argon2 === undefined) return yield* UnsupportedAlgorithm.make({});

          const salt = yield* copy(value.salt);
          const associatedData = yield* copy(value.associatedData ?? new Uint8Array());

          return yield* withSecret(value.password, (password) => {
            const derive = (secret?: Uint8Array<ArrayBuffer>) =>
              argon2({
                password,
                salt,
                ...(secret === undefined ? {} : { secret }),
                associatedData,
                memoryKiB: value.memoryKiB,
                passes: value.passes,
                parallelism: value.parallelism,
                length: value.length,
              }).pipe(Effect.map((bytes) => Redacted.make(bytes)));

            return value.secret === undefined ? derive() : withSecret(value.secret, derive);
          });
        }),
      ),
  });
});
