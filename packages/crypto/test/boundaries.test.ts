import { it } from "@effect/vitest";
import { Kdf } from "@yielded/crypto/Kdf";
import * as KdfAdmission from "@yielded/crypto/KdfAdmission";
import * as Portable from "@yielded/crypto/Portable";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import { describe, expect } from "vite-plus/test";

import { backends, utf8 } from "./backends";

for (const backend of backends) {
  describe(backend.name, () => {
    it.effect(
      "rejects PBKDF2 input, iteration and output costs without exposing the password",
      () =>
        Effect.gen(function* () {
          const kdf = yield* Kdf;
          const password = Redacted.make(utf8("synthetic-secret-do-not-log"));
          const input = { password, salt: utf8("salt"), iterations: 1, length: 32 };

          for (const invalid of [
            { ...input, iterations: 0 },
            { ...input, iterations: 1000001 },
            { ...input, length: 1025 },
            { ...input, password: Redacted.make(new Uint8Array(65537)) },
          ]) {
            const failure = yield* kdf.pbkdf2(invalid).pipe(Effect.flip);

            expect(failure).toMatchObject({ _tag: "CryptoInvalidInput" });
            expect(JSON.stringify(failure)).not.toContain("synthetic-secret-do-not-log");
            expect(failure).not.toHaveProperty("cause");
          }
        }).pipe(Effect.provide(backend.layer)),
    );

    if (backend.extended) {
      it.effect("bounds Argon2 memory, memory-times-passes and lanes before deriving", () =>
        Effect.gen(function* () {
          const kdf = yield* Kdf;

          const input = {
            password: Redacted.make(utf8("password")),
            salt: utf8("somesalt"),
            memoryKiB: 32,
            passes: 3,
            parallelism: 4,
            length: 32,
          };

          for (const invalid of [
            { ...input, memoryKiB: 65537 },
            { ...input, memoryKiB: 65536, passes: 3 },
            { ...input, memoryKiB: 31 },
            { ...input, parallelism: 5 },
            { ...input, salt: new Uint8Array(7) },
          ]) {
            expect(yield* kdf.argon2id(invalid).pipe(Effect.flip)).toMatchObject({
              _tag: "CryptoInvalidInput",
            });
          }
        }).pipe(Effect.provide(backend.layer)),
      );
    }
  });
}
it.effect("keeps absolute KDF bounds when application resource ceilings are raised", () =>
  Effect.gen(function* () {
    const kdf = yield* Kdf;
    const password = Redacted.make(new Uint8Array([1]));
    const salt = new Uint8Array(8);

    const pbkdf2 = yield* kdf
      .pbkdf2({ password, salt, iterations: 2 ** 32, length: 32 })
      .pipe(Effect.flip);

    const argon2 = yield* kdf
      .argon2id({ password, salt, memoryKiB: 8, passes: 2 ** 32, parallelism: 1, length: 32 })
      .pipe(Effect.flip);

    expect([pbkdf2, argon2]).toMatchObject([
      { _tag: "CryptoInvalidInput" },
      { _tag: "CryptoInvalidInput" },
    ]);
  }).pipe(
    Effect.provide(
      Portable.layer(globalThis.crypto.subtle, {
        maximumIterations: 2 ** 32,
        maximumPasses: 2 ** 32,
        maximumMemoryPasses: 8 * 2 ** 32,
      }).pipe(Layer.provide(KdfAdmission.layer())),
    ),
  ),
);

// Requested port review: Argon2 H0 encodes each byte length in uint32 even when
// resource limits are raised. Oversized reported lengths avoid a 4 GiB allocation.
it.effect("retains absolute Argon2 byte-length bounds independently of resource ceilings", () =>
  Effect.gen(function* () {
    const kdf = yield* Kdf;
    const oversized = new Uint8Array(8);

    Object.defineProperty(oversized, "length", { value: 2 ** 32 });

    const input = {
      password: Redacted.make(utf8("password")),
      salt: utf8("somesalt"),
      memoryKiB: 8,
      passes: 1,
      parallelism: 1,
      length: 32,
    };

    const outcomes = yield* Effect.forEach(
      [
        { ...input, password: Redacted.make(oversized) },
        { ...input, salt: oversized },
        { ...input, secret: Redacted.make(oversized) },
        { ...input, associatedData: oversized },
      ],
      (request) =>
        kdf
          .argon2id(request)
          .pipe(Effect.match({ onFailure: (error) => error._tag, onSuccess: () => "derived" })),
    );

    expect(outcomes).toEqual([
      "CryptoInvalidInput",
      "CryptoInvalidInput",
      "CryptoInvalidInput",
      "CryptoInvalidInput",
    ]);
  }).pipe(
    Effect.provide(
      Portable.layer(globalThis.crypto.subtle, { maximumInputBytes: 2 ** 32 }).pipe(
        Layer.provide(KdfAdmission.layer()),
      ),
    ),
  ),
);
