import * as Aead from "effect/crypto/Aead";
import * as CryptoError from "effect/crypto/CryptoError";
import * as KeyFormat from "effect/crypto/KeyFormat";
import * as Mac from "effect/crypto/Mac";
import * as Signature from "effect/crypto/Signature";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";

import { InvalidKey } from "./Errors";
import { algorithms, sanitizeCryptoError } from "./internal/algorithms";
import { decode, reveal } from "./internal/encoding";
import * as KeyInput from "./internal/keyInput";

export const AsymmetricAlgorithm = Schema.Literals(["RS256", "PS256", "ES256", "EdDSA"]);
export type AsymmetricAlgorithm = typeof AsymmetricAlgorithm.Type;
export const Algorithm = Schema.Literals(["HS256", "RS256", "PS256", "ES256", "EdDSA"]);
export type Algorithm = typeof Algorithm.Type;

const encodedBytes = Schema.String.check(
  Schema.isPattern(/^[A-Za-z0-9_-]+$/),
  Schema.isMaxLength(16384),
);

const operations = Schema.Array(Schema.NonEmptyString).check(
  Schema.isMaxLength(KeyInput.maxArrayLength),
  Schema.makeFilter((values) => new Set(values).size === values.length),
);

const metadata = {
  kid: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(256))),
  alg: Schema.optionalKey(Schema.NonEmptyString),
  use: Schema.optionalKey(Schema.Literals(["sig", "enc"])),
  key_ops: Schema.optionalKey(operations),
  /** Optional issuer restriction published with a public key. */
  issuer: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(2048))),
};

const rsa = { ...metadata, kty: Schema.Literal("RSA"), n: encodedBytes, e: encodedBytes };

const ec = {
  ...metadata,
  kty: Schema.Literal("EC"),
  crv: Schema.Literal("P-256"),
  x: encodedBytes,
  y: encodedBytes,
};

const okp = {
  ...metadata,
  kty: Schema.Literal("OKP"),
  crv: Schema.Literal("Ed25519"),
  x: encodedBytes,
};

const noSecret = { d: Schema.optionalKey(Schema.Never), k: Schema.optionalKey(Schema.Never) };

export const PublicJwk = Schema.Union([
  Schema.Struct({ ...rsa, ...noSecret }),
  Schema.Struct({ ...ec, ...noSecret }),
  Schema.Struct({ ...okp, ...noSecret }),
]);

export type PublicJwk = typeof PublicJwk.Type;

export const PrivateJwk = Schema.Union([
  Schema.Struct({
    ...rsa,
    d: encodedBytes,
    p: encodedBytes,
    q: encodedBytes,
    dp: encodedBytes,
    dq: encodedBytes,
    qi: encodedBytes,
    oth: Schema.optionalKey(Schema.Never),
  }),
  Schema.Struct({ ...ec, d: encodedBytes }),
  Schema.Struct({ ...okp, d: encodedBytes }),
]);

export type PrivateJwk = typeof PrivateJwk.Type;

export const SecretJwk = Schema.Struct({
  ...metadata,
  kty: Schema.Literal("oct"),
  k: encodedBytes,
});

export type SecretJwk = typeof SecretJwk.Type;

export const GenerateKeyPairInput = Schema.Union([
  Schema.Struct({
    algorithm: Schema.Literals(["RS256", "PS256"]),
    modulusLength: Schema.optionalKey(Schema.Literals([2048, 3072, 4096])),
    kid: metadata.kid,
  }),
  Schema.Struct({ algorithm: Schema.Literals(["ES256", "EdDSA"]), kid: metadata.kid }),
]);

export type GenerateKeyPairInput = typeof GenerateKeyPairInput.Type;

export const GeneratedKeyPair = Schema.Struct({
  publicKey: PublicJwk,
  privateKey: Schema.Redacted(PrivateJwk, { disallowJsonEncode: true }),
});

export type GeneratedKeyPair = typeof GeneratedKeyPair.Type;

/** Validated, algorithm-bound key snapshots. Private material remains Redacted. */
export interface PublicKey {
  readonly _tag: "PublicKey";
  readonly algorithm: AsymmetricAlgorithm;
  readonly jwk: PublicJwk;
  readonly material: Signature.PublicKey;
}

export interface PrivateKey {
  readonly _tag: "PrivateKey";
  readonly algorithm: AsymmetricAlgorithm;
  readonly jwk: Redacted.Redacted<PrivateJwk>;
  readonly material: Redacted.Redacted<Signature.PrivateKey>;
}

export type SecretKey = {
  readonly _tag: "SecretKey";
  readonly jwk: Redacted.Redacted<SecretJwk>;
} & (
  | { readonly algorithm: "HS256"; readonly material: Redacted.Redacted<Mac.Key> }
  | { readonly algorithm: "dir"; readonly material: Redacted.Redacted<Aead.Key> }
);

export type SigningKey = PrivateKey | SecretKey;
export type VerificationKey = PublicKey | SecretKey;

/** Generate signing JWKs through Effect's selected Signature service. */
export const generateKeyPair = Effect.fnUntraced(
  function* (input: GenerateKeyPairInput) {
    const value = yield* read(GenerateKeyPairInput, input);
    const signatures = yield* Signature.Signature;

    const pair =
      value.algorithm === "ES256"
        ? yield* signatures.generateKeyPair(Signature.ecdsaP256)
        : value.algorithm === "EdDSA"
          ? yield* signatures.generateKeyPair(Signature.ed25519)
          : value.algorithm === "RS256"
            ? yield* signatures.generateKeyPair({
                ...algorithms.RS256,
                modulusLength: ("modulusLength" in value ? value.modulusLength : undefined) ?? 2048,
              })
            : yield* signatures.generateKeyPair({
                ...algorithms.PS256,
                modulusLength: ("modulusLength" in value ? value.modulusLength : undefined) ?? 2048,
              });

    const metadata = {
      alg: value.algorithm,
      use: "sig",
      ...(value.kid === undefined ? {} : { kid: value.kid }),
    };

    const publicKey = yield* read(PublicJwk, {
      ...(yield* KeyFormat.encode(KeyFormat.jwk, pair.publicKey)),
      ...metadata,
    });

    const privateKey = yield* read(PrivateJwk, {
      ...(yield* KeyFormat.encode(KeyFormat.jwk, pair.privateKey)),
      ...metadata,
    });

    return { publicKey, privateKey: Redacted.make(privateKey) } satisfies GeneratedKeyPair;
  },
  Effect.mapError((error) =>
    CryptoError.isCryptoError(error) ? sanitizeCryptoError(error) : error,
  ),
);

const read = <S extends Schema.Constraint>(schema: S, input: unknown) =>
  Effect.try({
    try: () => KeyInput.jwk(input),
    catch: () => InvalidKey.make({}),
  }).pipe(
    Effect.flatMap(Effect.fromResult),
    Effect.flatMap((captured) =>
      Schema.decodeUnknownEffect(schema)(captured, { reportInput: false }).pipe(
        Effect.mapError(() => InvalidKey.make({})),
      ),
    ),
    Effect.map(KeyInput.detach),
  );

const bytes = (value: string) => decode(value).pipe(Effect.mapError(() => InvalidKey.make({})));

const snapshot = <A extends PublicJwk | PrivateJwk | SecretJwk>(jwk: A): A => {
  if (jwk.key_ops !== undefined) Object.freeze(jwk.key_ops);

  return Object.freeze(jwk);
};

/** JOSE signing policy requires RSA moduli of at least 2048 bits. */
const checkModulus = Effect.fnUntraced(function* (jwk: PublicJwk | PrivateJwk) {
  if (jwk.kty !== "RSA") return;
  const modulus = yield* bytes(jwk.n);
  const first = modulus.findIndex((byte) => byte !== 0);

  const bitLength =
    first < 0 ? 0 : (modulus.length - first - 1) * 8 + 32 - Math.clz32(modulus[first]!);

  if (bitLength < 2048 || bitLength > 8192) return yield* InvalidKey.make({});
});

export const importPublic = Effect.fnUntraced(function* (
  input: unknown,
  selected: AsymmetricAlgorithm,
) {
  const algorithm = yield* read(AsymmetricAlgorithm, selected);
  const jwk = yield* read(PublicJwk, input);

  yield* checkModulus(jwk);

  const material = yield* KeyFormat.decodePublic(KeyFormat.jwk, algorithms[algorithm], {
    ...jwk,
    key_ops: [...(jwk.key_ops ?? [])],
  }).pipe(Effect.mapError(() => InvalidKey.make({})));

  return Object.freeze({
    _tag: "PublicKey",
    algorithm,
    jwk: snapshot(jwk),
    material,
  }) satisfies PublicKey;
});

export const importPrivate = Effect.fnUntraced(function* (
  input: Redacted.Redacted<unknown>,
  selected: AsymmetricAlgorithm,
) {
  const algorithm = yield* read(AsymmetricAlgorithm, selected);

  const jwk = yield* read(
    PrivateJwk,
    yield* reveal(input).pipe(Effect.mapError(() => InvalidKey.make({}))),
  );

  yield* checkModulus(jwk);

  const material = yield* KeyFormat.decodePrivate(KeyFormat.jwk, algorithms[algorithm], {
    ...jwk,
    key_ops: [...(jwk.key_ops ?? [])],
  }).pipe(Effect.mapError(() => InvalidKey.make({})));

  return Object.freeze({
    _tag: "PrivateKey",
    algorithm,
    jwk: Redacted.make(snapshot(jwk)),
    material: Redacted.make(material),
  }) satisfies PrivateKey;
});

/** Import PKCS8 DER through Effect's key-format decoder and bind its JWK metadata. */
export const importPkcs8 = Effect.fnUntraced(function* (
  input: Redacted.Redacted<Uint8Array>,
  selected: AsymmetricAlgorithm,
  options?: { readonly kid?: string },
) {
  const algorithm = yield* read(AsymmetricAlgorithm, selected);

  const material = yield* KeyFormat.decodePrivate(
    KeyFormat.pkcs8,
    algorithms[algorithm],
    yield* reveal(input),
  ).pipe(Effect.mapError(() => InvalidKey.make({})));

  const jwk = yield* read(PrivateJwk, {
    ...(yield* KeyFormat.encode(KeyFormat.jwk, material)),
    alg: algorithm,
    use: "sig",
    ...(options?.kid === undefined ? {} : { kid: options.kid }),
  });

  yield* checkModulus(jwk);

  return Object.freeze({
    _tag: "PrivateKey",
    algorithm,
    jwk: Redacted.make(snapshot(jwk)),
    material: Redacted.make(material),
  }) satisfies PrivateKey;
});

export const importSecret = Effect.fnUntraced(function* (
  input: Redacted.Redacted<unknown>,
  selected: "HS256" | "dir",
) {
  const algorithm = yield* read(Schema.Literals(["HS256", "dir"]), selected);

  const jwk = yield* read(
    SecretJwk,
    yield* reveal(input).pipe(Effect.mapError(() => InvalidKey.make({}))),
  );

  const material = yield* bytes(jwk.k);

  if (
    (jwk.alg !== undefined && jwk.alg !== algorithm) ||
    material.length < 32 ||
    (algorithm === "dir" && material.length !== 32)
  ) {
    material.fill(0);

    return yield* InvalidKey.make({});
  }

  const common = { _tag: "SecretKey" as const, jwk: Redacted.make(snapshot(jwk)) };

  if (algorithm === "HS256") {
    const key = yield* Mac.key(Mac.hmacSha256, material).pipe(
      Effect.ensuring(Effect.sync(() => material.fill(0))),
    );

    return Object.freeze({
      ...common,
      algorithm,
      material: Redacted.make(key),
    }) satisfies SecretKey;
  }

  const key = yield* Aead.key(Aead.aes256Gcm, material).pipe(
    Effect.ensuring(Effect.sync(() => material.fill(0))),
  );

  return Object.freeze({ ...common, algorithm, material: Redacted.make(key) }) satisfies SecretKey;
});

export const exportPublic = Effect.fnUntraced(function* (key: PublicKey) {
  return yield* read(PublicJwk, key.jwk);
});

export const exportPrivate = Effect.fnUntraced(function* (key: PrivateKey | SecretKey) {
  const value = yield* reveal<PrivateJwk | SecretJwk>(key.jwk).pipe(
    Effect.mapError(() => InvalidKey.make({})),
  );

  return Redacted.make(yield* read(Schema.Union([PrivateJwk, SecretJwk]), value));
});
