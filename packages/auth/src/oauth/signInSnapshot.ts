import { DateTime, Effect, Predicate, Schema } from "effect";

import { OAuthUnavailable } from "./signInErrors";

/** Freeze a detached, validated graph before retaining it or passing it to a
 * callback. This does not validate or copy input; use snapshotOAuth to do both. */
export const freezeOAuth = (value: unknown): void => {
  if (!Predicate.isObjectOrArray(value) || Object.isFrozen(value)) return;
  if (DateTime.isDateTime(value)) Object.freeze(DateTime.toPartsUtc(value));
  for (const child of Object.values(value)) freezeOAuth(child);
  Object.freeze(value);
};

/** Compile once for a stable schema; each call still validates, detaches through
 * JSON and recursively freezes its own result. Retains no snapshot values. */
export const makeOAuthSnapshot = <S extends Schema.Codec<unknown, unknown, never, never>>(
  schema: S,
) => {
  let detach: ((value: S["Type"]) => S["Type"]) | undefined;

  const sync = (value: S["Type"]): S["Type"] => {
    try {
      if (detach === undefined) {
        const codec = Schema.fromJsonString(Schema.toCodecJson(Schema.toType(schema)));
        const encode = Schema.encodeSync(codec);
        const decode = Schema.decodeSync(codec);

        detach = (input) => decode(encode(input));
      }
      // JSON fields can otherwise retain nested input references through validation.
      const result = detach(value);

      freezeOAuth(result);

      return result;
    } catch {
      throw OAuthUnavailable.make({});
    }
  };

  return {
    sync,
    effect: (value: S["Type"]) =>
      Effect.try({
        try: () => sync(value),
        catch: () => OAuthUnavailable.make({}),
      }),
  };
};

export const snapshotOAuthSync = <S extends Schema.Codec<unknown, unknown, never, never>>(
  schema: S,
  value: S["Type"],
): S["Type"] => {
  try {
    return makeOAuthSnapshot(schema).sync(value);
  } catch {
    throw OAuthUnavailable.make({});
  }
};

export const snapshotOAuth = <S extends Schema.Codec<unknown, unknown, never, never>>(
  schema: S,
  value: S["Type"],
) =>
  Effect.try({
    try: () => snapshotOAuthSync(schema, value),
    catch: () => OAuthUnavailable.make({}),
  });
