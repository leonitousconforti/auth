import { Effect, Redacted, Schema } from "effect";
import { Cookies } from "effect/http";

import { origin } from "../internal/origin";
import type { CredentialSlot } from "../operations/credentials";
import { SessionCacheGeneration } from "../sessions/cookieCache";
import { OperationHttpError } from "./errors";
import { credentialSlots } from "./models";
import { OperationHttpServerConfig } from "./OperationHttpServerConfig";
import { generationCookieConfiguration, optionalCookie } from "./session-cache-cookie";

/** Browser mutation admission is independent of body encoding. */
export const mutationSecurity = Effect.fnUntraced(function* (request: Request) {
  const config = yield* OperationHttpServerConfig;
  const requestOrigin = request.headers.get("origin");

  if (
    ["GET", "HEAD", "OPTIONS"].includes(request.method) ||
    requestOrigin === null ||
    !config.trustedOrigins.includes(requestOrigin)
  )
    return yield* OperationHttpError.make({ reason: "origin" });
  if (request.headers.get(config.csrfHeader) !== config.csrfValue)
    return yield* OperationHttpError.make({ reason: "csrf" });
});

export const requestSecurity = Effect.fnUntraced(function* (
  request: Request,
  kind: "operation" | "callback" | "read" | "request",
) {
  const config = yield* OperationHttpServerConfig;

  const publicOrigin =
    typeof config.publicOrigin === "string"
      ? config.publicOrigin
      : yield* config.publicOrigin(request);

  if (!Schema.is(origin)(publicOrigin)) return yield* OperationHttpError.make({ reason: "origin" });
  const requestOrigin = request.headers.get("origin");

  const native =
    config.native !== undefined && request.headers.get(config.native.modeHeader) === "native";

  if (native) {
    if (
      kind === "callback" ||
      requestOrigin !== null ||
      request.headers.has("sec-fetch-mode") ||
      request.headers.has("cookie")
    )
      return yield* OperationHttpError.make({ reason: "origin" });
    yield* config.native!.authorize(request);
  } else if (kind === "operation") {
    yield* mutationSecurity(request);
    if (
      request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase() !==
      "application/json"
    )
      return yield* OperationHttpError.make({ reason: "csrf" });
  }
  if (kind === "read" && requestOrigin !== null && !config.trustedOrigins.includes(requestOrigin))
    return yield* OperationHttpError.make({ reason: "origin" });
  const rawCookie = request.headers.get("cookie") ?? "";

  if (rawCookie.length > 65536) return yield* OperationHttpError.make({ reason: "too-large" });
  const parts = rawCookie.split(";");
  const cacheName = config.cookies["session-cache"].name;
  const generationName = generationCookieConfiguration(config.cookies["session-cache"]).name;

  const authoritativeCookie = parts
    .filter((part) => ![cacheName, generationName].includes(part.trim().split("=", 1)[0]))
    .join(";");

  const parsed = Cookies.parseHeader(authoritativeCookie);
  const credentials: Partial<Record<CredentialSlot, Redacted.Redacted<string>>> = {};

  for (const slot of credentialSlots) {
    const configured = config.cookies[slot];

    if (slot === "session-cache") {
      const value = native ? undefined : optionalCookie(parts, cacheName);

      if (value !== undefined) credentials[slot] = Redacted.make(value);
      continue;
    }
    const cookies = parts.filter((part) => part.trim().split("=", 1)[0] === configured.name);

    if (cookies.length > 1) return yield* OperationHttpError.make({ reason: "credentials" });

    const header =
      config.native === undefined ? null : request.headers.get(config.native.requestHeaders[slot]);

    if (!native && header !== null)
      return yield* OperationHttpError.make({ reason: "credentials" });
    const value = native ? header : parsed[configured.name];

    if (value !== null && value !== undefined) {
      if (value.length === 0 || value.length > 16384 || /[\r\n]/.test(value))
        return yield* OperationHttpError.make({ reason: "credentials" });
      credentials[slot] = Redacted.make(value);
    }
  }

  const generation = native ? undefined : optionalCookie(parts, generationName);

  return {
    native,
    credentials: Object.freeze(credentials),
    publicOrigin,
    requestOrigin,
    ...(Schema.is(SessionCacheGeneration)(generation)
      ? { sessionCacheGeneration: Redacted.make(generation) }
      : {}),
  };
});
