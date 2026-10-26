import { it } from "@effect/vitest";
import {
  Auth,
  Hooks,
  Http,
  OperationHttpClient,
  Schema as AuthSchema,
  Sessions,
  WebCrypto,
} from "@yielded/auth";
import * as Cause from "effect/Cause";
import * as Context from "effect/Context";
import * as DateTime from "effect/DateTime";
import * as Deferred from "effect/Deferred";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Fiber from "effect/Fiber";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientResponse from "effect/http/HttpClientResponse";
import * as HttpServerRequest from "effect/http/HttpServerRequest";
import * as HttpServerResponse from "effect/http/HttpServerResponse";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import * as Stream from "effect/Stream";
import * as TestClock from "effect/testing/TestClock";
import { expect } from "vite-plus/test";

const origin = "https://example.test";
const app = Auth.make("test/session-maintenance", { claims: Schema.Struct({}) });
const http = Http.make(app, { origin });

const policy = Sessions.stateless({
  maxAge: "1 minute",
  idleTimeout: "10 seconds",
  renewAfter: "5 seconds",
}).policy(app.sessions.moduleId);

const requirement = Sessions.AuthenticationRequirement.make({
  alternatives: [
    {
      factors: ["knowledge"],
      minimumCredentials: 1,
      userVerified: false,
      phishingResistant: false,
    },
  ],
  maximumAgeMillis: 60_000,
});

const fixture = Effect.gen(function* () {
  const events: string[] = [];

  const infrastructure = Layer.mergeAll(
    WebCrypto.layerWebCrypto,
    Layer.succeed(Sessions.SessionSigningKeys, {
      activeKeyId: "test",
      keys: [
        { id: "test", material: Redacted.make("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") },
      ],
    }),
    Layer.succeed(Hooks.LifecycleHooks, {
      before: () => Effect.void,
      after: (event) =>
        Effect.sync(() => {
          events.push(event.id);

          return [];
        }),
    }),
    Layer.succeed(Sessions.AuthenticationAuthority, {
      capture: () => Effect.die("This fixture supplies verified authentication evidence"),
      requirements: () => Effect.succeed(requirement),
      approve: (_input, prepare) =>
        Hooks.coordinateCommit((journal) => Effect.sync(() => prepare(undefined, journal))).pipe(
          Effect.map((result) => result.value),
          Effect.orDie,
          Effect.provide(Hooks.LifecycleHooks.empty),
        ),
    }),
  );

  const strategyLayer = app.sessions.statelessLayer(policy).pipe(Layer.provide(infrastructure));

  const context = yield* Layer.build(
    app.layer.pipe(Layer.provideMerge(strategyLayer), Layer.provideMerge(infrastructure)),
  );

  const strategy = Context.get(context, app.sessions.SessionStrategy);

  const prepared = yield* strategy
    .prepareEstablish({
      evidence: Sessions.AuthenticationEvidence.make({
        revision: {
          subjectId: AuthSchema.SubjectId.make("member"),
          securityRevision: Sessions.SecurityRevision.make("1"),
          credentials: [
            { credentialId: "password", revision: Sessions.SecurityRevision.make("1") },
          ],
        },
        flowId: Sessions.AuthenticationFlowId.make("maintenance"),
        bindingDigest: AuthSchema.TokenDigest.make("maintenance-binding"),
        proofs: [
          {
            method: "password",
            credentialId: "password",
            factors: ["knowledge"],
            userVerified: false,
            phishingResistant: false,
            verifiedAt: yield* DateTime.now,
          },
        ],
      }),
      requirement,
      claims: {},
    })
    .pipe(Effect.provide(context));

  const issued = yield* prepared.read;
  const command = issued.credentialCommands.find((value) => value._tag === "Issue");

  if (command === undefined) return yield* Effect.die("Missing fixture credential");
  events.length = 0;

  return { context, strategy, credential: command.credential, events };
});

const request = (credential: Redacted.Redacted<string>) =>
  HttpServerRequest.fromWeb(
    new Request(`${origin}/account`, {
      headers: { cookie: `__Host-effect-auth-session=${Redacted.value(credential)}` },
    }),
  );

const read = Effect.gen(function* () {
  const auth = yield* app;

  yield* auth.requireSession;

  return HttpServerResponse.empty();
});

// https://github.com/yielded-dev/auth/commit/001e478c8010216fc15c5897d054b68483e802d1
// introduced automatic credential delivery. These regressions require
// controlled response ordering and concurrent reads, which sequential examples
// and the session lifetime tests do not exercise.
it.effect.each(["3 seconds", "5 seconds"] as const)(
  "does not let an older read replace a newer cookie after %s",
  (delay) =>
    Effect.gen(function* () {
      const { context, credential } = yield* fixture;
      const entered = yield* Deferred.make<void>();
      const release = yield* Deferred.make<void>();

      const delayed = yield* http
        .withRequest(
          read.pipe(
            Effect.tap(() => Deferred.succeed(entered, undefined)),
            Effect.tap(() => Deferred.await(release)),
          ),
        )
        .pipe(
          Effect.provideService(HttpServerRequest.HttpServerRequest, request(credential)),
          Effect.provide(context),
          Effect.forkChild,
        );

      yield* Deferred.await(entered);
      yield* TestClock.adjust("6 seconds");

      const renewed = yield* http
        .withRequest(read)
        .pipe(
          Effect.provideService(HttpServerRequest.HttpServerRequest, request(credential)),
          Effect.provide(context),
        );

      expect(HttpServerResponse.toWeb(renewed).headers.getSetCookie().length).toBe(1);
      yield* TestClock.adjust(delay);
      yield* Deferred.succeed(release, undefined);
      const late = yield* Fiber.join(delayed);

      expect(HttpServerResponse.toWeb(late).headers.getSetCookie().length).toBe(0);
    }),
);

it.effect("shares one signed maintenance result across parallel reads of one request", () =>
  Effect.gen(function* () {
    const { context, credential, events } = yield* fixture;

    yield* TestClock.adjust("6 seconds");
    yield* http
      .withRequest(
        Effect.gen(function* () {
          const auth = yield* app;

          const sessions = yield* Effect.all([auth.requireSession, auth.requireSession], {
            concurrency: 2,
          });

          expect(sessions.map((session) => DateTime.toEpochMillis(session.expiresAt))).toEqual([
            16_000, 16_000,
          ]);

          return HttpServerResponse.empty();
        }),
      )
      .pipe(
        Effect.provideService(HttpServerRequest.HttpServerRequest, request(credential)),
        Effect.provide(context),
      );
    expect(events).toHaveLength(1);
  }),
);

// Composite failures are not reliably inducible with a live crypto provider;
// replace only refresh on the complete real strategy at its public service seam.
it.effect("preserves a cleanup defect accompanying an invalid maintenance credential", () =>
  Effect.gen(function* () {
    const { context, credential, strategy } = yield* fixture;

    const broken = app.sessions.SessionStrategy.of({
      ...strategy,
      refresh: () =>
        Effect.failCause(
          Cause.fromReasons([
            Cause.makeFailReason(Sessions.SessionInvalid.make({})),
            Cause.makeDieReason("cleanup failed"),
          ]),
        ),
    });

    const auth = yield* app.make.pipe(
      Effect.provideService(app.sessions.SessionStrategy, broken),
      Effect.provide(context),
    );

    yield* TestClock.adjust("6 seconds");

    const result = yield* http
      .withRequest(read)
      .pipe(
        Effect.provideService(HttpServerRequest.HttpServerRequest, request(credential)),
        Effect.provideService(app, auth),
        Effect.provide(context),
        Effect.exit,
      );

    expect(Exit.isFailure(result) && Cause.hasDies(result.cause)).toBe(true);
  }),
);

it.effect("admits a queued credential mutation before newer maintenance reads", () =>
  Effect.gen(function* () {
    const entered = yield* Deferred.make<void>();
    const release = yield* Deferred.make<void>();
    const calls: string[] = [];

    const transport = HttpClient.make((request) =>
      Effect.gen(function* () {
        const mutation = new URL(request.url).pathname === app.contract.actions.signOut.route.path;

        calls.push(mutation ? "mutation" : "read");
        if (calls.length === 1) {
          yield* Deferred.succeed(entered, undefined);
          yield* Deferred.await(release);
        }

        return HttpClientResponse.fromWeb(
          request,
          Response.json({
            _tag: "Success",
            value: mutation ? { clearCredential: true, invalidation: "already-invalid" } : null,
          }),
        );
      }),
    );

    const client = yield* OperationHttpClient.make({
      baseUrl: origin,
      csrfHeader: "x-csrf",
      csrfValue: "1",
    }).pipe(Effect.provideService(HttpClient.HttpClient, transport));

    const first = yield* client
      .call(app.contract.actions.getSession.route, undefined)
      .pipe(Effect.forkChild);

    yield* Deferred.await(entered);

    const mutation = yield* client
      .call(app.contract.actions.signOut.route, undefined)
      .pipe(Effect.forkChild);

    yield* Effect.yieldNow;

    const second = yield* client
      .call(app.contract.actions.getSession.route, undefined)
      .pipe(Effect.forkChild);

    yield* Effect.yieldNow;
    yield* Deferred.succeed(release, undefined);
    yield* Effect.all([Fiber.join(first), Fiber.join(mutation), Fiber.join(second)], {
      concurrency: 3,
    });

    expect(calls).toEqual(["read", "mutation", "read"]);
  }),
);

// https://github.com/yielded-dev/auth/commit/001e478c8010216fc15c5897d054b68483e802d1
// Native headers can expire while the response body is consumed. The response
// ordering tests above do not cover client-side expiry or its credential store.
it.effect(
  "discards expired optional native maintenance without weakening credential validation",
  () =>
    Effect.gen(function* () {
      class Credentials extends Context.Service<
        Credentials,
        OperationHttpClient.NativeCredentials
      >()("test/session-maintenance/Credentials") {}

      const headers = {
        session: "x-session",
        "session-cache": "x-session-cache",
        "pending-proof": "x-pending-proof",
        registration: "x-registration",
        "request-binding": "x-request-binding",
        "session-step-up": "x-session-step-up",
      };

      const consuming = yield* Deferred.make<void>();
      const release = yield* Deferred.make<void>();
      let responseHeader = headers.session;
      let accepted = 0;

      const transport = HttpClient.make((request) =>
        Effect.gen(function* () {
          const mutation =
            new URL(request.url).pathname === app.contract.actions.signOut.route.path;

          const body = yield* Stream.toReadableStreamEffect(
            Stream.fromEffect(
              Effect.gen(function* () {
                yield* Deferred.succeed(consuming, undefined);
                yield* Deferred.await(release);

                return new TextEncoder().encode(
                  JSON.stringify({
                    _tag: "Success",
                    value: mutation
                      ? { clearCredential: true, invalidation: "already-invalid" }
                      : null,
                  }),
                );
              }),
            ),
          );

          return HttpClientResponse.fromWeb(
            request,
            new Response(body, {
              headers: {
                "content-type": "application/json",
                [responseHeader]: JSON.stringify({
                  _tag: "Issue",
                  credential: "synthetic-maintenance-credential",
                  expiresAtMillis: 1_000,
                }),
              },
            }),
          );
        }),
      );

      const client = yield* OperationHttpClient.make({
        baseUrl: origin,
        csrfHeader: "x-csrf",
        csrfValue: "1",
        native: {
          modeHeader: "x-mode",
          requestHeaders: headers,
          responseHeaders: headers,
          credentials: Credentials,
        },
      }).pipe(
        Effect.provideService(HttpClient.HttpClient, transport),
        Effect.provideService(Credentials, {
          read: Effect.succeed({ session: Redacted.make("synthetic-existing-credential") }),
          accept: () =>
            Effect.sync(() => {
              accepted++;
            }),
        }),
      );

      const pending = yield* client
        .call(app.contract.actions.getSession.route, undefined)
        .pipe(Effect.result, Effect.forkChild);

      yield* Deferred.await(consuming);
      yield* TestClock.adjust("2 seconds");
      yield* Deferred.succeed(release, undefined);
      const maintenance = yield* Fiber.join(pending);

      const explicit = yield* client
        .call(app.contract.actions.signOut.route, undefined)
        .pipe(Effect.result);

      expect(explicit).toMatchObject({
        _tag: "Failure",
        failure: { _tag: "OperationHttpError", reason: "credentials" },
      });
      responseHeader = headers["request-binding"];

      const unexpected = yield* client
        .call(app.contract.actions.getSession.route, undefined)
        .pipe(Effect.result);

      expect(unexpected).toMatchObject({
        _tag: "Failure",
        failure: { _tag: "OperationHttpError", reason: "credentials" },
      });
      expect(accepted).toBe(0);
      expect(maintenance._tag).toBe("Success");
      if (maintenance._tag === "Success") expect(maintenance.success).toBeNull();
    }),
);
