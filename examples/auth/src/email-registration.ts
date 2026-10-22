import * as SqliteClient from "@effect/sql-sqlite-bun/SqliteClient";
import {
  Auth,
  Email,
  EmailDelivery,
  Hooks,
  Operations,
  Proofs,
  Schema as AuthSchema,
  Sessions,
  WebCrypto,
} from "@yielded/auth";
import { AuthPersistence } from "@yielded/auth-persistence";
import { Effect, Layer, Redacted, Schema } from "effect";
import { Base64Url } from "effect/encoding";
import { SqlClient } from "effect/sql";

const AppAuth = Auth.make("example/email-registration", {
  claims: Schema.Struct({ displayName: Schema.String }),
  sessions: Sessions.stateful(),
  strategies: { email: Email.makeCode() },
  defaultStrategy: "email",
});

const members = AuthPersistence.table({
  name: "members",
  columns: {
    id: { name: "id", type: "text" },
    active: { name: "active", type: "boolean" },
    revision: { name: "revision", type: "text" },
    displayName: { name: "display_name", type: "text" },
  },
  unique: [["id"]],
});

const Persistence = AuthPersistence.make(AppAuth);

const storage = Persistence.managed({
  prefix: "member_auth",
  subjects: {
    table: members,
    id: "id",
    status: "active",
    activeValue: true,
    securityRevision: "revision",
    idCodec: AuthSchema.SubjectId,
    createFromEmail: (email) =>
      Effect.sync(() => ({ id: crypto.randomUUID(), displayName: email })),
    requirements: () =>
      Effect.succeed({
        alternatives: [
          {
            factors: ["possession"],
            minimumCredentials: 1,
            userVerified: false,
            phishingResistant: false,
          },
        ],
        maximumAgeMillis: 300_000,
      }),
  },
});

const PersistenceLive = Persistence.layer.pipe(Layer.provide(Persistence.Config.layer(storage)));

const ClaimsLive = Layer.effect(
  AppAuth.strategies.email.SessionClaims,
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;

    return {
      resolve: ({ subjectId }) =>
        sql`select display_name as "displayName" from members where id = ${subjectId}`.pipe(
          Effect.flatMap((rows) => Schema.decodeUnknownEffect(AppAuth.claims)(rows[0])),
          Effect.mapError(() => Email.EmailUnavailable.make({})),
        ),
    };
  }),
);

// Disposable example setup. Applications keep their own versioned migrations.
const createTables = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;
  const quote = (name: string) => '"' + name.replaceAll('"', '""') + '"';

  for (const table of [members, ...Object.values(storage.schema)]) {
    const columns = Object.values(table.columns).map(
      ({ options }) =>
        `${quote(options.name)} ${options.type === "text" ? "text" : "integer"}${options.nullable ? "" : " not null"}`,
    );

    const keys = table.unique.map(
      (key) => `unique (${key.map((name) => quote(table.columns[name].options.name)).join(", ")})`,
    );

    yield* sql.unsafe(`create table ${quote(table.name)} (${[...columns, ...keys].join(", ")})`);
  }
});

export const emailRegistration = Effect.gen(function* () {
  yield* createTables;
  const sql = yield* SqlClient.SqlClient;
  const deliveries: EmailDelivery.EmailMessage[] = [];
  const commands: Operations.AuthCredentialCommand[] = [];

  // Demo-only key material. Production requires independently generated keys.
  const keys = {
    activeKeyId: "example",
    keys: [
      { id: "example", material: Redacted.make(Base64Url.encode(new Uint8Array(32).fill(42))) },
    ],
  };

  const dependencies = Layer.mergeAll(
    PersistenceLive,
    ClaimsLive,
    Proofs.ProofKeys.layer(keys),
    Auth.RequestBindingConfig.layer({ keyring: keys, lifetimeMillis: 300_000, generation: 1 }),
    Email.EmailReturnTargets.exactRoutes(["/account"]),
    Layer.succeed(EmailDelivery.EmailDelivery, {
      send: (message) =>
        Effect.sync(() => {
          deliveries.push(message);
        }),
    }),
  );

  return yield* Effect.gen(function* () {
    const auth = yield* AppAuth;

    const signIn = Effect.fn("EmailRegistration.signIn")(function* (flowId: string) {
      yield* auth.beginSignIn({ flowId });

      const binding = [...commands]
        .reverse()
        .find((command) => command._tag === "Issue" && command.slot === "request-binding");

      if (binding?._tag !== "Issue") return yield* Effect.die("request binding was not issued");

      const input = {
        flowId,
        requestBinding: Redacted.value(binding.credential),
        email: "reader@example.invalid",
        returnTarget: "/account",
      };

      const before = yield* sql`select id from members`;
      const requested = yield* auth.signIn({ ...input, requestId: flowId, locale: "en" });
      const after = yield* sql`select id from members`;

      if (before.length !== after.length)
        return yield* Effect.die("requesting a code created an account");
      const message = deliveries[deliveries.length - 1];

      if (!message) return yield* Effect.die("email code was not delivered");

      const completed = yield* auth.completeSignIn({
        ...input,
        reference: requested.reference,
        secret: Redacted.value(message.text).match(/code is ([0-9]+)/)?.[1] ?? "",
      });

      if (completed.completion._tag !== "Authenticated")
        return yield* Effect.die("email code did not establish a session");

      return completed.completion.session;
    });

    const first = yield* signIn("new-member");
    const returning = yield* signIn("returning-member");
    const rows = yield* sql`select id from members`;

    if (rows.length !== 1 || first.subjectId !== returning.subjectId)
      return yield* Effect.die("returning sign-in created another account");

    return {
      consumer: "composed-email-registration",
      accounts: rows.length,
      sessions: "new-and-returning",
    };
  }).pipe(
    Effect.provideService(Auth.AuthRequest, {
      invocation: Operations.guest,
      credentials: {},
      credentialCommandSink: (batch) =>
        Effect.sync(() => {
          commands.push(...batch);
        }),
    }),
    Effect.provideService(
      Proofs.ProofRequestContext,
      Effect.succeed({ networkKey: Redacted.make("email-registration-example") }),
    ),
    Effect.provide(AppAuth.layer.pipe(Layer.provide(dependencies))),
  );
}).pipe(
  Effect.provide(
    Layer.mergeAll(
      SqliteClient.layer({ filename: ":memory:" }),
      WebCrypto.layerWebCrypto,
      Hooks.LifecycleHooks.empty,
      Proofs.ProofDispatchScheduler.layerInline,
    ),
  ),
  Effect.scoped,
);
