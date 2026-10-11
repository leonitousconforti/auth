import {
  Cause,
  Context,
  Crypto,
  DateTime,
  Effect,
  Fiber,
  Layer,
  Redacted,
  Result,
  Schema,
} from "effect";
import { Base64Url } from "effect/encoding";

import { hasCommitScope, type PreparedCommit } from "../hooks/commit";
import { LifecycleHooks } from "../hooks/LifecycleHooks";
import { HookDenied, LifecycleEventId, lifecycleEvent, lifecycleSnapshot } from "../hooks/models";
import { IdentityConflict, LastSignInMethod } from "../identity/models";
import { reportAuthFailure } from "../internal/diagnostics";
import { AuthenticationClock } from "../operations/clock";
import { requireAuthenticated, type AuthInvocation } from "../operations/context";
import {
  formPostBinding,
  type AuthOperationResult,
  type AuthCredentialCommand,
} from "../operations/credentials";
import { AuthenticationRequired } from "../operations/errors";
import { makeOperation, operationGroup } from "../operations/operation";
import { makeRequestBinding } from "../operations/requestBinding";
import { CleanupResult } from "../persistence/cleanup";
import { TokenDigest } from "../Schema";
import { SessionInvalidationWindow, sessionInvalidationWindow } from "../sessions/invalidation";
import type { makeSessionModule } from "../sessions/module";
import {
  OAuthAccountRevision,
  OAuthLinkedAccount,
  OAuthLinkedAccountsList,
  OAuthLinkedAccountsListResult,
  OAuthLinkedAccountsRead,
  OAuthAccountsPolicy,
  OAuthActionAuthorization,
  OAuthActionChallenge,
  OAuthActionRequired,
  OAuthLinkAccess,
  OAuthLinkBegin,
  OAuthLinkConsumeDecision,
  OAuthLinkIntentContext,
  OAuthLinkComplete,
  OAuthLinkDecision,
  OAuthLinkIssueDecision,
  OAuthLinkFlow,
  OAuthLinkResult,
  OAuthLinkTransactionContext,
  OAuthUnlink,
  OAuthUnlinkDecision,
  OAuthUnlinked,
} from "./accountsModels";
import { authorizeOAuthEvidence } from "./actionAuthorization";
import { OAuthAccountsPersistence } from "./OAuthAccountsPersistence";
import { OAuthActionEvidence } from "./OAuthActionEvidence";
import { OAuthLinkTransactionProtector } from "./OAuthLinkTransactionProtector";
import { OAuthProtocol } from "./OAuthProtocol";
import { OAuthReturnTargets } from "./OAuthReturnTargets";
import {
  OAuthConfigurationError,
  OAuthMethodUnsupported,
  OAuthRejected,
  OAuthUnavailable,
} from "./signInErrors";
import {
  OAuthCallbackResponse,
  OAuthCleanupInput,
  OAuthCredentialSnapshot,
  OAuthModuleId,
  OAuthProtocolConfiguration,
  OAuthProtocolPreparation,
  OAuthReturnTarget,
  OAuthSealedTransaction,
  OAuthSignInAuthorization,
  OAuthTransactionSecrets,
  OAuthVerifiedExternalIdentity,
} from "./signInModels";
import { snapshotOAuth, snapshotOAuthSync } from "./signInSnapshot";

const Failure = Schema.Union([
  AuthenticationRequired,
  OAuthActionRequired,
  OAuthRejected,
  OAuthUnavailable,
  OAuthMethodUnsupported,
  IdentityConflict,
  LastSignInMethod,
  HookDenied,
]);

type Failure = typeof Failure.Type;

const read = <A>(receipt: PreparedCommit<A>) =>
  receipt.read.pipe(Effect.mapError(() => OAuthUnavailable.make({})));

const noAmbient = Effect.fn("OAuthAccounts.noAmbient")(function* () {
  if (yield* hasCommitScope) return yield* OAuthMethodUnsupported.make({});
});

// Cancellation stays on this fiber and runs finalizers before returning.
// An owner that reached commit may still have committed; its receipt is discarded, never retried.
const bounded = <A, E, R>(effect: Effect.Effect<A, E, R>, millis: number) =>
  Effect.gen(function* () {
    const fiber = yield* effect.pipe(Effect.interruptible, Effect.forkChild);

    return yield* Fiber.join(fiber).pipe(
      Effect.timeout(millis),
      Effect.ensuring(Fiber.interrupt(fiber)),
    );
  });

const encoder = new TextEncoder();
const strings = Schema.fromJsonString(Schema.Array(Schema.String));
const intentJson = Schema.fromJsonString(OAuthLinkIntentContext);
const flowJson = Schema.fromJsonString(OAuthLinkFlow);
const credentialJson = Schema.fromJsonString(OAuthCredentialSnapshot);
const responseJson = Schema.fromJsonString(OAuthCallbackResponse);
const invalidationJson = Schema.fromJsonString(SessionInvalidationWindow);

const clearChanged: ReadonlyArray<AuthCredentialCommand> = Object.freeze([
  Object.freeze({ _tag: "Clear" as const, slot: "session" as const }),
  Object.freeze({ _tag: "Clear" as const, slot: "pending-proof" as const }),
  Object.freeze({ _tag: "Clear" as const, slot: "request-binding" as const }),
]);

const clearBinding: ReadonlyArray<AuthCredentialCommand> = Object.freeze([
  Object.freeze({ _tag: "Clear" as const, slot: "request-binding" as const }),
]);

export interface AccountsModule<Id extends string> {
  readonly moduleId: Id;
  readonly kind: "oauth-accounts";
}

/** Authenticated login inventory and account mutations; no Claims, registration, login completion
 * or connected-grant authority. Method eligibility and final action policy belong
 * to the same physical persistence authority as each mutation. */
export const makeOAuthAccounts = <
  const Id extends string,
  const SessionId extends string,
  Claims extends Schema.Codec<unknown, unknown, unknown, unknown>,
>(
  moduleId: Id,
  sessions: ReturnType<typeof makeSessionModule<SessionId, Claims>>,
  configuration: OAuthAccountsPolicy,
) => {
  const binding = makeRequestBinding(moduleId, "oauth-link");

  const Accounts = Context.Service<
    AccountsModule<Id>,
    {
      readonly list: (
        invocation: AuthInvocation,
        input: OAuthLinkedAccountsList,
      ) => Effect.Effect<
        OAuthLinkedAccountsListResult,
        AuthenticationRequired | OAuthUnavailable | OAuthMethodUnsupported
      >;
      readonly begin: (
        invocation: AuthInvocation,
        input: typeof OAuthLinkBegin.Type,
      ) => Effect.Effect<AuthOperationResult<typeof OAuthSignInAuthorization.Type>, Failure>;
      readonly complete: (
        invocation: AuthInvocation,
        input: typeof OAuthLinkComplete.Type,
      ) => Effect.Effect<AuthOperationResult<typeof OAuthLinkResult.Type>, Failure>;
      readonly unlink: (
        invocation: AuthInvocation,
        input: typeof OAuthUnlink.Type,
      ) => Effect.Effect<AuthOperationResult<typeof OAuthUnlinked.Type>, Failure>;
      readonly cleanup: (limit: number) => Effect.Effect<CleanupResult, Failure>;
    }
  >(`effect-auth/oauth/${moduleId.length}:${moduleId}/Accounts`);

  let captured: OAuthAccountsPolicy | undefined;

  try {
    captured = snapshotOAuthSync(OAuthAccountsPolicy, configuration);
  } catch {
    /* Layer validates. */
  }

  const layer = Layer.effect(
    Accounts,
    Effect.gen(function* () {
      const id = yield* Schema.decodeEffect(OAuthModuleId)(moduleId).pipe(
        Effect.mapError(() => OAuthConfigurationError.make({ reason: "module" })),
      );

      if (captured === undefined) return yield* OAuthConfigurationError.make({ reason: "policy" });
      const policy = captured;
      const { issue: issueBinding, verify: verifyBinding } = yield* binding.RequestBinding;

      const {
        list: listRows,
        capture,
        issue,
        consume,
        link,
        readCredential,
        unlink,
        cleanup,
      } = yield* OAuthAccountsPersistence;

      const { verify: verifyAction } = yield* OAuthActionEvidence;
      const { prepareAuthorization, exchangeVerifiedIdentity } = yield* OAuthProtocol;
      const { resolve: resolveTarget } = yield* OAuthReturnTargets;
      const { seal, open } = yield* OAuthLinkTransactionProtector;
      const { before } = yield* LifecycleHooks;
      const { randomBytes, digest } = yield* Crypto.Crypto;
      const strategy = yield* sessions.SessionStrategy;
      const clockPolicy = yield* AuthenticationClock;

      const invalidation = snapshotOAuthSync(
        SessionInvalidationWindow,
        sessionInvalidationWindow("credential-change", strategy.capabilities, strategy.policy),
      );

      const expectedInvalidation = Schema.encodeSync(invalidationJson)(invalidation);

      const available = Effect.fn("OAuthAccounts.available")(function* (
        invocation: AuthInvocation,
      ) {
        yield* noAmbient();
        const caller = yield* requireAuthenticated(invocation);

        return yield* snapshotOAuth(OAuthLinkedAccountsRead.fields.invocation, caller);
      });

      const hash = Effect.fn("OAuthAccounts.hash")(function* (value: string) {
        const bytes = yield* digest("SHA-256", encoder.encode(value)).pipe(
          Effect.mapError(() => OAuthUnavailable.make({})),
        );

        return TokenDigest.make(Base64Url.encode(bytes));
      });

      const stateDigest = Effect.fn("OAuthAccounts.stateDigest")(function* (
        flowId: typeof OAuthLinkBegin.Type.flowId,
        provider: typeof OAuthLinkBegin.Type.provider,
        secret: Redacted.Redacted<string>,
      ) {
        const raw = Redacted.value(secret);

        if (!/^[A-Za-z0-9_-]{43}$/.test(raw)) return yield* OAuthRejected.make({});
        const bytes = Result.getOrUndefined(Base64Url.decode(raw));

        if (bytes === undefined || bytes.length !== 32 || Base64Url.encode(bytes) !== raw) {
          bytes?.fill(0);

          return yield* OAuthRejected.make({});
        }
        bytes.fill(0);

        return yield* hash(
          Schema.encodeSync(strings)([
            "effect-auth/oauth-link-state/v1",
            id,
            String(policy.generation),
            provider,
            flowId,
            raw,
          ]),
        );
      });

      const challenge = Effect.fn("OAuthAccounts.challenge")(function* (
        action: typeof OAuthActionChallenge.Type.action,
        flowId: typeof OAuthActionChallenge.Type.flowId,
        revision: OAuthAccountRevision,
        intent: string,
      ) {
        const intentDigest = yield* hash(intent);

        return snapshotOAuthSync(OAuthActionChallenge, {
          moduleId: id,
          action,
          flowId,
          revision,
          intentDigest,
          bindingDigest: yield* hash(
            Schema.encodeSync(strings)([
              "effect-auth/oauth-action/v1",
              id,
              action,
              flowId,
              intentDigest,
            ]),
          ),
        });
      });

      const authorize = Effect.fn("OAuthAccounts.authorize")(function* (
        caller: OAuthLinkedAccountsRead["invocation"],
        expected: OAuthActionChallenge,
        proof: Redacted.Redacted<string> | undefined,
        maximumAgeMillis = policy.maximumEvidenceAgeMillis,
      ) {
        const grant = yield* verifyAction({
          invocation: snapshotOAuthSync(OAuthLinkedAccountsRead.fields.invocation, caller),
          challenge: snapshotOAuthSync(OAuthActionChallenge, expected),
          ...(proof === undefined ? {} : { proof: Redacted.make(Redacted.value(proof)) }),
        });

        const accepted = yield* authorizeOAuthEvidence(
          caller,
          expected,
          grant,
          Math.min(policy.maximumEvidenceAgeMillis, maximumAgeMillis),
        ).pipe(Effect.provideService(AuthenticationClock, clockPolicy));

        const authorization = yield* snapshotOAuth(OAuthActionAuthorization, {
          challenge: expected,
          ...accepted,
        });

        return authorization;
      });

      const binderError = (error: { readonly _tag: string }) =>
        error._tag === "RequestBindingInvalid" ? OAuthRejected.make({}) : OAuthUnavailable.make({});

      const eventFor = Effect.fn("OAuthAccounts.event")(function* (
        action: "linking" | "credential-change",
        subjectId: OAuthAccountRevision["subjectId"],
      ) {
        const snapshot = lifecycleSnapshot({
          action,
          operation: `${moduleId}/accounts/${action === "linking" ? "link" : "unlink"}`,
          subjectId,
          method: "oauth",
          identifiers: [],
        });

        yield* before(snapshot);
        const bytes = yield* randomBytes(32).pipe(Effect.mapError(() => OAuthUnavailable.make({})));

        const event = lifecycleEvent({
          id: LifecycleEventId.make(Base64Url.encode(bytes)),
          occurredAtMillis: DateTime.toEpochMillis(yield* DateTime.now),
          snapshot,
        });

        bytes.fill(0);

        return event;
      });

      const begin = Effect.fn("OAuthAccounts.begin")(
        function* (invocation: AuthInvocation, raw: typeof OAuthLinkBegin.Type) {
          const caller = yield* available(invocation);
          const request = yield* snapshotOAuth(OAuthLinkBegin, raw);
          const found = yield* capture({ moduleId: id, subjectId: caller.subjectId });

          if (found === undefined) return yield* OAuthRejected.make({});
          const revision = yield* snapshotOAuth(OAuthAccountRevision, found);

          if (revision.subjectId !== caller.subjectId) return yield* OAuthUnavailable.make({});

          const target = yield* resolveTarget(request.returnTarget).pipe(
            Effect.flatMap((value) => snapshotOAuth(OAuthReturnTarget, value)),
          );

          const issued = yield* issueBinding(request.flowId).pipe(Effect.mapError(binderError));
          const original = issued.credentialCommands[0];

          if (
            issued.credentialCommands.length !== 1 ||
            original?._tag !== "Issue" ||
            original.slot !== "request-binding" ||
            issued.value.flowId !== request.flowId ||
            original.expiresAtMillis !== issued.value.expiresAtMillis
          )
            return yield* OAuthUnavailable.make({});

          const command = Object.freeze({
            _tag: "Issue" as const,
            slot: "request-binding" as const,
            credential: Redacted.make(Redacted.value(original.credential)),
            expiresAtMillis: original.expiresAtMillis,
          });

          const binder = {
            ...(yield* verifyBinding(
              request.flowId,
              Redacted.make(Redacted.value(command.credential)),
            ).pipe(Effect.mapError(binderError))),
          };

          if (binder.expiresAtMillis !== command.expiresAtMillis)
            return yield* OAuthUnavailable.make({});

          const prepared = yield* prepareAuthorization(
            Object.freeze({
              provider: request.provider,
              ...(request.callbackId === undefined ? {} : { callbackId: request.callbackId }),
              flowId: request.flowId,
              ...(request.prompt === undefined ? {} : { prompt: request.prompt }),
              ...(request.loginHint === undefined ? {} : { loginHint: request.loginHint }),
            }),
          ).pipe(Effect.flatMap((value) => snapshotOAuth(OAuthProtocolPreparation, value)));

          if (
            prepared.configuration.provider !== request.provider ||
            prepared.configuration.callbackId !== request.callbackId ||
            (prepared.configuration.protocol === "oidc") !==
              (prepared.secrets.oidcNonce !== undefined)
          )
            return yield* OAuthUnavailable.make({});
          const now = DateTime.toEpochMillis(yield* DateTime.now);
          const expiresAtMillis = Math.min(now + policy.lifetimeMillis, binder.expiresAtMillis);

          if (expiresAtMillis <= now) return yield* OAuthRejected.make({});

          const intent = snapshotOAuthSync(OAuthLinkIntentContext, {
            ...prepared.configuration,
            ...(prepared.responseMode === undefined ? {} : { responseMode: prepared.responseMode }),
            namespace: "effect-auth/oauth-link-context/v1",
            moduleId: id,
            generation: policy.generation,
            flowId: request.flowId,
            revision,
            maximumEvidenceAgeMillis: policy.maximumEvidenceAgeMillis,
            returnTarget: target,
            stateDigest: yield* stateDigest(
              request.flowId,
              request.provider,
              prepared.secrets.state,
            ).pipe(Effect.mapError(() => OAuthUnavailable.make({}))),
            requestBindingVerifier: binder.verifier,
            requestBindingExpiresAtMillis: binder.expiresAtMillis,
            issuedAtMillis: now,
            expiresAtMillis,
            exchangeTimeoutMillis: policy.exchangeTimeoutMillis,
          });

          const authorization = yield* authorize(
            caller,
            yield* challenge(
              "link-begin",
              intent.flowId,
              revision,
              Schema.encodeSync(intentJson)(intent),
            ),
            request.actionProof,
          );

          const context = snapshotOAuthSync(OAuthLinkTransactionContext, {
            ...intent,
            authorization,
          });

          const sealed = yield* seal({
            context: snapshotOAuthSync(OAuthLinkTransactionContext, context),
            secrets: snapshotOAuthSync(OAuthTransactionSecrets, prepared.secrets),
          }).pipe(Effect.flatMap((value) => snapshotOAuth(OAuthSealedTransaction, value)));

          const flow = snapshotOAuthSync(OAuthLinkFlow, {
            context,
            sealed,
          });

          const expected = Schema.encodeSync(flowJson)(flow);

          const receipt = yield* issue(snapshotOAuthSync(OAuthLinkFlow, flow), (value, journal) => {
            const decision = snapshotOAuthSync(OAuthLinkIssueDecision, value);

            if (
              decision._tag === "Issued" &&
              Schema.encodeSync(flowJson)(decision.flow) !== expected
            )
              throw OAuthUnavailable.make({});

            return journal.prepare(decision._tag === "Issued");
          });

          if (!(yield* read(receipt))) return yield* OAuthRejected.make({});

          return {
            value: {
              flowId: request.flowId,
              authorizationUrl: prepared.authorizationUrl,
              expiresAtMillis,
            },
            credentialCommands: [formPostBinding(command, prepared.responseMode)],
          };
        },
        Effect.tapCause((cause) =>
          Cause.hasDies(cause) ? reportAuthFailure("oauth-accounts", cause) : Effect.void,
        ),
        Effect.catchDefect(() => Effect.fail(OAuthUnavailable.make({}))),
      );

      const complete = Effect.fn("OAuthAccounts.complete")(
        function* (invocation: AuthInvocation, raw: typeof OAuthLinkComplete.Type) {
          const authenticated = yield* available(invocation).pipe(
            Effect.catchTag("AuthenticationRequired", () => Effect.succeed(undefined)),
          );

          const request = yield* snapshotOAuth(OAuthLinkComplete, raw);
          const response = request.response;

          if (encoder.encode(Schema.encodeSync(responseJson)(response)).length > 16384)
            return yield* OAuthRejected.make({});

          const binder = {
            ...(yield* verifyBinding(request.flowId, request.requestBinding).pipe(
              Effect.mapError(binderError),
            )),
          };

          const binding = {
            moduleId: id,
            generation: policy.generation,
            flowId: request.flowId,
            provider: request.provider,
            callbackId: request.callbackId,
            stateDigest: yield* stateDigest(request.flowId, request.provider, response.state),
            requestBindingVerifier: binder.verifier,
            requestBindingExpiresAtMillis: binder.expiresAtMillis,
            ...(response.issuer === undefined ? {} : { responseIssuer: response.issuer }),
          };

          const access = snapshotOAuthSync(
            OAuthLinkAccess,
            authenticated === undefined
              ? { ...binding, formPostSubject: true as const }
              : { ...binding, subjectId: authenticated.subjectId },
          );

          const consumed = yield* consume(access, (value, journal) =>
            journal.prepare(snapshotOAuthSync(OAuthLinkConsumeDecision, value)),
          ).pipe(Effect.flatMap(read));

          if (consumed._tag !== "Consumed") {
            if (authenticated === undefined) return yield* AuthenticationRequired.make({});

            return yield* OAuthRejected.make({});
          }
          const flow = snapshotOAuthSync(OAuthLinkFlow, consumed.flow);
          const context = flow.context;

          if (authenticated === undefined && context.responseMode !== "form_post")
            return yield* AuthenticationRequired.make({});

          const caller = authenticated ?? { subjectId: context.revision.subjectId };

          if (
            context.moduleId !== id ||
            context.generation !== policy.generation ||
            context.flowId !== request.flowId ||
            context.provider !== request.provider ||
            context.callbackId !== request.callbackId ||
            context.revision.subjectId !== caller.subjectId ||
            context.stateDigest !== access.stateDigest ||
            context.requestBindingVerifier !== binder.verifier ||
            context.requestBindingExpiresAtMillis !== binder.expiresAtMillis ||
            context.expiresAtMillis > binder.expiresAtMillis ||
            (context.responseIssuerMode === "required"
              ? response.issuer !== context.issuer
              : response.issuer !== undefined)
          )
            return yield* OAuthUnavailable.make({});
          if (response._tag === "Error")
            return {
              value: { _tag: "Cancelled" as const, returnTarget: context.returnTarget },
              credentialCommands: clearBinding,
            };
          if (DateTime.toEpochMillis(yield* DateTime.now) >= context.authorization.validUntilMillis)
            return yield* OAuthActionRequired.make({});

          const identity = yield* bounded(
            Effect.gen(function* () {
              const secrets = yield* open({ context, sealed: flow.sealed }).pipe(
                Effect.flatMap((value) => snapshotOAuth(OAuthTransactionSecrets, value)),
              );

              if (
                (context.protocol === "oidc") !== (secrets.oidcNonce !== undefined) ||
                (yield* stateDigest(context.flowId, context.provider, secrets.state)) !==
                  context.stateDigest ||
                Redacted.value(secrets.state) !== Redacted.value(response.state)
              )
                return yield* OAuthUnavailable.make({});

              return yield* exchangeVerifiedIdentity({
                configuration: snapshotOAuthSync(OAuthProtocolConfiguration, context),
                response,
                secrets,
                verificationStartedAt: yield* DateTime.now,
              }).pipe(
                Effect.flatMap((value) => snapshotOAuth(OAuthVerifiedExternalIdentity, value)),
              );
            }),
            context.exchangeTimeoutMillis,
          ).pipe(
            Effect.catchTag("TimeoutError", () => Effect.fail(OAuthUnavailable.make({}))),
            Effect.catchTag("OAuthProtocolRejected", () => Effect.fail(OAuthRejected.make({}))),
          );

          if (
            identity.identity.provider !== context.provider ||
            identity.identity.issuer !== context.issuer
          )
            return yield* OAuthRejected.make({});
          const event = yield* eventFor("linking", caller.subjectId);

          const finished = yield* link({ flow, identity }, (value, journal) => {
            const decision = snapshotOAuthSync(OAuthLinkDecision, value);

            if (decision._tag === "Linked") {
              const c = decision.credential;

              if (
                c.moduleId !== id ||
                c.revision.subjectId !== caller.subjectId ||
                c.identity.provider !== identity.identity.provider ||
                c.identity.issuer !== identity.identity.issuer ||
                c.identity.subject !== identity.identity.subject ||
                c.revision.securityRevision !== context.revision.securityRevision ||
                !c.revision.credentials.some(
                  (item) =>
                    item.credentialId === c.credentialId && item.revision === c.credentialRevision,
                ) ||
                new Set(c.revision.credentials.map((item) => item.credentialId)).size !==
                  c.revision.credentials.length
              )
                throw OAuthUnavailable.make({});
              if (decision.changed) journal.stage(event);
            }

            return journal.prepare(decision);
          }).pipe(Effect.flatMap(read));

          if (finished._tag === "Conflict") return yield* IdentityConflict.make({});
          if (finished._tag === "Rejected") return yield* OAuthRejected.make({});

          return {
            value: {
              _tag: "Linked" as const,
              changed: finished.changed,
              credentialId: finished.credential.credentialId,
              returnTarget: context.returnTarget,
            },
            credentialCommands: clearBinding,
          };
        },
        Effect.tapCause((cause) =>
          Cause.hasDies(cause) ? reportAuthFailure("oauth-accounts", cause) : Effect.void,
        ),
        Effect.catchDefect(() => Effect.fail(OAuthUnavailable.make({}))),
      );

      const remove = Effect.fn("OAuthAccounts.unlink")(
        function* (invocation: AuthInvocation, raw: typeof OAuthUnlink.Type) {
          const caller = yield* available(invocation);
          const request = yield* snapshotOAuth(OAuthUnlink, raw);

          if (
            policy.requireImmediateInvalidation &&
            (invalidation.existingSessions !== "immediate" ||
              strategy.capabilities.positiveCacheMillis > 0)
          )
            return yield* OAuthMethodUnsupported.make({});

          const found = yield* readCredential({
            moduleId: id,
            subjectId: caller.subjectId,
            credentialId: request.credentialId,
          });

          if (found === undefined) return yield* OAuthRejected.make({});
          const credential = snapshotOAuthSync(OAuthCredentialSnapshot, found);

          if (
            credential.moduleId !== id ||
            credential.credentialId !== request.credentialId ||
            credential.revision.subjectId !== caller.subjectId ||
            !credential.revision.credentials.some(
              (c) =>
                c.credentialId === credential.credentialId &&
                c.revision === credential.credentialRevision,
            )
          )
            return yield* OAuthUnavailable.make({});

          const authorization = yield* authorize(
            caller,
            yield* challenge(
              "unlink",
              OAuthActionChallenge.fields.flowId.make(request.commandId),
              credential.revision,
              Schema.encodeSync(credentialJson)(credential),
            ),
            request.actionProof,
          );

          const event = yield* eventFor("credential-change", caller.subjectId);

          const receipt = yield* unlink(
            {
              credential: snapshotOAuthSync(OAuthCredentialSnapshot, credential),
              authorization: snapshotOAuthSync(OAuthActionAuthorization, authorization),
              invalidation: snapshotOAuthSync(SessionInvalidationWindow, invalidation),
            },
            (value, journal) => {
              const decision = snapshotOAuthSync(OAuthUnlinkDecision, value);

              if (decision._tag === "Unlinked") {
                if (
                  decision.result.credentialId !== credential.credentialId ||
                  Schema.encodeSync(invalidationJson)(decision.result.invalidation) !==
                    expectedInvalidation
                )
                  throw OAuthUnavailable.make({});
                journal.stage(event);
              }

              return journal.prepare(decision);
            },
          );

          const decision = yield* read(receipt);

          if (decision._tag === "Rejected") return yield* OAuthRejected.make({});
          if (decision._tag === "LastSignInMethod") return yield* LastSignInMethod.make({});

          return {
            value: decision.result,
            credentialCommands: clearChanged,
          };
        },
        Effect.tapCause((cause) =>
          Cause.hasDies(cause) ? reportAuthFailure("oauth-accounts", cause) : Effect.void,
        ),
        Effect.catchDefect(() => Effect.fail(OAuthUnavailable.make({}))),
      );

      return Accounts.of({
        list: Effect.fn("OAuthAccounts.list")(
          function* (invocation, raw) {
            const caller = yield* available(invocation);
            const request = yield* snapshotOAuth(OAuthLinkedAccountsList, raw);

            const result = yield* listRows({ ...request, moduleId: id, invocation: caller }).pipe(
              Effect.flatMap((value) => snapshotOAuth(OAuthLinkedAccountsListResult, value)),
            );

            if (
              result.items.length > request.limit ||
              new Set(result.items.map((item) => item.credentialId)).size !== result.items.length ||
              (result.cursor !== undefined && result.cursor === request.cursor)
            )
              return yield* OAuthUnavailable.make({});

            // Explicit projection also excludes excess fields supplied by a replacement port.
            return {
              items: result.items.map(({ credentialId, provider, issuer, subject }) =>
                OAuthLinkedAccount.make({ credentialId, provider, issuer, subject }),
              ),
              ...(result.cursor === undefined ? {} : { cursor: result.cursor }),
            };
          },
          Effect.tapCause((cause) =>
            Cause.hasDies(cause) ? reportAuthFailure("oauth-accounts", cause) : Effect.void,
          ),
          Effect.catchDefect(() => Effect.fail(OAuthUnavailable.make({}))),
        ),
        begin,
        complete,
        unlink: remove,
        cleanup: Effect.fn("OAuthAccounts.cleanup")(function* (limit) {
          yield* noAmbient();

          const input = yield* snapshotOAuth(OAuthCleanupInput, {
            moduleId: id,
            limit,
          });

          const receipt = yield* cleanup(input, (value, journal) => {
            const result = snapshotOAuthSync(CleanupResult, value);

            if (result.removed > input.limit) throw OAuthUnavailable.make({});

            return journal.prepare(result);
          });

          return yield* read(receipt);
        }),
      });
    }),
  );

  const List = makeOperation(`${moduleId}/accounts/list`, {
    payload: OAuthLinkedAccountsList,
    success: OAuthLinkedAccountsListResult,
    error: Schema.Union([AuthenticationRequired, OAuthUnavailable, OAuthMethodUnsupported]),
    access: "authenticated",
    exposure: "public",
    replay: "read-only",
  });

  const Begin = makeOperation(`${moduleId}/accounts/link/begin`, {
    payload: OAuthLinkBegin,
    success: OAuthSignInAuthorization,
    error: Failure,
    access: "authenticated",
    exposure: "public",
    replay: "non-idempotent",
    credentials: true,
  });

  // form_post completion carries the binding cookie. A guest reaches the handler,
  // which accepts only a form_post continuation whose sealed subject and binding
  // match. Begin, list, and unlink stay authenticated.
  const Complete = makeOperation(`${moduleId}/accounts/link/complete`, {
    payload: OAuthLinkComplete,
    success: OAuthLinkResult,
    error: Failure,
    access: "any",
    exposure: "public",
    replay: "single-use",
    credentials: true,
  });

  const Unlink = makeOperation(`${moduleId}/accounts/unlink`, {
    payload: OAuthUnlink,
    success: OAuthUnlinked,
    error: Failure,
    access: "authenticated",
    exposure: "public",
    replay: "single-use",
    credentials: true,
  });

  const handlersLayer = Layer.mergeAll(
    List.handlerLayer(
      Effect.fn("OAuthAccounts.List")(function* (input, invocation) {
        return yield* (yield* Accounts).list(invocation, input);
      }),
    ),
    Begin.credentialHandlerLayer(
      Effect.fn("OAuthAccounts.Link.Begin")(function* (input, invocation) {
        return yield* (yield* Accounts).begin(invocation, input);
      }),
    ),
    Complete.credentialHandlerLayer(
      Effect.fn("OAuthAccounts.Link.Complete")(function* (input, invocation) {
        return yield* (yield* Accounts).complete(invocation, input);
      }),
    ),
    Unlink.credentialHandlerLayer(
      Effect.fn("OAuthAccounts.Unlink")(function* (input, invocation) {
        return yield* (yield* Accounts).unlink(invocation, input);
      }),
    ),
  );

  return Object.freeze({
    Accounts,
    binding,
    layer,
    operations: Object.freeze({ List, Link: Object.freeze({ Begin, Complete }), Unlink }),
    handlersLayer,
    group: operationGroup(List, Begin, Complete, Unlink),
  });
};
