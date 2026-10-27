import * as Cause from "effect/Cause";
import * as Crypto from "effect/Crypto";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";

import { makeAuthStrategy } from "../auth/AuthStrategy";
import { defaultLayer, hooksLayer } from "../auth/defaults";
import { hasCommitScope } from "../hooks/commit";
import { HookDenied } from "../hooks/models";
import { LoginIdentifier } from "../identity/models";
import type { AuthInvocation } from "../operations/context";
import { makeOperation, operationGroup } from "../operations/operation";
import {
  RequestBindingCredential,
  makeRequestBinding,
  RequestBindingFlowId,
} from "../operations/requestBinding";
import { readProofCommit } from "../proofs/dispatch";
import { ProofBinding, ProofPurpose, ProofRequestId } from "../proofs/models";
import { makeProofModule } from "../proofs/module";
import type { ProofPolicy } from "../proofs/policy";
import { defaultProofPolicy } from "../proofs/policy";
import { Locale, TokenDigest } from "../Schema";
import { AuthenticationFlowId, type AuthenticationEvidence } from "../sessions/models";
import type { makeSessionModule } from "../sessions/module";
import { phoneAdmission, phoneAttemptAdmission } from "./admission";
import { makePhoneClaims } from "./claims";
import { deliveryLayer } from "./delivery";
import { phoneFailure } from "./failure";
import type { PhoneLifecycleTarget } from "./lifecycleModels";
import type { PhoneOtpRequest } from "./models";
import {
  PhoneCredentialSnapshot,
  PhoneNumber,
  PhoneOtpChallenge,
  PhoneOtpComplete,
  PhoneOtpRejected,
  PhoneOtpUnavailable,
} from "./models";
import { commitPhoneMutation } from "./mutation";
import { defaultPhoneAdmissionLayer } from "./PhoneAdmission";
import { PhoneDeliveryEligibility } from "./PhoneDeliveryEligibility";
import { PhonePersistence } from "./PhonePersistence";
import { PhoneSignInTargets } from "./PhoneSignInTargets";

const Start = Schema.Struct({
  flowId: RequestBindingFlowId,
  requestId: ProofRequestId,
  phoneNumber: PhoneNumber,
  locale: Locale,
  requestBinding: Schema.optionalKey(RequestBindingCredential),
});

const Failure = Schema.Union([PhoneOtpRejected, PhoneOtpUnavailable, HookDenied]);
const tuple = Schema.fromJsonString(Schema.Array(Schema.String));

const noAmbient = Effect.fn("PhoneOtp.noAmbient")(function* () {
  if (yield* hasCommitScope) return yield* PhoneOtpUnavailable.make({});
});

export interface PhoneCodeOptions<
  SessionId extends string,
  Claims extends Schema.Codec<unknown, unknown, unknown, unknown>,
> {
  readonly sessions: ReturnType<typeof makeSessionModule<SessionId, Claims>>;
  readonly policy?: ProofPolicy;
  readonly digits?: 6 | 7 | 8 | 9 | 10;
}

const makePhoneCode = <
  const Id extends string,
  const SessionId extends string,
  Claims extends Schema.Codec<unknown, unknown, unknown, unknown>,
>(
  moduleId: Id,
  options: PhoneCodeOptions<SessionId, Claims>,
) => {
  const { sessions } = options;
  const binding = makeRequestBinding(moduleId, "phone-otp-sign-in");

  const proof = makeProofModule(`${moduleId}/sign-in`, {
    purpose: ProofPurpose.make("phone-otp-sign-in"),
    binding: ProofBinding,
    channel: "sms",
    template: "phone-otp-sign-in",
    secret: { _tag: "NumericCode", digits: options.digits ?? 6 },
    policy: options.policy ?? defaultProofPolicy,
  });

  const SessionClaims = makePhoneClaims<Id, Claims>(moduleId);

  const capture = Effect.fn("PhoneOtp.capture")(function* (request: {
    readonly flowId: RequestBindingFlowId;
    readonly phoneNumber: PhoneNumber;
    readonly requestBinding: typeof RequestBindingCredential.Type;
  }) {
    const verified = yield* (yield* binding.RequestBinding)
      .verify(request.flowId, request.requestBinding)
      .pipe(Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, phoneFailure))));

    const candidate = yield* (yield* PhoneSignInTargets).lookup({
      moduleId,
      phoneNumber: request.phoneNumber,
    });

    let target: Option.Option<PhoneCredentialSnapshot> = Option.none();

    if (Option.isSome(candidate)) {
      const codec = Schema.toCodecJson(PhoneCredentialSnapshot);

      const snapshot = yield* Schema.encodeEffect(codec)(candidate.value).pipe(
        Effect.flatMap(Schema.decodeEffect(codec)),
        Effect.mapError(phoneFailure),
      );

      if (
        snapshot.moduleId === moduleId &&
        snapshot.phoneNumber === request.phoneNumber &&
        snapshot.verifiedAtMillis <= DateTime.toEpochMillis(yield* DateTime.now) &&
        snapshot.revision.credentials.some(
          (value) =>
            value.credentialId === snapshot.credentialId &&
            value.revision === snapshot.credentialRevision,
        )
      )
        target = Option.some(snapshot);
    }

    return {
      flowId: request.flowId,
      phoneNumber: request.phoneNumber,
      verifier: verified.verifier,
      target,
    };
  });

  const bind = Effect.fnUntraced(function* (
    current: Effect.Success<ReturnType<typeof capture>>,
    registrationTarget?: PhoneLifecycleTarget,
  ) {
    const encoded = yield* Schema.encodeEffect(tuple)([
      "effect-auth/phone-otp-sign-in/v1",
      moduleId,
      current.flowId,
      current.verifier,
      current.phoneNumber,
      Option.isSome(current.target)
        ? current.target.value.custodyRevision
        : (registrationTarget?.custody?.custodyRevision ?? ""),
    ]).pipe(Effect.mapError(phoneFailure));

    const digest = yield* (yield* Crypto.Crypto)
      .digest("SHA-256", new TextEncoder().encode(encoded))
      .pipe(Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, phoneFailure))));

    const base = {
      flowId: current.flowId,
      contextDigest: TokenDigest.make(Base64Url.encode(digest)),
      identifier: LoginIdentifier.make({ namespace: "phone", value: current.phoneNumber }),
    };

    const proofBinding: ProofBinding = Option.isSome(current.target)
      ? { _tag: "Subject", ...base, revision: current.target.value.revision }
      : { _tag: "Identifier", ...base };

    return proofBinding;
  });

  const admitSignIn = Effect.fn("PhoneOtp.admitRequest")(function* () {
    if (!(yield* phoneAdmission(moduleId, "request"))) return yield* PhoneOtpRejected.make({});
  });

  const SignIn = makeOperation(`${moduleId}/sign-in`, {
    payload: Start,
    authorize: admitSignIn,
    success: PhoneOtpChallenge,
    error: Failure,
    access: "any",
    exposure: "public",
    replay: "non-idempotent",
    credentials: true,
  });

  const Complete = makeOperation(`${moduleId}/complete`, {
    payload: PhoneOtpComplete,
    authorize: () => phoneAttemptAdmission(moduleId),
    success: sessions.CompletionResult,
    error: Failure,
    access: "any",
    exposure: "public",
    replay: "single-use",
    credentials: true,
  });

  const begin = Effect.fnUntraced(function* (input: typeof Start.Type, invocation: AuthInvocation) {
    yield* noAmbient();
    if (invocation._tag !== "Guest") return yield* PhoneOtpRejected.make({});

    const issued =
      input.requestBinding === undefined
        ? yield* (yield* binding.RequestBinding)
            .issue(input.flowId)
            .pipe(Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, phoneFailure))))
        : undefined;

    const command = issued?.credentialCommands.find(
      (value) => value._tag === "Issue" && value.slot === "request-binding",
    );

    const requestBinding =
      input.requestBinding ?? (command?._tag === "Issue" ? command.credential : undefined);

    if (requestBinding === undefined) return yield* PhoneOtpUnavailable.make({});
    const current = yield* capture({ ...input, requestBinding });

    return { current, credentialCommands: issued?.credentialCommands ?? [] };
  });

  const issue = Effect.fnUntraced(function* (
    input: typeof Start.Type,
    started: Effect.Success<ReturnType<typeof begin>>,
    registrationTarget?: PhoneLifecycleTarget,
  ) {
    const proofBinding = yield* bind(started.current, registrationTarget);
    const eligible = yield* (yield* PhoneDeliveryEligibility).allowed(input.phoneNumber);

    const dispatch = yield* (yield* proof.Proofs)
      .prepareIssue({
        requestId: input.requestId,
        binding: proofBinding,
        locale: input.locale,
        eligible:
          (Option.isSome(started.current.target) || registrationTarget?.eligible === true) &&
          eligible,
      })
      .pipe(
        Effect.flatMap(readProofCommit),
        Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, phoneFailure))),
      );

    yield* dispatch.schedule.pipe(
      Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, phoneFailure))),
    );

    return {
      value: { ...dispatch.receipt, flowId: input.flowId },
      credentialCommands: started.credentialCommands,
    };
  });

  const redeemSignIn = Effect.fnUntraced(function* (
    input: PhoneOtpComplete,
    target: Option.Option<PhoneCredentialSnapshot>,
    proofBinding: ProofBinding,
  ) {
    const consumed = yield* (yield* proof.Proofs)
      .prepareRedeem({
        binding: proofBinding,
        reference: input.reference,
        credential: input.code,
      })
      .pipe(
        Effect.flatMap(readProofCommit),
        Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, phoneFailure))),
      );

    if (consumed !== "redeemed" || Option.isNone(target)) return yield* PhoneOtpRejected.make({});

    return target.value;
  });

  const establish = Effect.fnUntraced(function* (
    flowId: RequestBindingFlowId,
    proofBinding: ProofBinding,
    credential: PhoneCredentialSnapshot,
    verifiedAt: DateTime.Utc,
  ) {
    const evidence: AuthenticationEvidence = {
      flowId: AuthenticationFlowId.make(flowId),
      bindingDigest: proofBinding.contextDigest,
      revision: credential.revision,
      proofs: [
        {
          method: "phone-otp",
          credentialId: credential.credentialId,
          factors: ["possession"],
          userVerified: false,
          phishingResistant: false,
          verifiedAt,
        },
      ],
    };

    const claimCredential = yield* Schema.encodeEffect(Schema.toCodecJson(PhoneCredentialSnapshot))(
      credential,
    ).pipe(
      Effect.flatMap(Schema.decodeEffect(Schema.toCodecJson(PhoneCredentialSnapshot))),
      Effect.mapError(phoneFailure),
    );

    const claims = yield* (yield* SessionClaims).resolve({
      subjectId: claimCredential.revision.subjectId,
      credential: claimCredential,
    });

    const established = yield* (yield* sessions.AuthenticationCompletion)
      .prepare({ evidence, requirement: credential.requirement, claims })
      .pipe(
        Effect.flatMap((receipt) => receipt.read),
        Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, phoneFailure))),
      );

    return {
      value: established.value,
      credentialCommands: [
        ...established.credentialCommands,
        { _tag: "Clear" as const, slot: "request-binding" as const },
      ],
    };
  });

  const withHandlers = <const AllowSignUp extends boolean, Handlers, E, R>(
    allowSignUp: AllowSignUp,
    handlersLayer: Layer.Layer<Handlers, E, R>,
  ) => {
    const layer = handlersLayer.pipe(
      Layer.provide(defaultLayer(binding.RequestBinding, binding.layer)),
      Layer.provide(defaultLayer(proof.Proofs, proof.smsLayer.pipe(Layer.provide(deliveryLayer)))),
      Layer.provide(hooksLayer),
    );

    return Object.freeze({
      persistence: { kind: "phone" as const, moduleId, allowSignUp },
      SessionClaims,
      binding,
      proof,
      layer,
      handlersLayer,
      operations: { SignIn, Complete },
      group: operationGroup(SignIn, Complete),
      strategy: makeAuthStrategy(
        {
          signIn: Effect.fn("PhoneOtp.signInRequest")(function* (
            invocation: AuthInvocation,
            input: typeof PhoneOtpRequest.Encoded,
          ) {
            const crypto = yield* Crypto.Crypto;

            const flowId = yield* crypto
              .randomUUIDv4()
              .pipe(Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, phoneFailure))));

            const requestId = yield* crypto
              .randomUUIDv4()
              .pipe(Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, phoneFailure))));

            return yield* SignIn.invoke(invocation, {
              ...input,
              flowId,
              requestId,
              locale: input.locale ?? "en",
            });
          }),
          completeSignIn: Complete.invoke,
        },
        layer.pipe(
          Layer.merge(Layer.effect(Crypto.Crypto, Crypto.Crypto)),
          Layer.provideMerge(defaultPhoneAdmissionLayer),
        ),
        { completion: true },
      ),
    });
  };

  return {
    signIn: () =>
      withHandlers(
        false,
        Layer.mergeAll(
          SignIn.credentialHandlerLayer(
            Effect.fn("PhoneOtp.signIn")(function* (input, invocation) {
              return yield* issue(input, yield* begin(input, invocation));
            }),
          ),
          Complete.credentialHandlerLayer(
            Effect.fn("PhoneOtp.completeSignIn")(function* (input, invocation) {
              yield* noAmbient();
              if (invocation._tag !== "Guest") return yield* PhoneOtpRejected.make({});
              const current = yield* capture(input);
              const proofBinding = yield* bind(current);
              const verifiedAt = yield* DateTime.now;
              const credential = yield* redeemSignIn(input, current.target, proofBinding);

              return yield* establish(input.flowId, proofBinding, credential, verifiedAt);
            }),
          ),
        ),
      ),
    signUp: () =>
      withHandlers(
        true,
        Layer.mergeAll(
          SignIn.credentialHandlerLayer(
            Effect.fn("PhoneOtp.signIn")(function* (input, invocation) {
              const started = yield* begin(input, invocation);

              const registrationTarget = Option.isNone(started.current.target)
                ? yield* (yield* PhonePersistence).target({
                    moduleId,
                    action: "register",
                    phoneNumber: input.phoneNumber,
                  })
                : undefined;

              return yield* issue(input, started, registrationTarget);
            }),
          ),
          Complete.credentialHandlerLayer(
            Effect.fn("PhoneOtp.completeSignIn")(function* (input, invocation) {
              yield* noAmbient();
              if (invocation._tag !== "Guest") return yield* PhoneOtpRejected.make({});
              const current = yield* capture(input);

              const registrationTarget = Option.isNone(current.target)
                ? yield* (yield* PhonePersistence).target({
                    moduleId,
                    action: "register",
                    phoneNumber: input.phoneNumber,
                  })
                : undefined;

              const proofBinding = yield* bind(current, registrationTarget);
              const verifiedAt = yield* DateTime.now;

              let credential: PhoneCredentialSnapshot;

              if (Option.isSome(current.target)) {
                credential = yield* redeemSignIn(input, current.target, proofBinding);
              } else {
                const redemption = yield* (yield* proof.Proofs)
                  .planRedeem({
                    binding: proofBinding,
                    reference: input.reference,
                    credential: input.code,
                  })
                  .pipe(
                    Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, phoneFailure))),
                  );

                if (registrationTarget === undefined || !registrationTarget.eligible)
                  return yield* PhoneOtpRejected.make({});

                credential = yield* commitPhoneMutation(
                  {
                    moduleId,
                    action: "register",
                    commandId: input.flowId,
                    target: registrationTarget,
                    redemption,
                  },
                  verifiedAt,
                );
              }

              return yield* establish(input.flowId, proofBinding, credential, verifiedAt);
            }),
          ),
        ),
      ),
  };
};

type PhoneModule<
  Id extends string,
  SessionId extends string,
  Claims extends Schema.Codec<unknown, unknown, unknown, unknown>,
  AllowSignUp extends boolean,
> = ReturnType<
  ReturnType<typeof makePhoneCode<Id, SessionId, Claims>>[AllowSignUp extends true
    ? "signUp"
    : "signIn"]
>;

/** One SMS sign-in flow. Signup is opt-in and uses the phone persistence owner;
 * a changed target or failure after proof consumption requires a fresh code. */
export function makePhoneOtp<
  const Id extends string,
  const SessionId extends string,
  Claims extends Schema.Codec<unknown, unknown, unknown, unknown>,
  const AllowSignUp extends boolean = false,
>(
  moduleId: Id,
  options: PhoneCodeOptions<SessionId, Claims> & { readonly allowSignUp?: AllowSignUp },
): PhoneModule<Id, SessionId, Claims, AllowSignUp>;

export function makePhoneOtp<
  const Id extends string,
  const SessionId extends string,
  Claims extends Schema.Codec<unknown, unknown, unknown, unknown>,
>(moduleId: Id, options: PhoneCodeOptions<SessionId, Claims> & { readonly allowSignUp?: boolean }) {
  const phone = makePhoneCode(moduleId, options);

  return options.allowSignUp === true ? phone.signUp() : phone.signIn();
}
