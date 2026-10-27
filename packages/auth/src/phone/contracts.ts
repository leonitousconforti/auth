import * as Schema from "effect/Schema";

import { HookDenied } from "../hooks/models";
import { action } from "../operations/actions";
import type { SubjectId } from "../Schema";
import {
  PhoneOtpChallenge,
  PhoneOtpComplete,
  PhoneOtpRejected,
  PhoneOtpRequest,
  PhoneOtpUnavailable,
} from "./models";

const Failure = Schema.Union([PhoneOtpRejected, PhoneOtpUnavailable, HookDenied]);
const { flowId, phoneNumber, reference, code } = PhoneOtpComplete.fields;
const CompleteInput = Schema.Struct({ flowId, phoneNumber, reference, code });

/** Request one phone challenge without disclosing whether the account exists. */
export const signInOrSignUp = (options?: { readonly strategy?: string }) =>
  action({
    payload: PhoneOtpRequest,
    success: PhoneOtpChallenge,
    error: Failure,
    mode: "mutation",
    credentials: true,
    replay: "non-idempotent",
    method: "signInOrSignUp",
    ...options,
  });

type Completion =
  | { readonly _tag: "Authenticated"; readonly session: { readonly subjectId: SubjectId } }
  | { readonly _tag: "PendingAuthentication" };

/** Redeem the phone challenge with the request binding supplied privately by the server. */
export const completeSignInOrSignUp = <
  S extends Schema.Codec<Completion, unknown, unknown, unknown>,
>(
  schemas: { readonly CompletionResult: S },
  options?: { readonly strategy?: string },
) =>
  action({
    payload: CompleteInput,
    success: schemas.CompletionResult,
    error: Failure,
    mode: "mutation",
    credentials: true,
    replay: "single-use",
    method: "completeSignInOrSignUp",
    requestFields: { requestBinding: "request-binding" },
    subject: {
      fromSuccess: (value) =>
        value._tag === "Authenticated" ? value.session.subjectId : undefined,
      sessionFromSuccess: (value) => (value._tag === "Authenticated" ? value.session : undefined),
    },
    ...options,
  });
