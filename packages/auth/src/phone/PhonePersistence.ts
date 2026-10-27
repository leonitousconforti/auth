import * as Context from "effect/Context";
import type * as Effect from "effect/Effect";

import type { CommitJournal, PreparedCommit } from "../hooks/commit";
import type { ProofRedemptionPlan } from "../proofs/redemption";
import type { SubjectId } from "../Schema";
import type {
  PhoneActionAuthorization,
  PhoneLifecycleAction,
  PhoneLifecyclePolicy,
  PhoneLifecycleTarget,
  PhoneMutationDecision,
} from "./lifecycleModels";
import type { PhoneNumber, PhoneOtpUnavailable } from "./models";

export interface PhoneMutation {
  readonly moduleId: string;
  readonly action: PhoneLifecycleAction;
  readonly commandId: string;
  readonly target: PhoneLifecycleTarget;
  readonly authorization?: PhoneActionAuthorization;
  readonly redemption: ProofRedemptionPlan;
  readonly policy: PhoneLifecyclePolicy;
}

/** Custody tombstones are permanent. Recycled numbers never create, transfer or
 * merge accounts automatically. Verification/change and proof redemption
 * share one native owner; a failed protected write cannot consume the proof.
 * Registration accepts /lifecycle proofs with purpose phone-lifecycle, or
 * /sign-in-or-sign-up proofs with purpose phone-otp-sign-in-or-sign-up, relative
 * to moduleId. Both require an
 * Identifier binding; the combined flow never authorizes verification/change. */
export class PhonePersistence extends Context.Service<
  PhonePersistence,
  {
    readonly target: (input: {
      readonly moduleId: string;
      readonly action: PhoneLifecycleAction;
      readonly phoneNumber: PhoneNumber;
      readonly subjectId?: SubjectId;
      readonly sourcePhoneNumber?: PhoneNumber;
    }) => Effect.Effect<PhoneLifecycleTarget, PhoneOtpUnavailable>;
    readonly mutate: <A>(
      input: PhoneMutation,
      prepare: (decision: PhoneMutationDecision, journal: CommitJournal) => PreparedCommit<A>,
    ) => Effect.Effect<PreparedCommit<A>, PhoneOtpUnavailable>;
  }
>()("effect-auth/PhonePersistence") {}
