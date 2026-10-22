import type * as Effect from "effect/Effect";

import type { PreparedCommit } from "../hooks/commit";
import type { LoginIdentifier } from "../identity/models";
import type { ProofRedemptionPlan } from "../proofs/redemption";
import type { PrepareEmailCommit } from "./EmailAddressPersistence";
import type { EmailUnavailable } from "./errors";
import type { EmailCodeRegistrationDecision, EmailCommandId } from "./models";

/** Supply a code strategy's RegistrationAuthority to enable email-only provisioning.
 * Application defaults belong to the registration owner and apply at redemption.
 * The default authority declines registration and sends no code to unknown addresses.
 */
export interface EmailCodeRegistrationAuthority {
  /** Captured when the code strategy is built; registration remains opt-in. */
  readonly enabled: boolean;
  /** Atomically redeem the code and create a new subject, verified identifier and
   * active email credential. Never adopt a verified owner or return authentication
   * after a replay or unknown commit outcome. The proof uses `${moduleId}/code-sign-in`
   * and `email-code-sign-in`; requestId is stable for the redeemed proof.
   */
  readonly registerWithProof: <A>(
    input: {
      readonly moduleId: string;
      readonly commandId: EmailCommandId;
      readonly requestId: string;
      readonly identifier: LoginIdentifier;
      readonly redemption: ProofRedemptionPlan;
    },
    prepare: PrepareEmailCommit<EmailCodeRegistrationDecision, A>,
  ) => Effect.Effect<PreparedCommit<A>, EmailUnavailable>;
}
