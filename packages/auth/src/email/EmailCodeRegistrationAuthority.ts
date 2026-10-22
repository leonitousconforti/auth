import type * as Effect from "effect/Effect";

import type { PreparedCommit } from "../hooks/commit";
import type { LoginIdentifier } from "../identity/models";
import type { ProofRedemptionPlan } from "../proofs/redemption";
import type { TokenDigest } from "../Schema";
import type { PrepareEmailCommit } from "./EmailAddressPersistence";
import type { EmailUnavailable } from "./errors";
import type { EmailCodeRegistrationDecision, EmailCommandId } from "./models";

/** Supply a code strategy's RegistrationAuthority to enable email-only provisioning.
 * Inspection is read-only; application defaults belong to the registration owner.
 * The default authority declines registration and sends no code to unknown addresses.
 */
export interface EmailCodeRegistrationAuthority {
  /** Fingerprint any policy that must remain fixed until redemption; a changed
   * fingerprint invalidates outstanding codes. Authorities may instead resolve
   * account defaults at redemption. Inspection must not create or reserve an account.
   */
  readonly inspect: (input: {
    readonly identifier: LoginIdentifier;
  }) => Effect.Effect<
    { readonly fingerprint: TokenDigest; readonly eligible: boolean },
    EmailUnavailable
  >;
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
      readonly fingerprint: TokenDigest;
      readonly redemption: ProofRedemptionPlan;
    },
    prepare: PrepareEmailCommit<EmailCodeRegistrationDecision, A>,
  ) => Effect.Effect<PreparedCommit<A>, EmailUnavailable>;
}
