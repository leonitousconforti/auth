import {
  EmailUnavailable,
  type EmailCodeRegistrationAuthority,
  type EmailCodeRegistrationDecision,
  type PrepareEmailCommit,
} from "@yielded/auth/Email";
import { LifecycleHooks } from "@yielded/auth/Hooks";
import { TokenDigest } from "@yielded/auth/Schema";
import * as Crypto from "effect/Crypto";
import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";
import * as SqlClient from "effect/sql/SqlClient";

import type { EmailSubjectProvisioning } from "./configuration";
import { makeNativeEmailCodeRegistrationServices } from "./email-registration-native";
import {
  requiredEmailRegistrationConstraints,
  type AnyEmailAddressMapping,
  type AnyEmailRegistrationMapping,
} from "./models/email-model";
import type { AnyProofPersistenceMapping } from "./models/proof-model";
import type { NativeSqlTables } from "./native-sql-table";
import { SqlBatchCommit } from "./sql-commit";

const SubjectValues = Schema.Record(Schema.String, Schema.Unknown);
const fingerprint = TokenDigest.make("effect-auth/email-code-registration/composed");

/** Application defaults are evaluated on redemption; the native owner inserts
 * them with verified email ownership and its own active status and revisions.
 */
export const makeComposedEmailRegistrationAuthority = Effect.fnUntraced(function* (
  tables: NativeSqlTables,
  mapping: AnyEmailAddressMapping,
  proofs: AnyProofPersistenceMapping,
  provisioning?: EmailSubjectProvisioning,
): Effect.fn.Return<
  EmailCodeRegistrationAuthority,
  never,
  SqlClient.SqlClient | Crypto.Crypto | LifecycleHooks | SqlBatchCommit
> {
  if (provisioning === undefined)
    return {
      inspect: () => Effect.succeed({ fingerprint: TokenDigest.make("disabled"), eligible: false }),
      registerWithProof: () => Effect.fail(EmailUnavailable.make({})),
    };

  const sql = yield* SqlClient.SqlClient;
  const crypto = yield* Crypto.Crypto;
  const hooks = yield* LifecycleHooks;
  const batch = yield* SqlBatchCommit;
  const s = mapping.subject;
  const inspect = () => Effect.succeed({ fingerprint, eligible: true });

  return {
    inspect,
    registerWithProof: Effect.fnUntraced(
      function* <A>(
        input: Parameters<EmailCodeRegistrationAuthority["registerWithProof"]>[0],
        prepare: PrepareEmailCommit<EmailCodeRegistrationDecision, A>,
      ) {
        const values = yield* provisioning.values({
          requestId: input.requestId,
          identifier: { ...input.identifier },
          registration: undefined,
        });

        const row = Object.freeze({ ...(yield* Schema.decodeEffect(SubjectValues)(values)) });
        const subjectId = yield* mapping.subjectId.toSubject(row[s.id]);
        const nativeId = yield* mapping.subjectId.toNative(subjectId);

        const registration: AnyEmailRegistrationMapping<void> = {
          ...mapping,
          mode: "atomic",
          constraints: requiredEmailRegistrationConstraints,
          inspect,
          snapshotRegistration: () => Effect.void,
          provisioning: {
            idMode: "synchronous",
            allocateSubjectIdSync: () => nativeId,
            encodeSubjectInsert: (_, allocated) => ({
              ...row,
              [s.id]: allocated.nativeSubjectId,
              [s.status]: s.activeStatusValue,
              [s.securityRevision]: allocated.securityRevision,
            }),
          },
        };

        const services = yield* makeNativeEmailCodeRegistrationServices(
          tables,
          registration,
          proofs,
          batch,
        );

        return yield* services.registrationAuthority.registerWithProof(input, prepare);
      },
      Effect.provideService(SqlClient.SqlClient, sql),
      Effect.provideService(Crypto.Crypto, crypto),
      Effect.provideService(LifecycleHooks, hooks),
      Effect.mapError(() => EmailUnavailable.make({})),
    ),
  };
});
