import * as Cause from "effect/Cause";
import type * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";

import { LifecycleHooks } from "../hooks/LifecycleHooks";
import { lifecycleEvent, lifecycleSnapshotEffect, LifecycleEventId } from "../hooks/models";
import { phoneFailure } from "./failure";
import { PhoneOtpRejected } from "./models";
import { PhonePersistence, type PhoneMutation } from "./PhonePersistence";

/** Keep account/credential changes, proof consumption and their event under one owner. */
export const commitPhoneMutation = Effect.fnUntraced(function* (
  input: PhoneMutation,
  now: DateTime.Utc,
) {
  const hooks = yield* LifecycleHooks;

  const snapshot = yield* lifecycleSnapshotEffect({
    action: input.action === "register" ? "registration" : "identifier-change",
    operation: `${input.moduleId}/${input.action}`,
    method: "phone-otp",
    identifiers: [input.redemption.input.binding.identifier],
    ...(input.target.revision === null ? {} : { subjectId: input.target.revision.subjectId }),
  }).pipe(Effect.orDie);

  yield* hooks.before(snapshot);

  const decision = yield* (yield* PhonePersistence)
    .mutate(input, (decision, journal) => {
      if (decision._tag === "Accepted")
        journal.stage(
          lifecycleEvent({
            id: LifecycleEventId.make(`phone/${input.moduleId}/${input.commandId}`),
            occurredAtMillis: now.epochMilliseconds,
            snapshot: { ...snapshot, subjectId: decision.credential.revision.subjectId },
          }),
        );

      return journal.prepare(decision);
    })
    .pipe(
      Effect.flatMap((receipt) => receipt.read),
      Effect.catchCause((cause) => Effect.failCause(Cause.map(cause, phoneFailure))),
    );

  if (decision._tag !== "Accepted") return yield* PhoneOtpRejected.make({});

  return decision.credential;
});
