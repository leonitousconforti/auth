import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";

import type {
  BindingOf,
  ClaimsCodec,
  StrategyBinding,
  StrategyDefinition,
  StrategyTypeLambda,
} from "../auth/definition";
import { operationGroup } from "../operations/operation";
import { snapshotPhoneConfiguration } from "./configuration";
import { defaultPhoneLifecyclePolicy, makePhoneLifecycle } from "./lifecycle";
import type { PhoneLifecyclePolicy } from "./lifecycleModels";
import { makePhoneOtp, type PhoneCodeOptions } from "./module";

export type PhoneOtpOptions<
  Namespace extends string | undefined = undefined,
  AllowSignUp extends boolean = boolean,
> = Omit<PhoneCodeOptions<string, ClaimsCodec>, "sessions"> & {
  readonly namespace?: Namespace;
  /** Create an account after verification when the number is unused. Defaults to false. */
  readonly allowSignUp?: AllowSignUp;
};

const bindDefine = <
  const Namespace extends string | undefined,
  const AllowSignUp extends boolean,
  Claims extends ClaimsCodec,
  const Id extends string,
  const SessionId extends string,
>(
  binding: StrategyBinding<Claims, Id, SessionId>,
  options: PhoneOtpOptions<Namespace, AllowSignUp>,
) =>
  makePhoneOtp<Id, SessionId, Claims, AllowSignUp>(binding.namespace, {
    ...options,
    sessions: binding.sessions,
  });

export interface DefineStrategy<
  Namespace extends string | undefined,
  AllowSignUp extends boolean,
> extends StrategyTypeLambda {
  readonly type: ReturnType<
    typeof bindDefine<
      Namespace,
      AllowSignUp,
      BindingOf<this>["claims"],
      BindingOf<this>["namespace"],
      BindingOf<this>["sessionNamespace"]
    >
  >;
}

const define = <const Namespace extends string | undefined, const AllowSignUp extends boolean>(
  namespace: Namespace,
  input: PhoneOtpOptions<Namespace, AllowSignUp>,
) => {
  const options = snapshotPhoneConfiguration(input);

  const bind = <
    Claims extends ClaimsCodec,
    const Id extends string,
    const SessionId extends string,
  >(
    binding: StrategyBinding<Claims, Id, SessionId>,
  ) => bindDefine<Namespace, AllowSignUp, Claims, Id, SessionId>(binding, options);

  const definition: StrategyDefinition<DefineStrategy<Namespace, AllowSignUp>, Namespace> = {
    namespace,
    bind,
  };

  return Object.freeze(definition);
};

/** Add explicit registration, verification, and number changes independently of login signup. */
export type PhoneLifecycleOptions<
  Namespace extends string | undefined = undefined,
  AllowSignUp extends boolean = boolean,
> = PhoneOtpOptions<Namespace, AllowSignUp> & {
  readonly lifecycle: true | PhoneLifecyclePolicy;
};

const bindLifecycle = <
  const Namespace extends string | undefined,
  const AllowSignUp extends boolean,
  Claims extends ClaimsCodec,
  const Id extends string,
  const SessionId extends string,
>(
  binding: StrategyBinding<Claims, Id, SessionId>,
  options: PhoneOtpOptions<Namespace, AllowSignUp> & { readonly lifecycle: PhoneLifecyclePolicy },
) => {
  const phone = bindDefine<Namespace, AllowSignUp, Claims, Id, SessionId>(binding, options);

  const lifecycle = makePhoneLifecycle<Id, SessionId, Claims>(binding.namespace, {
    ...options,
    sessions: binding.sessions,
  });

  return Object.freeze({
    persistence: {
      ...phone.persistence,
      lifecycle: true as const,
      lifecyclePolicy: options.lifecycle,
    },
    SessionClaims: phone.SessionClaims,
    binding: phone.binding,
    proof: phone.proof,
    lifecycle,
    operations: { ...phone.operations, ...lifecycle.operations },
    group: operationGroup(
      phone.operations.SignIn,
      phone.operations.Complete,
      lifecycle.operations.Begin,
      lifecycle.operations.CompleteLifecycle,
      lifecycle.operations.Cancel,
    ),
    layer: Layer.merge(phone.layer, lifecycle.layer),
    handlersLayer: Layer.merge(phone.handlersLayer, lifecycle.handlersLayer),
    strategy: {
      completion: true as const,
      make: Effect.gen(function* () {
        const signIn = yield* phone.strategy.make;
        const management = yield* lifecycle.strategy.make;

        return { ...signIn, ...management };
      }),
    },
  });
};

export interface LifecycleStrategy<
  Namespace extends string | undefined,
  AllowSignUp extends boolean,
> extends StrategyTypeLambda {
  readonly type: ReturnType<
    typeof bindLifecycle<
      Namespace,
      AllowSignUp,
      BindingOf<this>["claims"],
      BindingOf<this>["namespace"],
      BindingOf<this>["sessionNamespace"]
    >
  >;
}

const defineLifecycle = <
  const Namespace extends string | undefined,
  const AllowSignUp extends boolean,
>(
  namespace: Namespace,
  input: PhoneLifecycleOptions<Namespace, AllowSignUp>,
) => {
  const options = snapshotPhoneConfiguration({
    ...input,
    lifecycle: Object.freeze({
      ...(input.lifecycle === true ? defaultPhoneLifecyclePolicy : input.lifecycle),
    }),
  });

  const bind = <
    Claims extends ClaimsCodec,
    const Id extends string,
    const SessionId extends string,
  >(
    binding: StrategyBinding<Claims, Id, SessionId>,
  ) => bindLifecycle<Namespace, AllowSignUp, Claims, Id, SessionId>(binding, options);

  const definition: StrategyDefinition<LifecycleStrategy<Namespace, AllowSignUp>, Namespace> = {
    namespace,
    bind,
  };

  return Object.freeze(definition);
};

/** Configure phone sign-in; signup is opt-in and number management is independent. */
export function make<const Namespace extends string, const AllowSignUp extends boolean = false>(
  options: PhoneLifecycleOptions<Namespace, AllowSignUp> & { readonly namespace: Namespace },
): ReturnType<typeof defineLifecycle<Namespace, AllowSignUp>>;

export function make<
  const Namespace extends string | undefined = undefined,
  const AllowSignUp extends boolean = false,
>(
  options: PhoneLifecycleOptions<Namespace, AllowSignUp>,
): ReturnType<typeof defineLifecycle<Namespace | undefined, AllowSignUp>>;

export function make<const Namespace extends string, const AllowSignUp extends boolean = false>(
  options: PhoneOtpOptions<Namespace, AllowSignUp> & { readonly namespace: Namespace },
): ReturnType<typeof define<Namespace, AllowSignUp>>;

export function make<
  const Namespace extends string | undefined = undefined,
  const AllowSignUp extends boolean = false,
>(
  options?: PhoneOtpOptions<Namespace, AllowSignUp>,
): ReturnType<typeof define<Namespace | undefined, AllowSignUp>>;

export function make<const Namespace extends string | undefined>(
  options: PhoneOtpOptions<Namespace> | PhoneLifecycleOptions<Namespace> = {},
) {
  return "lifecycle" in options
    ? defineLifecycle(options.namespace, options)
    : define(options.namespace, options);
}
