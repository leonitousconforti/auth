import { type Effect, type Redacted, Schema } from "effect";

import { type OAuthProtocolRejected } from "../../signInErrors";
import {
  type OAuthProtocolConfiguration,
  type OAuthVerifiedExternalIdentity,
} from "../../signInModels";
import type {
  TokenCompatibility,
  tokenCompatibility,
  githubVerifiedPrimaryEmail,
} from "./compatibility";
import type { DiscoveryProfile, discoveryProfile } from "./discovery";

export const IdTokenSignedResponseAlg = Schema.Literals([
  "RS256",
  "PS256",
  "ES256",
  "EdDSA",
  "HS256",
]);

export type IdTokenSignedResponseAlg = typeof IdTokenSignedResponseAlg.Type;

export const defaultIdTokenSignedResponseAlgs: readonly IdTokenSignedResponseAlg[] = [
  "RS256",
  "PS256",
  "ES256",
  "EdDSA",
];

export const idTokenSignedResponseAlgs: readonly IdTokenSignedResponseAlg[] = [
  "RS256",
  "PS256",
  "ES256",
  "EdDSA",
  "HS256",
];

export const advertisedIdTokenAlgorithms = (
  advertised: ReadonlyArray<string> | undefined,
  allowed: ReadonlyArray<IdTokenSignedResponseAlg>,
): ReadonlyArray<IdTokenSignedResponseAlg> | undefined => {
  const supported = idTokenSignedResponseAlgs.filter(
    (algorithm) => allowed.includes(algorithm) && advertised?.includes(algorithm),
  );

  return supported.length === 0 ? undefined : supported;
};

export const OidcUserInfoMode = Schema.Literals(["id-token", "merge"]);
export type OidcUserInfoMode = typeof OidcUserInfoMode.Type;

export type OidcProfileSchema = Schema.Codec<Schema.JsonObject>;

export class OpenIdConnectConfigurationError extends Schema.TaggedError<OpenIdConnectConfigurationError>()(
  "OpenIdConnectConfigurationError",
  {
    reason: Schema.Literals([
      "provider",
      "generation",
      "issuer",
      "callback",
      "authentication",
      "parameters",
      "metadata",
      "identity-source",
    ]),
  },
) {}

export type OpenIdConnectAuthentication =
  | { readonly method: "client_secret_basic"; readonly secret: Redacted.Redacted<string> }
  | { readonly method: "client_secret_post"; readonly secret: Redacted.Redacted<string> }
  | { readonly method: "none"; readonly publicClient: true };

export interface PlainOAuthIdentity {
  readonly subject: string;
  readonly profile?: NonNullable<OAuthVerifiedExternalIdentity["profile"]>;
}

interface ProviderGeneration {
  readonly provider: OAuthProtocolConfiguration["provider"];
  readonly configurationGeneration: OAuthProtocolConfiguration["configurationGeneration"];
  readonly issuance: "active" | "retired";
  /** Preserve this exact issuer identifier, including an optional trailing slash. */
  readonly issuer: OAuthProtocolConfiguration["issuer"];
  readonly responseIssuerMode: OAuthProtocolConfiguration["responseIssuerMode"];
  readonly clientId: string;
  readonly authentication: OpenIdConnectAuthentication;
  readonly callbacks: ReadonlyArray<{
    readonly callbackId: OAuthProtocolConfiguration["callbackId"];
    readonly redirectUri: OAuthProtocolConfiguration["redirectUri"];
  }>;
  readonly scopes: ReadonlyArray<string>;
  readonly authorizationParameters?: Readonly<Record<string, string>>;
  readonly tokenParameters?: Readonly<Record<string, string>>;
}

export interface OpenIdConnectOidcProvider extends ProviderGeneration {
  /** @internal Provider-specific discovery metadata, retained by the configuration codec. */
  readonly [discoveryProfile]?: typeof DiscoveryProfile.Type;
  readonly protocol: "oidc";
  readonly idTokenSignedResponseAlg: ReadonlyArray<IdTokenSignedResponseAlg>;
  readonly pkceS256: boolean;
  readonly userInfo: OidcUserInfoMode;
  readonly profileSchema: OidcProfileSchema;
  readonly maxAgeSeconds?: number;
}

export interface OpenIdConnectOAuthProvider<R = never> extends ProviderGeneration {
  /** @internal First-party provider behavior, retained by the configuration codec. */
  readonly [tokenCompatibility]?: TokenCompatibility;
  /** @internal Opt-in GitHub email lookup, retained by the generation codec. */
  readonly [githubVerifiedPrimaryEmail]?: boolean;
  readonly protocol: "oauth";
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly pkceS256: boolean;
  readonly identitySource: {
    readonly url: string;
    readonly headers?: Readonly<Record<string, string>>;
    /** Receives only the freshly fetched authenticated identity body, never a grant. */
    readonly decodeIdentity: (
      body: unknown,
    ) => Effect.Effect<PlainOAuthIdentity, OAuthProtocolRejected, R>;
  };
}

export interface OpenIdConnectOAuthProtocolOptions<R = never> {
  readonly providers: ReadonlyArray<OpenIdConnectOidcProvider | OpenIdConnectOAuthProvider<R>>;
  /** Per-request deadline; the method separately limits the complete exchange. */
  readonly timeoutSeconds: number;
}
