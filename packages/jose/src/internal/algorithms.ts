import * as CryptoError from "effect/crypto/CryptoError";
import * as Digest from "effect/crypto/Digest";
import * as Signature from "effect/crypto/Signature";

import type { AsymmetricAlgorithm } from "../Jwk";

export const algorithms = {
  ES256: Signature.ecdsaP256,
  RS256: Signature.rsaPkcs1v15({ hash: Digest.sha256, modulusLength: 2048 }),
  PS256: Signature.rsaPss({ hash: Digest.sha256, modulusLength: 2048, saltLength: 32 }),
  EdDSA: Signature.ed25519,
} satisfies Record<AsymmetricAlgorithm, Signature.Algorithm>;

/** Keep native diagnostics and key material out of JOSE failures. */
export const sanitizeCryptoError = (error: CryptoError.CryptoError): CryptoError.CryptoError => {
  const description = "Cryptographic operation failed";

  const reason =
    error.reason._tag === "InvalidArgument"
      ? new CryptoError.InvalidArgument({ description })
      : error.reason._tag === "InvalidKey"
        ? new CryptoError.InvalidKey({ description })
        : error.reason._tag === "Unsupported"
          ? new CryptoError.Unsupported({ description })
          : error.reason._tag === "NotExtractable"
            ? new CryptoError.NotExtractable({ description })
            : new CryptoError.DecryptionFailed();

  return new CryptoError.CryptoError({ module: "JOSE", method: "crypto", reason });
};
