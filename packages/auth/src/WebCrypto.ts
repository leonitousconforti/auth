import * as Aead from "effect/crypto/Aead";
import * as Digest from "effect/crypto/Digest";
import * as Mac from "effect/crypto/Mac";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as Signature from "effect/crypto/Signature";
import * as Base64 from "effect/encoding/Base64";
import * as Layer from "effect/Layer";
import * as Result from "effect/Result";

/** Secure entropy and digests from the host WebCrypto capability. */
export const layerCryptoWeb = Layer.merge(SecureRandom.layerWebCrypto, Digest.layerWebCrypto);

/** Auth's WebCrypto services, including portable XChaCha20-Poly1305. */
export const layerWebCrypto = Layer.mergeAll(
  Mac.layerWebCrypto,
  Aead.layerWebCrypto,
  Signature.layerWebCrypto,
).pipe(Layer.provideMerge(layerCryptoWeb));

/** Decode a PEM body's base64 payload into its DER bytes. */
export const decodePem = (pem: string): Uint8Array | undefined =>
  Result.getOrUndefined(
    Base64.decode(
      pem
        .replace(/\\r\\n|\\n/g, "\n")
        .replace(/-----[A-Z ]+-----/g, "")
        .replace(/\s/g, ""),
    ),
  );
