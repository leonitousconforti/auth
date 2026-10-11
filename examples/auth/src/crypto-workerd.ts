import { KdfAdmission } from "@yielded/crypto";
import * as WorkerdCrypto from "@yielded/crypto/platform-workerd";
import * as WebCrypto from "@yielded/crypto/WebCrypto";
import { Layer } from "effect";

// Bundle this composition with Wrangler and enable nodejs_compat.
const Admission = KdfAdmission.layer();

export const CryptoLive = Layer.merge(
  WebCrypto.layerCryptoWeb,
  WorkerdCrypto.layer(globalThis.crypto.subtle).pipe(Layer.provideMerge(Admission)),
);
