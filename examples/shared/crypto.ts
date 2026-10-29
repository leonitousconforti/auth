import * as WebCrypto from "@yielded/auth/WebCrypto";
import * as KdfAdmission from "@yielded/crypto/KdfAdmission";
import * as Portable from "@yielded/crypto/Portable";
import { Layer } from "effect";

// One admission instance protects each complete password operation and its nested
// KDF work. This example host chooses WebCrypto and the portable Argon2id backend.
const admission = KdfAdmission.layer();

export const CryptoLive = Layer.mergeAll(
  WebCrypto.layerWebCrypto,
  Portable.layer(globalThis.crypto.subtle).pipe(Layer.provideMerge(admission)),
);
