import { Hash, Struct, ZkProgram } from "o1js";
import { bytes32ToScalar, EcdsaSecp256k1, Secp256k1 } from "../utilsO1.ts";
import { SIGNED_ATTRS } from "./constants.ts";

export class SignedAttrs_Secp256k1_Sha256_Input extends Struct({
  signedAttrs: SIGNED_ATTRS,
  publicKey: Secp256k1,
  signature: EcdsaSecp256k1,
}) {}

export const SignedAttrs_Secp256k1_Sha256 = ZkProgram({
  name: "signedattrs-secp256k1-sha256",
  publicInput: SignedAttrs_Secp256k1_Sha256_Input,

  methods: {
    verifySignedAttrs: {
      privateInputs: [],

      // deno-lint-ignore require-await
      async method(inp: SignedAttrs_Secp256k1_Sha256_Input) {
        const hash = Hash.SHA2_256.hash(inp.signedAttrs);
        const aff = bytes32ToScalar(hash.bytes);
        const isValid = inp.signature.verifySignedHash(aff, inp.publicKey);
        isValid.assertTrue("signature validation failed");
      },
    },
  },
});
