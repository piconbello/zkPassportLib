import { Hash, ZkProgram } from "o1js";
import { DigestAlgo } from "../common.ts";
import { hashToScalar, ZkSign_PubInput_74_k1 } from "./common.ts";
import { assertEquals } from "jsr:@std/assert";
import { lengthSignedAttrs } from "../common.ts";

export const DIGEST_ALGO: DigestAlgo = "sha256";

assertEquals(lengthSignedAttrs(DIGEST_ALGO), 74);

export const ZkSignSha256Secp256k1 = ZkProgram({
  name: "sha256-secp256k1",
  publicInput: ZkSign_PubInput_74_k1,

  methods: {
    verifySignature: {
      privateInputs: [],

      // deno-lint-ignore require-await
      async method(inp: ZkSign_PubInput_74_k1) {
        const hash = Hash.SHA2_256.hash(inp.payload);
        const aff = hashToScalar(hash);
        const isValid = inp.signature.verifySignedHash(aff, inp.publicKey);
        isValid.assertTrue("signature validation failed");
      },
    },
  },
});
