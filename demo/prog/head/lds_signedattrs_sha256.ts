import { Struct, ZkProgram } from "o1js";
import { DynamicSHA2 } from "mina-credentials/dynamic";
import { assertSubarray } from "../../utilsO1.ts";
import {
  DIGEST_SIZE,
  LDS,
  OFFSET_LDS_IN_SIGNEDATTRS,
  SIGNED_ATTRS,
} from "./constants.ts";

export class Lds_SignedAttrs_Sha256_Input extends Struct({
  lds: LDS,
  signedAttrs: SIGNED_ATTRS,
}) {}

export const Lds_SignedAttrs_Sha256 = ZkProgram({
  name: "lds-signedAttrs-sha256",
  publicInput: Lds_SignedAttrs_Sha256_Input,

  methods: {
    isLdsInSignedattrs: {
      privateInputs: [],

      // deno-lint-ignore require-await
      async method(inp: Lds_SignedAttrs_Sha256_Input) {
        const ldsDigest = DynamicSHA2.hash(256, inp.lds);
        assertSubarray(
          inp.signedAttrs.bytes,
          ldsDigest.bytes,
          DIGEST_SIZE,
          OFFSET_LDS_IN_SIGNEDATTRS,
          "lds in signedAttrs",
        );
      },
    },
  },
});
