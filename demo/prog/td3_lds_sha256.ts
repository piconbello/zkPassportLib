import { Hash, Struct, ZkProgram } from "o1js";
import { assertSubarray } from "../utilsO1.ts";
import { DG1_TD3, DIGEST_SIZE, LDS, OFFSET_DG1_IN_LDS } from "./constants.ts";

export class Td3_Lds_Sha256_Input extends Struct({
  dg1: DG1_TD3,
  lds: LDS,
}) {}

export const Td3_Lds_Sha256 = ZkProgram({
  name: "td3-lds-sha256",
  publicInput: Td3_Lds_Sha256_Input,

  methods: {
    isDg1InLds: {
      privateInputs: [],

      // deno-lint-ignore require-await
      async method(inp: Td3_Lds_Sha256_Input) {
        const dg1Digest = Hash.SHA2_256.hash(inp.dg1);
        inp.lds.length.assertGreaterThan(OFFSET_DG1_IN_LDS + DIGEST_SIZE);
        assertSubarray(
          inp.lds.array,
          dg1Digest.bytes,
          DIGEST_SIZE,
          OFFSET_DG1_IN_LDS,
          "dg1 in lds",
        );
      },
    },
  },
});
