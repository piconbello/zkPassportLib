import { VerificationKey, ZkProgram } from "o1js";
import { DynProofZkTD3_74 } from "../zkDG1/common.ts";
import { DynProofZkSign74_k1 } from "../zkSign/common.ts";

export const Zk_TD3_74_k1 = ZkProgram({
  name: "td3_74_k1",

  methods: {
    verifyCombine: {
      privateInputs: [
        VerificationKey,
        DynProofZkTD3_74,
        VerificationKey,
        DynProofZkSign74_k1,
      ],

      // deno-lint-ignore require-await
      async method(
        vkDG1: VerificationKey,
        proofDG1: DynProofZkTD3_74,
        vkSign: VerificationKey,
        proofSign: DynProofZkSign74_k1,
      ) {
        // TODO connect public to public between
        proofDG1.verify(vkDG1);
        proofSign.verify(vkSign);
      },
    },
  },
});
