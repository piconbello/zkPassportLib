import {
  DynamicProof,
  FeatureFlags,
  Struct,
  VerificationKey,
  Void,
  ZkProgram,
} from "o1js";

import { Td3_Lds_Sha256_Input } from "./td3_lds_sha256.ts";
import { Lds_SignedAttrs_Sha256_Input } from "./lds_signedattrs_sha256.ts";
import { DG1_TD3, SIGNED_ATTRS } from "./constants.ts";

export class Dyn_Td3_Lds_Sha256
  extends DynamicProof<Td3_Lds_Sha256_Input, Void> {
  static override publicInputType = Td3_Lds_Sha256_Input;
  static override publicOutputType = Void;
  static override maxProofsVerified = 0 as const;
  static override featureFlags = FeatureFlags.allMaybe;
}

export class Dyn_Lds_SignedAttrs_Sha256
  extends DynamicProof<Lds_SignedAttrs_Sha256_Input, Void> {
  static override publicInputType = Lds_SignedAttrs_Sha256_Input;
  static override publicOutputType = Void;
  static override maxProofsVerified = 0 as const;
  static override featureFlags = FeatureFlags.allMaybe;
}

export class Combine_Td3_SignedAttrs_Sha256_Output extends Struct({
  dg1: DG1_TD3,
  signedAttrs: SIGNED_ATTRS,
}) {}

export const Combine_Td3_SignedAttrs_Sha256 = ZkProgram({
  name: "lds-signedAttrs-sha256",
  publicOutput: Combine_Td3_SignedAttrs_Sha256_Output,

  methods: {
    verifyDg1ToSignedAttrs: {
      privateInputs: [
        VerificationKey,
        Dyn_Td3_Lds_Sha256,
        VerificationKey,
        Dyn_Lds_SignedAttrs_Sha256,
      ],

      // deno-lint-ignore require-await
      async method(
        vk_dg1: VerificationKey,
        dyn_dg1: Dyn_Td3_Lds_Sha256,
        vk_signedAttrs: VerificationKey,
        dyn_signedAttrs: Dyn_Lds_SignedAttrs_Sha256,
      ) {
        dyn_dg1.verify(vk_dg1);
        dyn_signedAttrs.verify(vk_signedAttrs);

        const ldsLen = dyn_dg1.publicInput.lds.array.length;
        for (let i = 0; i < ldsLen; i += 1) {
          dyn_dg1.publicInput.lds.array[i].assertEquals(
            dyn_signedAttrs.publicInput.lds.array[i],
          );
        }

        return {
          publicOutput: new Combine_Td3_SignedAttrs_Sha256_Output({
            dg1: dyn_dg1.publicInput.dg1,
            signedAttrs: dyn_signedAttrs.publicInput.signedAttrs,
          }),
        };
      },
    },
  },
});
