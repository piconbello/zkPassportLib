import { Hash, Provable, Struct, VerificationKey, ZkProgram } from "o1js";
import { assertSubarray } from "../../utilsO1.ts";
import {
  DG1_TD3,
  DIGEST_SIZE,
  OFFSET_DG1_IN_LDS,
  OFFSET_LDS_IN_SIGNEDATTRS,
  SIGNED_ATTRS,
} from "./constants.ts";
import { DynProof_Hash_Lds_Sha256 } from "./hash_lds_256.ts";

export class Td3_SignedAttrs_Sha256_Input extends Struct({
  dg1: DG1_TD3,
  signedAttrs: SIGNED_ATTRS,
}) {}

export const Td3_SignedAttrs_Sha256 = ZkProgram({
  name: "td3-lds-sha256",
  publicInput: Td3_SignedAttrs_Sha256_Input,

  methods: {
    proveTD3toSignedAttrs: {
      privateInputs: [
        VerificationKey,
        DynProof_Hash_Lds_Sha256,
      ],

      // deno-lint-ignore require-await
      async method(
        inp: Td3_SignedAttrs_Sha256_Input,
        vkHash: VerificationKey,
        proofHash: DynProof_Hash_Lds_Sha256,
      ) {
        // const dg1Digest = Hash.SHA2_256.hash(inp.dg1);
        // const lds = proofHash.publicInput.lds;
        // lds.length.assertGreaterThan(
        //   OFFSET_DG1_IN_LDS + DIGEST_SIZE,
        // );
        // // Provable.log("1");
        // assertSubarray(
        //   lds.array,
        //   dg1Digest.bytes,
        //   DIGEST_SIZE,
        //   OFFSET_DG1_IN_LDS,
        //   "dg1 in lds",
        // );
        // Provable.log("2");
        // TODO: check vk
        proofHash.verify(vkHash);
        // Provable.log("3");
        const ldsDigest = proofHash.publicOutput.digest;
        // Provable.log("4");
        // assertSubarray(
        //   inp.signedAttrs.bytes,
        //   ldsDigest.bytes,
        //   DIGEST_SIZE,
        //   OFFSET_LDS_IN_SIGNEDATTRS,
        //   "lds in signedAttrs",
        // );
        // Provable.log("5");
      },
    },
  },
});
