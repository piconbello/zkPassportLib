import { Bytes, Proof, VerificationKey } from "o1js";
import { assert } from "@std/assert";

import {
  compile_hash_lds_256,
  DynProof_Hash_Lds_Sha256,
  Hash_Lds_Sha256_Input,
  Hash_Lds_Sha256_Multi_Final,
  LDS_256,
  prove_hash_lds_256,
} from "./hash_lds_256.ts";
import { parseBundle } from "../../parse.ts";
import {
  Td3_SignedAttrs_Sha256,
  Td3_SignedAttrs_Sha256_Input,
} from "./td3_signedattrs_sha256.ts";

Deno.test("TD3 => SignedAttrs @ 256", async (t) => {
  const bundleFrodo = parseBundle(
    Deno.readTextFileSync("files/bundle.frodo.json"),
  );
  let vkHash: VerificationKey;
  await t.step("Compile LDS hasher", async () => {
    vkHash = await compile_hash_lds_256(console.log);
  });

  let proofHash: DynProof_Hash_Lds_Sha256;
  await t.step("Prove LDS digest", async () => {
    const proof = await prove_hash_lds_256(
      new Hash_Lds_Sha256_Input({
        lds: LDS_256.fromBytes(bundleFrodo.lds),
      }),
      console.log,
    );
    assert(await Hash_Lds_Sha256_Multi_Final.verify(proof));
    proofHash = DynProof_Hash_Lds_Sha256.fromProof(proof);
  });

  await t.step("Compile TD3 => SignedAttrs", async () => {
    await Td3_SignedAttrs_Sha256.compile();
  });

  let proofTD3toSignedAttrs: Proof<Td3_SignedAttrs_Sha256_Input, void>;
  await t.step("Prove TD3 => SignedAttrs", async () => {
    const proof = await Td3_SignedAttrs_Sha256.proveTD3toSignedAttrs(
      new Td3_SignedAttrs_Sha256_Input({
        dg1: Bytes.from(bundleFrodo.dg1),
        signedAttrs: Bytes.from(bundleFrodo.signed_attrs),
      }),
      vkHash,
      proofHash,
    );
    proofTD3toSignedAttrs = proof.proof;
  });

  // await t.step("Verify TD3 => SignedAttrs", async () => {
  //   const isValid = await Td3_SignedAttrs_Sha256.verify(proofTD3toSignedAttrs);
  //   assert(isValid);
  // });

  // const payload = Hash_Lds_Sha256_Multi_Input.fromBytes(
  //   repeatedArray(640, [1, 2, 3, 4]),
  // );

  // let proofFinal: Proof<undefined, Bytes>;
  // await t.step("prove", async () => {
  //   proofFinal = await prove_hash_lds_256_multi(payload, console.log);
  // });

  // await t.step("validate", async () => {
  //   const expected = DynamicSHA2.hash(256, payload);
  //   assertEquals(
  //     proofFinal.publicOutput.toBytes(),
  //     expected.toBytes(),
  //     "hash is wrong",
  //   );

  //   const isValid = await Hash_Lds_Sha256_Multi_Final.verify(proofFinal);
  //   assert(isValid, "proof is wrong");
  // });
});
