import { Bytes, Proof, VerificationKey } from "o1js";

import { parseBundle } from "../../parse.ts";
import { Td3_Lds_Sha256, Td3_Lds_Sha256_Input } from "./td3_lds_sha256.ts";
import {
  Lds_SignedAttrs_Sha256,
  Lds_SignedAttrs_Sha256_Input,
} from "./lds_signedattrs_sha256.ts";
import { LDS } from "./constants.ts";
import {
  Combine_Td3_SignedAttrs_Sha256,
  Dyn_Lds_SignedAttrs_Sha256,
  Dyn_Td3_Lds_Sha256,
} from "./combine_td3_signedattrs_sha256.ts";
import { assertEquals } from "@std/assert";

Deno.test("head tests", async (t) => {
  // we know that it is sha256 + secp256k1 all over.
  const bundleFrodo = parseBundle(
    Deno.readTextFileSync("files/bundle.frodo.json"),
  );

  let vk_td3_lds: VerificationKey | null = null;
  await t.step("⏳ Compiling DG1 to LDS", async () => {
    const prog = await Td3_Lds_Sha256.compile();
    vk_td3_lds = prog.verificationKey;
  });
  let proof_dg1_in_lds: Proof<Td3_Lds_Sha256_Input, void> | null = null;
  await t.step("❔ Is DG1 in LDS", async () => {
    const proof = await Td3_Lds_Sha256.isDg1InLds(
      new Td3_Lds_Sha256_Input({
        dg1: Bytes.from(bundleFrodo.dg1),
        lds: LDS.fromBytes(bundleFrodo.lds),
      }),
    );

    await Td3_Lds_Sha256.verify(proof.proof);
    proof_dg1_in_lds = proof.proof;
  });

  let vk_lds_signedattrs: VerificationKey | null = null;
  await t.step("⏳ Compiling LDS to SignedAttrs", async () => {
    const prog = await Lds_SignedAttrs_Sha256.compile();
    vk_lds_signedattrs = prog.verificationKey;
  });
  let proof_lds_in_signedattrs:
    | Proof<Lds_SignedAttrs_Sha256_Input, void>
    | null = null;
  await t.step("❔ Is LDS in SignedAttrs", async () => {
    const proof = await Lds_SignedAttrs_Sha256.isLdsInSignedattrs(
      new Lds_SignedAttrs_Sha256_Input({
        lds: LDS.fromBytes(bundleFrodo.lds),
        signedAttrs: Bytes.from(bundleFrodo.signed_attrs),
      }),
    );

    await Lds_SignedAttrs_Sha256.verify(proof.proof);
    proof_lds_in_signedattrs = proof.proof;
  });

  await t.step("⏳ Compiling Combine DG1 to SignedAttrs", async () => {
    await Combine_Td3_SignedAttrs_Sha256.compile();
  });
  await t.step("❔ Combine DG1 to SignedAttrs", async () => {
    const proof = await Combine_Td3_SignedAttrs_Sha256.verifyDg1ToSignedAttrs(
      vk_td3_lds!,
      Dyn_Td3_Lds_Sha256.fromProof(proof_dg1_in_lds!),
      vk_lds_signedattrs!,
      Dyn_Lds_SignedAttrs_Sha256.fromProof(proof_lds_in_signedattrs!),
    );

    await Combine_Td3_SignedAttrs_Sha256.verify(proof.proof);
    assertEquals(proof.proof.publicOutput.dg1.toBytes(), bundleFrodo.dg1);
    assertEquals(
      proof.proof.publicOutput.signedAttrs.toBytes(),
      bundleFrodo.signed_attrs,
    );
  });
});
