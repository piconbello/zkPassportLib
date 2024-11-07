import { Bytes, VerificationKey } from "o1js";
import { sha256 } from "@noble/hashes/sha2";
import { assert } from "@std/assert";

import { DIGEST_ALGO, LDS, ZkTD3_sha256 } from "../zkDG1/td3_sha256.ts";
import { ZkSignSha256Secp256k1 } from "../zkSign/sha256_secp256k1.ts";
import { generateDG1 } from "../../mock/dg1.ts";
import { SignerSecp256k1 } from "../../mock/signerSecp256k1.ts";
import { mockLdsAndSignedAttrs } from "../../mock/ldsSerializer.ts";
import { DynProofZkSign74_k1 } from "../zkSign/common.ts";
import { Zk_TD3_74_k1 } from "./td3_74_k1.ts";
import { DynProofZkTD3_74 } from "../zkDG1/common.ts";

Deno.test("combine TD3 sha256 sha256+secp256k1", async (t) => {
  let vkDG1: VerificationKey;
  let vkSign: VerificationKey;
  await t.step("compiles", async () => {
    vkDG1 = (await ZkTD3_sha256.compile()).verificationKey;
    console.log("compiled td3");
    vkSign = (await ZkSignSha256Secp256k1.compile()).verificationKey;
    await Zk_TD3_74_k1.compile();
  });

  const signer = new SignerSecp256k1();
  const publicKey = signer.pubO1;
  const mock = generateDG1();
  const { lds, signedAttrs } = mockLdsAndSignedAttrs(
    mock.dg1,
    DIGEST_ALGO,
    new Set([1, 2, 6, 11, 12, 14]),
  );
  const signature = signer.sign(sha256(signedAttrs));

  let dynProofDG1: DynProofZkTD3_74;
  await t.step("dg1", async () => {
    const proofDG1 = await ZkTD3_sha256.mrz2signedAttrs({
      dg1: Bytes.from(mock.dg1),
      signedAttrs: Bytes.from(signedAttrs),
    }, LDS.fromBytes(lds));
    assert(await ZkTD3_sha256.verify(proofDG1.proof));
    dynProofDG1 = DynProofZkTD3_74.fromProof(proofDG1.proof);
    dynProofDG1.verify(vkDG1);
  });

  let dynProofSign: DynProofZkSign74_k1;
  await t.step("sign", async () => {
    const proofSign = await ZkSignSha256Secp256k1.verifySignature({
      payload: Bytes.from(signedAttrs),
      signature,
      publicKey,
    });
    assert(await ZkSignSha256Secp256k1.verify(proofSign.proof));
    dynProofSign = DynProofZkSign74_k1.fromProof(proofSign.proof);
    dynProofSign.verify(vkSign);
  });

  await t.step("combine", async () => {
    const proofCombo = await Zk_TD3_74_k1.verifyCombine(
      vkDG1,
      dynProofDG1,
      vkSign,
      dynProofSign,
    );

    await Zk_TD3_74_k1.verify(proofCombo.proof);
  });
});
