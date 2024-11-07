import { generateDG1 } from "../../mock/dg1.ts";
import { mockLdsAndSignedAttrs } from "../../mock/ldsSerializer.ts";
import { Bytes } from "o1js";
import { DIGEST_ALGO, LDS_MAX_LENGTH, ZkTD3_sha256 } from "./td3_sha256.ts";
import { DynamicBytes } from "../primitives/dynamic-bytes.ts";

Deno.test("zkprog DG1 TD3 sha256", async (t) => {
  console.log((await ZkTD3_sha256.analyzeMethods()).mrz2signedAttrs);
  // bro... sha2_256 is more expensive than sha3_256.
  // returns 74k.
  await ZkTD3_sha256.compile();

  await t.step("proves", async () => {
    const mock = generateDG1();
    const { lds, signedAttrs } = mockLdsAndSignedAttrs(
      mock.dg1,
      DIGEST_ALGO,
      new Set([1, 2, 6, 11, 12, 14]),
    );
    // const birthYear = parseInt(mock.dateOfBirth.slice(0, 2));
    const proof = await ZkTD3_sha256.mrz2signedAttrs({
      dg1: Bytes.from(mock.dg1),
      signedAttrs: Bytes.from(signedAttrs),
      // birthYear: Field(birthYear),
    }, DynamicBytes({ maxLength: LDS_MAX_LENGTH }).fromBytes(lds));

    await ZkTD3_sha256.verify(proof.proof);
  });
});
