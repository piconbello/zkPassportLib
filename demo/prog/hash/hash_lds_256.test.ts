import { Proof, VerificationKey, ZkProgram } from "o1js";
import { DynamicSHA2 } from "mina-credentials/dynamic";
import { assert, assertEquals } from "@std/assert";
import { sha256 } from "@noble/hashes/sha2";

import {
  compile_hash_lds_256,
  DynProof_Hash_Sha256,
  Hash_Sha256_Final,
  Hash_Sha256_Input,
  Hash_Sha256_Output,
  INPUT_256,
  prove_hash_lds_256,
} from "./hash_lds_256.ts";
import { parseBundle } from "../../parse.ts";
import { encodeHex } from "@std/encoding/hex";

function repeatedArray(size: number, pattern: number[]): number[] {
  const res = new Array(size);
  for (let i = 0; i < size; i++) {
    res[i] = pattern[i % pattern.length];
  }
  return res;
}

const HashDynChecker = ZkProgram({
  name: "hash-dyn-checker-256",

  methods: {
    check: {
      privateInputs: [DynProof_Hash_Sha256, VerificationKey],

      // deno-lint-ignore require-await
      async method(
        proof: DynProof_Hash_Sha256,
        vk: VerificationKey,
      ) {
        proof.verify(vk);
      },
    },
  },
});

Deno.test("hash lds 256 tests", async (t) => {
  const bundleFrodo = parseBundle(
    Deno.readTextFileSync("files/bundle.frodo.json"),
  );
  console.log("len", bundleFrodo.lds.length);
  console.log("digest", encodeHex(sha256(bundleFrodo.lds)));

  await t.step("compile", async () => {
    await compile_hash_lds_256(console.log);
  });

  // await t.step("small", async (t) => {
  //   const payload = new Hash_Lds_Sha256_Input({
  //     lds: LDS_256.fromBytes(
  //       bundleFrodo.lds,
  //     ),
  //   });

  //   let proofFinal: Proof<Hash_Lds_Sha256_Input, Hash_Lds_Sha256_Output>;
  //   await t.step("prove", async () => {
  //     proofFinal = await prove_hash_lds_256(payload, console.log);
  //   });

  //   await t.step("validate", async () => {
  //     const expected = DynamicSHA2.hash(256, payload.lds);
  //     assertEquals(
  //       proofFinal.publicOutput.digest.toBytes(),
  //       expected.toBytes(),
  //       "hash is wrong",
  //     );

  //     const isValid = await Hash_Lds_Sha256_Multi_Final.verify(proofFinal);
  //     assert(isValid, "proof is wrong");
  //   });
  // });

  // await t.step("big", async (t) => {
  //   const payload = new Hash_Lds_Sha256_Input({
  //     lds: LDS_256.fromBytes(
  //       repeatedArray(622, [1, 2, 3]),
  //     ),
  //   });

  //   let proofFinal: Proof<Hash_Lds_Sha256_Input, Hash_Lds_Sha256_Output>;
  //   await t.step("prove", async () => {
  //     proofFinal = await prove_hash_lds_256(payload, console.log);
  //   });

  //   await t.step("validate", async () => {
  //     const expected = DynamicSHA2.hash(256, payload.lds);
  //     assertEquals(
  //       proofFinal.publicOutput.digest.toBytes(),
  //       expected.toBytes(),
  //       "hash is wrong",
  //     );

  //     const isValid = await Hash_Lds_Sha256_Multi_Final.verify(proofFinal);
  //     assert(isValid, "proof is wrong");
  //   });
  // });

  await t.step("dyn", async (t) => {
    const payload = new Hash_Sha256_Input({
      payload: INPUT_256.fromBytes(
        repeatedArray(22, [1, 2, 3]),
      ),
    });

    let dynProof: DynProof_Hash_Sha256;
    await t.step("prove", async () => {
      const proofFinal = await prove_hash_lds_256(payload, console.log);
      assert(await Hash_Sha256_Final.verify(proofFinal));
      dynProof = DynProof_Hash_Sha256.fromProof(proofFinal);
    });

    let dynVk: VerificationKey;
    await t.step("compile dyn checker", async () => {
      dynVk = (await HashDynChecker.compile()).verificationKey;
    });

    await t.step("verify dyn", async () => {
      const proof = await HashDynChecker.check(dynProof, dynVk);
      assert(await HashDynChecker.verify(proof.proof));
    });
  });
});
