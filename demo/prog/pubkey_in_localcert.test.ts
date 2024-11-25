// deno-lint-ignore-file require-await

import { Bytes, UInt32 } from "o1js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { assert } from "@std/assert";

import { parseBundle } from "../parse.ts";
import {
  assertECpubkey256Uncompressed,
  assertSubarrayDynamic,
  Bytes65,
  CertTBS,
  Secp256k1,
} from "../utilsO1.ts";
import {
  PubkeyInCert256,
  PubkeyInCert256_Input,
} from "./pubkey_in_localcert_ec256.ts";

const findOffset = (larger: Uint8Array, smaller: Uint8Array): number =>
  [...larger.entries()]
    .findIndex(([i]) => smaller.every((val, j) => larger[i + j] === val));

Deno.test("pubkey in localcert tests", async (t) => {
  const bundleFrodo = parseBundle(
    Deno.readTextFileSync("files/bundle.frodo.json"),
  );
  const coords = {
    x: bundleFrodo.cert_local_pubkey.x,
    y: bundleFrodo.cert_local_pubkey.y,
  };
  const pubkey_o1 = new Secp256k1(coords);
  const pubkey_native = secp256k1.ProjectivePoint.fromAffine(coords);
  const sec1 = pubkey_native.toRawBytes(false);
  const cert_local = bundleFrodo.cert_local_tbs;

  await t.step("pubkey conversion", async () => {
    assertECpubkey256Uncompressed(
      Bytes65.from(sec1),
      pubkey_o1.x.value,
      pubkey_o1.y.value,
    );
  });
  await t.step("check subarray", async () => {
    const offset = findOffset(cert_local, sec1);
    assertSubarrayDynamic(
      CertTBS.fromBytes(cert_local),
      Bytes.from(sec1),
      UInt32.from(offset),
    );
  });
  await t.step("⏳ Compiling zkProgram", async () => {
    await PubkeyInCert256.compile();
  });
  await t.step("test zkProg ec256", async () => {
    const offset = findOffset(cert_local, sec1);
    const proof = await PubkeyInCert256.associatePubkeyWithCert(
      new PubkeyInCert256_Input({
        cert: CertTBS.fromBytes(cert_local),
        x: pubkey_o1.x.value,
        y: pubkey_o1.y.value,
      }),
      Bytes.from(sec1),
      UInt32.from(offset),
    );

    const isValid = await PubkeyInCert256.verify(proof.proof);
    assert(isValid);
  });
});
