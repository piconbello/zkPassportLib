import { Bytes, Proof, VerificationKey } from "o1js";

import { parseBundle, parseMasterlist } from "../parse.ts";
import { Td3_Lds_Sha256, Td3_Lds_Sha256_Input } from "./td3_lds_sha256.ts";
import {
  Lds_SignedAttrs_Sha256,
  Lds_SignedAttrs_Sha256_Input,
} from "./lds_signedattrs_sha256.ts";
import { LDS } from "./constants.ts";
import {
  SignedAttrs_Secp256k1_Sha256,
  SignedAttrs_Secp256k1_Sha256_Input,
} from "./signedattrs_secp256k1_sha256.ts";
import { bigintToLimbs, EcdsaSecp256k1, Secp256k1 } from "../utilsO1.ts";
import { CertificateRegistry } from "../certificateRegistry.ts";
import {
  MasterCert_Secp521r1,
  MasterCert_Secp521r1_Input,
} from "./mastercert_secp521r1.ts";
import {
  Combine_Td3_SignedAttrs_Sha256,
  Combine_Td3_SignedAttrs_Sha256_Output,
  Dyn_Lds_SignedAttrs_Sha256,
  Dyn_Td3_Lds_Sha256,
} from "./combine_td3_signedattrs_sha256.ts";
import { assertEquals } from "@std/assert";

Deno.test("demo tests", async (t) => {
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

  await t.step("⏳ Compiling SignedAttrs Signature Verification", async () => {
    await SignedAttrs_Secp256k1_Sha256.compile();
  });
  let proof_signedattrs_is_signed:
    | Proof<SignedAttrs_Secp256k1_Sha256_Input, void>
    | null = null;
  await t.step("❔ Is SignedAttrs signed", async () => {
    const proof = await SignedAttrs_Secp256k1_Sha256.verifySignedAttrs(
      new SignedAttrs_Secp256k1_Sha256_Input({
        signedAttrs: Bytes.from(bundleFrodo.signed_attrs),
        publicKey: new Secp256k1({
          x: bundleFrodo.cert_local_pubkey.x,
          y: bundleFrodo.cert_local_pubkey.y,
        }),
        signature: new EcdsaSecp256k1({
          r: bundleFrodo.document_signature.r,
          s: bundleFrodo.document_signature.s,
        }),
      }),
    );

    await SignedAttrs_Secp256k1_Sha256.verify(proof.proof);
    proof_signedattrs_is_signed = proof.proof;
  });

  await t.step("⏳ Compiling Known Mastercert", async () => {
    await MasterCert_Secp521r1.compile();
  });
  let registry: CertificateRegistry | null = null;
  await t.step("⏳ Preparing Certificate Registry", async () => {
    const masterlist = parseMasterlist(
      Deno.readTextFileSync("files/masterlist_284.json"),
    );
    registry = new CertificateRegistry(masterlist);
    await MasterCert_Secp521r1.compile();
  });
  let proof_known_mastercert: Proof<MasterCert_Secp521r1_Input, void> | null =
    null;
  await t.step("❔ Is MasterCert known", async () => {
    const bundleHalit = parseBundle(
      Deno.readTextFileSync("files/bundle.halit.json"),
    );

    const x = bigintToLimbs(bundleHalit.cert_master_pubkey.x);
    const y = bigintToLimbs(bundleHalit.cert_master_pubkey.y);
    const witness = registry!.proveFor(bundleHalit.cert_master_pubkey);

    const proof = await MasterCert_Secp521r1.verifyKnownMastercert(
      new MasterCert_Secp521r1_Input({
        root: registry!.getRoot(),
        x,
        y,
      }),
      witness.witness,
    );

    await MasterCert_Secp521r1.verify(proof.proof);
    proof_known_mastercert = proof.proof;
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
