import { Bytes } from "o1js";

import { parseBundle, parseMasterlist } from "../parse.ts";
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
import { assert } from "@std/assert";

Deno.test("demo tests", async (t) => {
  await t.step("⏳ Compiling SignedAttrs Signature Verification", async () => {
    await SignedAttrs_Secp256k1_Sha256.compile();
  });
  await t.step("❔ Is SignedAttrs signed", async () => {
    // we know that it is sha256 + secp256k1 all over.
    const bundleFrodo = parseBundle(
      Deno.readTextFileSync("files/bundle.frodo.json"),
    );
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

    const isValid = await SignedAttrs_Secp256k1_Sha256.verify(proof.proof);
    assert(isValid);
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

    const isValid = await MasterCert_Secp521r1.verify(proof.proof);
    assert(isValid);
  });
});
