import { assert, Bytes, Hash } from "npm:o1js";
import { parseBundle, PublicKeyEC, SignatureEC } from "./parse.ts";
import {
  assertSubarray,
  bytes32ToScalar,
  EcdsaSecp256k1,
  Secp256k1,
} from "./utilsO1.ts";
import {
  CertificateRegistry,
  isValidRegistryWitness,
} from "./certificateRegistry.ts";
import { randomMasterlist } from "./mockMasterlist.ts";

function assertDG1inLDS(dg1: Uint8Array, lds: Uint8Array) {
  const dg1Digest = Hash.SHA2_256.hash(Bytes.from(dg1));
  const ldsBytes = Bytes.from(lds);
  const offset = 29;
  assertSubarray(ldsBytes.bytes, dg1Digest.bytes, 32, offset, "dg1 in lds");
}

function assertLDSinSignedAttrs(lds: Uint8Array, signedAttrs: Uint8Array) {
  const ldsDigest = Hash.SHA2_256.hash(Bytes.from(lds));
  const signedAttrsBytes = Bytes.from(signedAttrs);
  const offset = 42;
  assertSubarray(
    signedAttrsBytes.bytes,
    ldsDigest.bytes,
    32,
    offset,
    "lds in signedAttrs",
  );
}

function assertSignedAttrsIsSignedByCert(
  signedAttrs: Uint8Array,
  pubkey: PublicKeyEC,
  signature: SignatureEC,
) {
  const digest = Hash.SHA2_256.hash(Bytes.from(signedAttrs));
  const aff = bytes32ToScalar(digest.bytes);
  const pubkeyObj = new Secp256k1(pubkey);
  const signatureObj = new EcdsaSecp256k1(signature);
  const isValid = signatureObj.verifySignedHash(aff, pubkeyObj);
  isValid.assertTrue("document signature validation failed");
}

function assertLocalIsSignedByMaster(
  cert_local_tbs: Uint8Array,
  master_pubkey: PublicKeyEC,
  signature: SignatureEC,
) {
  const digest = Hash.SHA2_256.hash(Bytes.from(cert_local_tbs));
  const aff = bytes32ToScalar(digest.bytes);
  const pubkeyObj = new Secp256k1(master_pubkey);
  const signatureObj = new EcdsaSecp256k1(signature);
  const isValid = signatureObj.verifySignedHash(aff, pubkeyObj);
  isValid.assertTrue("cert signature validation failed");
}

if (import.meta.main) {
  const bundleText = Deno.readTextFileSync("files/bundle.frodo.json");
  const bundle = parseBundle(bundleText); // its verified that its sha256 + secp256k1 all over.
  console.log("📋 Loaded and parsed passport bundle");

  assertDG1inLDS(bundle.dg1, bundle.lds);
  console.log(
    "✅ Verified DG1 data matches LDS",
  );
  assertLDSinSignedAttrs(bundle.lds, bundle.signed_attrs);
  console.log(
    "✅ Verified LDS matches signed attributes",
  );
  assertSignedAttrsIsSignedByCert(
    bundle.signed_attrs,
    bundle.cert_local_pubkey,
    bundle.document_signature,
  );
  console.log("✅ Verified document signature with local certificate");
  assertLocalIsSignedByMaster(
    bundle.cert_local_tbs,
    bundle.cert_master_pubkey,
    bundle.cert_local_signature,
  );
  console.log("✅ Verified local certificate is signed by master certificate");

  // const masterListText = Deno.readTextFileSync("files/masterlist_284.json");
  // const masterlist = parseMasterlist(masterListText);
  const [masterlist, _cert_master_index] = randomMasterlist(800, {
    pubkey: bundle.cert_master_pubkey,
    subject_key_id: bundle.cert_master_subject_key_id,
  });
  console.log("📋 Generated random masterlist with 800 certificates");

  console.log(
    "⏳ Creating certificate registry from masterlist (this may take a while)...",
  );
  const registry = new CertificateRegistry(masterlist);
  const registryProof = registry.proveFor(bundle.cert_master_pubkey);
  console.log("🔍 Created registry proof for master certificate");
  assert(
    isValidRegistryWitness(
      registryProof.root,
      registryProof.certificate,
      registryProof.witness,
    ),
    "witness is valid",
  );
  console.log("✅ Verified registry witness is valid");
}
