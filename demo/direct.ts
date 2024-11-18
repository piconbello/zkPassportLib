import {
  decodeBase64,
  decodeHex,
  encodeBase64,
  encodeHex,
} from "@std/encoding";
import {
  assert,
  Bool,
  Bytes,
  createEcdsa,
  createForeignCurve,
  Crypto,
  Hash,
  UInt8,
} from "o1js";

interface PublicKeyECb64 {
  type: string;
  curve: string;
  x: string;
  y: string;
}

interface SignatureECb64 {
  type: string;
  r: string;
  s: string;
}

interface BundleBase64 {
  dg1: string;
  lds: string;
  signed_attrs: string;
  digest_algo: string;
  document_signature: SignatureECb64;
  cert_local_pubkey: PublicKeyECb64;
  cert_local_tbs: string;
  cert_local_tbs_digest_algo: string;
  cert_local_signature: SignatureECb64;
  cert_master_subject_key_id: string;
  cert_master_pubkey: PublicKeyECb64;
}

interface PublicKeyEC {
  x: bigint;
  y: bigint;
}

interface SignatureEC {
  r: bigint;
  s: bigint;
}

interface Bundle {
  dg1: Uint8Array;
  lds: Uint8Array;
  signed_attrs: Uint8Array;
  document_signature: SignatureEC;
  cert_local_pubkey: PublicKeyEC;
  cert_local_tbs: Uint8Array;
  cert_local_signature: SignatureEC;
  cert_master_subject_key_id: Uint8Array;
  cert_master_pubkey: PublicKeyEC;
}

function parsePubkeyECB64(pk: PublicKeyECb64): PublicKeyEC {
  if (pk.type !== "EC") {
    throw new Error("not EC pk");
  }
  if (pk.curve !== "secp256k1") {
    throw new Error("not secp256k1");
  }
  const x = BigInt("0x" + encodeHex(decodeBase64(pk.x)));
  const y = BigInt("0x" + encodeHex(decodeBase64(pk.y)));

  return { x, y };
}

function parseSignatureECB64(sig: SignatureECb64): SignatureEC {
  if (sig.type !== "EC") {
    throw new Error("not EC sig");
  }
  const r = BigInt("0x" + encodeHex(decodeBase64(sig.r)));
  const s = BigInt("0x" + encodeHex(decodeBase64(sig.s)));

  return { r, s };
}

function parseBundleB64(b: BundleBase64): Bundle {
  if (
    b.digest_algo !== "id-sha256" ||
    b.cert_local_tbs_digest_algo !== "id-sha256"
  ) {
    throw new Error("not sha256");
  }
  return {
    dg1: decodeBase64(b.dg1),
    lds: decodeBase64(b.lds),
    signed_attrs: decodeBase64(b.signed_attrs),
    document_signature: parseSignatureECB64(b.document_signature),
    cert_local_pubkey: parsePubkeyECB64(b.cert_local_pubkey),
    cert_local_tbs: decodeBase64(b.cert_local_tbs),
    cert_local_signature: parseSignatureECB64(b.cert_local_signature),
    cert_master_subject_key_id: decodeBase64(b.cert_master_subject_key_id),
    cert_master_pubkey: parsePubkeyECB64(b.cert_master_pubkey),
  };
}

export function assertSubarray(
  haystack: UInt8[],
  needle: UInt8[],
  sizeNeedle: number,
  offset: number,
  message?: string,
): void {
  for (let i = 0; i < sizeNeedle; i += 1) {
    haystack[offset + i].assertEquals(needle[i], message);
  }
}

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

class Secp256k1 extends createForeignCurve(
  Crypto.CurveParams.Secp256k1,
) {}
class EcdsaSecp256k1 extends createEcdsa(Secp256k1) {}

function hashToScalar(hash: Bytes) {
  const x2 = bytesToLimbBE(hash.bytes.slice(0, 10));
  const x1 = bytesToLimbBE(hash.bytes.slice(10, 21));
  const x0 = bytesToLimbBE(hash.bytes.slice(21, 32));

  return new Secp256k1.Scalar.AlmostReduced([x0, x1, x2]);
}

function bytesToLimbBE(bytes_: UInt8[]) {
  const bytes = bytes_.map((x) => x.value);
  const n = bytes.length;
  let limb = bytes[0];
  for (let i = 1; i < n; i++) {
    limb = limb.mul(1n << 8n).add(bytes[i]);
  }
  return limb.seal();
}

function assertSignedAttrsIsSignedByCert(
  signedAttrs: Uint8Array,
  pubkey: PublicKeyEC,
  signature: SignatureEC,
) {
  const digest = Hash.SHA2_256.hash(Bytes.from(signedAttrs));
  const aff = hashToScalar(digest);
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
  const aff = hashToScalar(digest);
  const pubkeyObj = new Secp256k1(master_pubkey);
  const signatureObj = new EcdsaSecp256k1(signature);
  const isValid = signatureObj.verifySignedHash(aff, pubkeyObj);
  isValid.assertTrue("cert signature validation failed");
}

if (import.meta.main) {
  const bundleText = Deno.readTextFileSync("files/bundle.frodo.json");
  const bundleB64: BundleBase64 = JSON.parse(bundleText);
  const bundle = parseBundleB64(bundleB64);
  // verified that its sha256 + secp256k1 all over.

  assertDG1inLDS(bundle.dg1, bundle.lds);
  assertLDSinSignedAttrs(bundle.lds, bundle.signed_attrs);
  assertSignedAttrsIsSignedByCert(
    bundle.signed_attrs,
    bundle.cert_local_pubkey,
    bundle.document_signature,
  );
  assertLocalIsSignedByMaster(
    bundle.cert_local_tbs,
    bundle.cert_master_pubkey,
    bundle.cert_local_signature,
  );
  // assert(false, "hey");

  console.log(bundle);
}
