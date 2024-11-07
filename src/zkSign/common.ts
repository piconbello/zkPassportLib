import {
  Bytes,
  createEcdsa,
  createForeignCurve,
  Crypto,
  FeatureFlags,
  UInt8,
} from "o1js";
import { DynamicProof, Struct, Void } from "o1js";
import { Bytes74 } from "../common.ts";

export class Secp256k1 extends createForeignCurve(
  Crypto.CurveParams.Secp256k1,
) {}
export class EcdsaSecp256k1 extends createEcdsa(Secp256k1) {}

export function hashToScalar(hash: Bytes) {
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

export class ZkSign_PubInput_74_k1 extends Struct({
  payload: Bytes74,
  publicKey: Secp256k1,
  signature: EcdsaSecp256k1,
}) {}

export class DynProofZkSign74_k1
  extends DynamicProof<ZkSign_PubInput_74_k1, Void> {
  static override publicInputType = ZkSign_PubInput_74_k1;
  static override publicOutputType = Void;
  static override maxProofsVerified = 0 as const;
  static override featureFlags = FeatureFlags.allMaybe;
}
