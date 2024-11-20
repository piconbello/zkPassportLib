import { secp256k1 } from "npm:@noble/curves/secp256k1";

import { MasterCert, PublicKeyEC } from "./parse.ts";

function randomPubkeyEC(): PublicKeyEC {
  const priv = secp256k1.utils.randomPrivateKey();
  const point = secp256k1.ProjectivePoint.fromPrivateKey(priv);
  return {
    type: "EC",
    curve: "secp256k1",
    x: point.x,
    y: point.y,
  };
}

export function randomMasterlist(
  n: number,
  includeCert: MasterCert,
): [MasterCert[], number] {
  const masterlist: MasterCert[] = Array(n).fill(null).map(() => ({
    pubkey: randomPubkeyEC(),
    subject_key_id: crypto.getRandomValues(new Uint8Array(20)),
  }));

  // Override one random position with includeCert
  const includeIndex = Math.floor(Math.random() * n);
  masterlist[includeIndex] = includeCert;

  return [masterlist, includeIndex];
}
