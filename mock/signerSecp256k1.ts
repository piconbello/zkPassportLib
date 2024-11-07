import { createEcdsa, createForeignCurve, Crypto } from "o1js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { encodeHex } from "@std/encoding/hex";

export class Secp256k1 extends createForeignCurve(
  Crypto.CurveParams.Secp256k1,
) {}
export class Ecdsa extends createEcdsa(Secp256k1) {}

export class SignerSecp256k1 {
  public privNative: Uint8Array;
  public pubNative: Uint8Array;
  public pubO1: Secp256k1;

  constructor() {
    this.privNative = secp256k1.utils.randomPrivateKey();
    this.pubNative = secp256k1.getPublicKey(this.privNative);

    const uncompressedPub = secp256k1.ProjectivePoint.fromHex(
      this.pubNative,
    ).toRawBytes(false);
    const x = BigInt("0x" + encodeHex(uncompressedPub.slice(1, 33)));
    const y = BigInt("0x" + encodeHex(uncompressedPub.slice(33)));
    this.pubO1 = new Secp256k1({
      x,
      y,
    });
  }

  sign(digest: Uint8Array): Ecdsa {
    const sig = secp256k1.sign(digest, this.privNative);

    return new Ecdsa({
      r: sig.r,
      s: sig.s,
    });
  }
}
