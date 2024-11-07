import { DigestAlgo } from "../src/common.ts";

import {
  sha3_224,
  sha3_256,
  sha3_384,
  sha3_512,
  shake128,
  shake256,
} from "@noble/hashes/sha3";
import {
  sha256,
  sha384,
  sha512,
  sha512_224,
  sha512_256,
} from "@noble/hashes/sha2";

export function digestFunc(
  algo: DigestAlgo,
): (message: Uint8Array) => Uint8Array {
  switch (algo) {
    case "sha256":
      return sha256;
    case "sha3-256":
      return sha3_256;
    case "sha512-256":
      return sha512_256;
    case "shake256":
      return shake256;
    case "sha384":
      return sha384;
    case "sha3-384":
      return sha3_384;
    case "sha512":
      return sha512;
    case "sha3-512":
      return sha3_512;
    case "sha512-224":
      return sha512_224;
    case "sha3-224":
      return sha3_224;
    case "shake128":
      return shake128;
  }
}
