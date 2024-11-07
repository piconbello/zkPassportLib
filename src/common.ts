import { Bytes, UInt8 } from "o1js";

/*
The offset of 42 bytes comes from:
  Part 1: Outer SET tag + length
  [30 15] = 2 bytes

  Part 2: First attribute (content_type)
  - SEQUENCE tag + length [30 15] = 2 bytes
  - type OID tag + length [06 09] = 2 bytes
  - type OID value [2a864886f70d010903] = 9 bytes
  - values SET tag + length [31 08] = 2 bytes
  - inner OID tag + length [06 06] = 2 bytes
  - inner OID value [678108010101] = 6 bytes
  Subtotal for first attribute = 23 bytes

  Part 3: Second attribute (message_digest) header
  - SEQUENCE tag + length [30 2f] = 2 bytes
  - type OID tag + length [06 09] = 2 bytes
  - type OID value [2a864886f70d010904] = 9 bytes
  - values SET tag + length [31 22] = 2 bytes
  - OCTET STRING tag + length [04 20] = 2 bytes
  Subtotal for second attribute header = 17 bytes

  Total: 2 + 23 + 17 = 42 bytes

  According to the ICAO specification (Doc 9303 Part 10) and ASN.1 structure,
  this offset of 42 bytes remains constant regardless of the hash algorithm used. This is because:

  1. The first part (Outer SET) is always 2 bytes
  2. The first attribute (content_type) structure is always 23 bytes
  3. The second attribute (message_digest) header structure is always 17 bytes

  What changes based on the hash algorithm is:
  1. The length of the hash value itself (which comes after the 42-byte offset)
  2. The OID that identifies the hash algorithm (which is part of the SignerInfo structure, not the signed attributes)
*/
export const LDS_DIGEST_OFFSET_IN_SIGNED_ATTRS = 42;

export type DigestAlgo =
  | "sha256"
  | "sha384"
  | "sha512"
  | "sha512-224"
  | "sha512-256"
  | "sha3-224"
  | "sha3-256"
  | "sha3-384"
  | "sha3-512"
  | "shake128"
  | "shake256";

export function lengthOID(algo: DigestAlgo): number {
  /*
  SHA2 family OID lengths:
  - SHA-256 (2.16.840.1.101.3.4.2.1): 19 bytes
  - SHA-384 (2.16.840.1.101.3.4.2.2): 19 bytes
  - SHA-512 (2.16.840.1.101.3.4.2.3): 19 bytes
  - SHA-512/224 (2.16.840.1.101.3.4.2.5): 19 bytes
  - SHA-512/256 (2.16.840.1.101.3.4.2.6): 19 bytes

  SHA3 family OID lengths:
  - SHA3-224 (2.16.840.1.101.3.4.2.7): 19 bytes
  - SHA3-256 (2.16.840.1.101.3.4.2.8): 19 bytes
  - SHA3-384 (2.16.840.1.101.3.4.2.9): 19 bytes
  - SHA3-512 (2.16.840.1.101.3.4.2.10): 20 bytes
  - SHAKE128 (2.16.840.1.101.3.4.2.11): 20 bytes
  - SHAKE256 (2.16.840.1.101.3.4.2.12): 20 bytes
  */
  switch (algo) {
    case "sha256":
    case "sha384":
    case "sha512":
    case "sha512-224":
    case "sha512-256":
    case "sha3-224":
    case "sha3-256":
    case "sha3-384":
      return 19;
    case "sha3-512":
    case "shake128":
    case "shake256":
      return 20;
  }
}

export function lengthDigest(algo: DigestAlgo): number {
  switch (algo) {
    case "sha256":
    case "sha3-256":
    case "sha512-256":
    case "shake256":
      return 32; // 256 bits = 32 bytes
    case "sha384":
    case "sha3-384":
      return 48; // 384 bits = 48 bytes
    case "sha512":
    case "sha3-512":
      return 64; // 512 bits = 64 bytes
    case "sha512-224":
    case "sha3-224":
    case "shake128":
      return 28; // 224 bits = 28 bytes
  }
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

export class Bytes32 extends Bytes(32) {}
export class Bytes48 extends Bytes(48) {}
export class Bytes64 extends Bytes(64) {}
export class Bytes28 extends Bytes(28) {}

export function getDigestBytes(algo: DigestAlgo) {
  switch (algo) {
    case "sha256":
    case "sha3-256":
    case "sha512-256":
    case "shake256":
      return Bytes32; // 256 bits = 32 bytes
    case "sha384":
    case "sha3-384":
      return Bytes48; // 384 bits = 48 bytes
    case "sha512":
    case "sha3-512":
      return Bytes64; // 512 bits = 64 bytes
    case "sha512-224":
    case "sha3-224":
    case "shake128":
      return Bytes28; // 224 bits = 28 bytes
  }
}

export function lengthSignedAttrs(algo: DigestAlgo): number {
  return 42 + lengthDigest(algo); // 42 bytes + length of the hash
}

export class Bytes74 extends Bytes(74) {}
export class Bytes90 extends Bytes(90) {}
export class Bytes106 extends Bytes(106) {}
export class Bytes70 extends Bytes(70) {}

export function getSignedAttrsBytes(algo: DigestAlgo) {
  switch (algo) {
    case "sha256":
    case "sha3-256":
    case "sha512-256":
    case "shake256":
      return Bytes74;
    case "sha384":
    case "sha3-384":
      return Bytes90;
    case "sha512":
    case "sha3-512":
      return Bytes106;
    case "sha512-224":
    case "sha3-224":
    case "shake128":
      return Bytes70;
  }
}

export function getDigestAlgoOID(algo: DigestAlgo): string {
  switch (algo) {
    case "sha256":
      return "2.16.840.1.101.3.4.2.1";
    case "sha384":
      return "2.16.840.1.101.3.4.2.2";
    case "sha512":
      return "2.16.840.1.101.3.4.2.3";
    case "sha512-224":
      return "2.16.840.1.101.3.4.2.5";
    case "sha512-256":
      return "2.16.840.1.101.3.4.2.6";
    case "sha3-224":
      return "2.16.840.1.101.3.4.2.7";
    case "sha3-256":
      return "2.16.840.1.101.3.4.2.8";
    case "sha3-384":
      return "2.16.840.1.101.3.4.2.9";
    case "sha3-512":
      return "2.16.840.1.101.3.4.2.10";
    case "shake128":
      return "2.16.840.1.101.3.4.2.11";
    case "shake256":
      return "2.16.840.1.101.3.4.2.12";
  }
}

export type DataGroupNumber =
  | 1
  | 2
  | 3
  | 4
  | 5
  | 6
  | 7
  | 8
  | 9
  | 10
  | 11
  | 12
  | 13
  | 14
  | 15
  | 16;
