import {
  Bytes,
  createEcdsa,
  createForeignCurve,
  Crypto,
  Field,
  UInt32,
  UInt8,
} from "npm:o1js";
import { DynamicBytes } from "mina-credentials/dynamic";

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

export class Secp256k1 extends createForeignCurve(
  Crypto.CurveParams.Secp256k1,
) {}
export class EcdsaSecp256k1 extends createEcdsa(Secp256k1) {}
export class Bytes65 extends Bytes(65) {}
export class CertTBS extends DynamicBytes({ maxLength: 800 }) {}

export function bytes32ToScalar(slice32: UInt8[]) {
  const x2 = bytesToLimbBE(slice32.slice(0, 10));
  const x1 = bytesToLimbBE(slice32.slice(10, 21));
  const x0 = bytesToLimbBE(slice32.slice(21, 32));

  return new Secp256k1.Scalar.AlmostReduced([x0, x1, x2]);
}

export function bytesToLimbBE(bytes_: UInt8[]) {
  const bytes = bytes_.map((x) => x.value);
  const n = bytes.length;
  let limb = bytes[0];
  for (let i = 1; i < n; i++) {
    limb = limb.mul(1n << 8n).add(bytes[i]);
  }
  return limb.seal();
}

export function bigintToLimbs(big: bigint): Field[] {
  const mask = (1n << 116n) - 1n; // mask for 116-bit limbs
  const limbs: Field[] = [];

  while (big > 0n) {
    limbs.push(Field(big & mask)); // Get lowest 116 bits
    big >>= 116n; // Shift right by 116 bits
  }

  return limbs;
}

export function parseECpubkey256Uncompressed(
  sec1: Bytes65,
) {
  // First byte is header (should be 4 for uncompressed SEC1)
  const bytes = sec1.bytes;
  const head = bytes[0];
  head.assertEquals(UInt8.from(4));

  // Parse X coordinate (32 bytes split into 3 Fields)
  const x: [Field, Field, Field] = [Field(0), Field(0), Field(0)];
  // x[2] (highest limb): first 10 bytes
  for (let i = 1; i < 11; i++) {
    x[2] = x[2].mul(1n << 8n).add(bytes[i].value);
  }
  // x[1] (middle limb): next 11 bytes
  for (let i = 11; i < 22; i++) {
    x[1] = x[1].mul(1n << 8n).add(bytes[i].value);
  }
  // x[0] (lowest limb): last 11 bytes
  for (let i = 22; i < 33; i++) {
    x[0] = x[0].mul(1n << 8n).add(bytes[i].value);
  }

  // Parse Y coordinate (32 bytes split into 3 Fields)
  const y: [Field, Field, Field] = [Field(0), Field(0), Field(0)];
  // y[2] (highest limb): first 10 bytes
  for (let i = 33; i < 43; i++) {
    y[2] = y[2].mul(1n << 8n).add(bytes[i].value);
  }
  // y[1] (middle limb): next 11 bytes
  for (let i = 43; i < 54; i++) {
    y[1] = y[1].mul(1n << 8n).add(bytes[i].value);
  }
  // y[0] (lowest limb): last 11 bytes
  for (let i = 54; i < 65; i++) {
    y[0] = y[0].mul(1n << 8n).add(bytes[i].value);
  }

  return { x, y };
}

export function assertECpubkey256Uncompressed(
  sec1: Bytes65,
  x: [Field, Field, Field],
  y: [Field, Field, Field],
) {
  const parsed = parseECpubkey256Uncompressed(sec1);
  x[0].assertEquals(parsed.x[0]);
  x[1].assertEquals(parsed.x[1]);
  x[2].assertEquals(parsed.x[2]);
  y[0].assertEquals(parsed.y[0]);
  y[1].assertEquals(parsed.y[1]);
  y[2].assertEquals(parsed.y[2]);
}

export function assertSubarrayDynamic(
  haystack: DynamicBytes,
  needle: Bytes,
  offset: UInt32,
) {
  haystack.assertIndexInRange(offset.add(needle.length));

  for (let i = 0; i < needle.length; i += 1) {
    haystack
      .getOrUnconstrained(offset.value.add(i))
      .assertEquals(needle.bytes[i]);
  }
}
