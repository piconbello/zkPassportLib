import { sha256 } from "@noble/hashes/sha2";
import { DynamicBytes } from "./dynamic-bytes.ts";
import { DynamicSHA256 } from "./dynamic-sha256.ts";

import { assertEquals } from "jsr:@std/assert";

Deno.test("dynamic sha256 test", () => {
  const payload = new Uint8Array(200);
  payload[1] = 1;
  const expectedDigest = sha256(payload);
  const payloadDyn = DynamicBytes({ maxLength: 300 }).fromBytes(payload);
  const digest = DynamicSHA256.hash(payloadDyn);
  assertEquals(digest.toBytes(), expectedDigest);
});
