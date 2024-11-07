import { Hash, ZkProgram } from "o1js";
import { dg1OffsetInLDS, ZkTD3_PubInput_74 } from "./common.ts";
import {
  assertSubarray,
  DigestAlgo,
  LDS_DIGEST_OFFSET_IN_SIGNED_ATTRS,
  lengthDigest,
  lengthSignedAttrs,
} from "../common.ts";
import { assertEquals } from "jsr:@std/assert";
import { DynamicBytes } from "../primitives/dynamic-bytes.ts";
import { DynamicSHA256 } from "../primitives/dynamic-sha256.ts";

// A LDS size for digest-size 32 nad 16 datagroups present.
export const LDS_MAX_LENGTH = 648;
export class LDS extends DynamicBytes({ maxLength: LDS_MAX_LENGTH }) {}

export const DIGEST_ALGO: DigestAlgo = "sha256";
const DIGEST_SIZE = lengthDigest(DIGEST_ALGO);
const DG1_OFFSET = dg1OffsetInLDS(DIGEST_ALGO);

assertEquals(lengthSignedAttrs(DIGEST_ALGO), 74);

export const ZkTD3_sha256 = ZkProgram({
  name: "td3-sha256",
  publicInput: ZkTD3_PubInput_74,

  methods: {
    mrz2signedAttrs: {
      privateInputs: [LDS],

      // deno-lint-ignore require-await
      async method(inp: ZkTD3_PubInput_74, lds: LDS) {
        const dg1Digest = Hash.SHA2_256.hash(inp.dg1);
        lds.length.assertGreaterThan(DG1_OFFSET + DIGEST_SIZE);
        assertSubarray(
          lds.array,
          dg1Digest.bytes,
          DIGEST_SIZE,
          DG1_OFFSET,
          "dg1 in lds",
        );

        const ldsDigest = DynamicSHA256.hash(lds);
        assertSubarray(
          inp.signedAttrs.bytes,
          ldsDigest.bytes,
          DIGEST_SIZE,
          LDS_DIGEST_OFFSET_IN_SIGNED_ATTRS,
          "lds in signedAttrs",
        );
      },
    },
  },
});
