import { Field, Struct, UInt32, ZkProgram } from "o1js";
import {
  assertECpubkey256Uncompressed,
  assertSubarrayDynamic,
  Bytes65,
  CertTBS,
} from "../utilsO1.ts";

export class PubkeyInCert256_Input extends Struct({
  cert: CertTBS,
  x: [Field, Field, Field],
  y: [Field, Field, Field],
}) {}

export const PubkeyInCert256 = ZkProgram({
  name: "pubkey-cert-256",
  publicInput: PubkeyInCert256_Input,

  methods: {
    associatePubkeyWithCert: {
      privateInputs: [Bytes65, UInt32],
      // deno-lint-ignore require-await
      async method(inp: PubkeyInCert256_Input, sec1: Bytes65, offset: UInt32) {
        assertSubarrayDynamic(
          inp.cert,
          sec1,
          offset,
        );
        assertECpubkey256Uncompressed(
          sec1,
          [inp.x[0], inp.x[1], inp.x[2]],
          [inp.y[0], inp.y[1], inp.y[2]],
        );
      },
    },
  },
});
