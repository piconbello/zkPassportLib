import { it, describe } from "jsr:@std/testing/bdd";
import {
  SHA512MiniWrapper,
  hashVerify,
  formatCheck,
} from './sha2_512mini.ts';
import { sampleDG1BigInt, sampleDG1HashBigInt } from "./utils.ts";

describe("SHA2_512MINI verification tests", () => {
  it("should accept a simple SHA2-512 hash", () => {
    // test vector SHA512("")
    // length is 0, therefore the input is bigint 1<<1023n (1 followed by 1023 zeros)
    const input = SHA512MiniWrapper.from(1n << 1023n, 0xcf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3en);
    hashVerify(input);
  });

  it("should accept a dg1 with its hash", () => {
    const input = SHA512MiniWrapper.from(
      sampleDG1BigInt,
      sampleDG1HashBigInt
    );
    hashVerify(input);
    formatCheck(input);
  });
})