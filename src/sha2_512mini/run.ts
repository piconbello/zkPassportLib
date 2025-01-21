import { ZkProgram } from 'o1js';
import { SHA512MiniWrapper, hashVerify, formatCheck } from './sha2_512mini.ts';
import { sampleDG1BigInt, sha512Bigint, makeChunkFromDG1Bytes, DG1BytesFromBase64, sampleDG1HashBigInt } from './utils.ts';

let sha2mini512ZkProgram = ZkProgram({
  name: 'sha2-mini-verify',

  methods: {
    verifySha2mini512: {
      privateInputs: [SHA512MiniWrapper],

      async method(
        dg1WithHash: SHA512MiniWrapper
      ) {
        hashVerify(dg1WithHash);
        formatCheck(dg1WithHash);
      }
    }
  }
});

let { verifySha2mini512 } = await sha2mini512ZkProgram.analyzeMethods();

console.log(verifySha2mini512.summary());

console.time('compile');
const forceRecompileEnabled = false;
await sha2mini512ZkProgram.compile({ forceRecompile: forceRecompileEnabled });
console.timeEnd('compile');

console.time('generate DG1 parameters and inputs');
const input2 = SHA512MiniWrapper.from(sampleDG1BigInt, sampleDG1HashBigInt);
console.timeEnd('generate DG1 parameters and inputs');

console.time('prove DG1');
let { proof } = await sha2mini512ZkProgram.verifySha2mini512(input2);
console.timeEnd('prove DG1');

console.time('verify DG1');
await sha2mini512ZkProgram.verify(proof);
console.timeEnd('verify DG1');
