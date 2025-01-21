import { ZkProgram, Bytes, Provable, UInt8 } from 'o1js';
import { SHA2 } from '../primitives/sha256.ts';
import { sampleDG1Bytes, sha512Bigint, makeChunkFromDG1Bytes, DG1BytesFromBase64, sampleDG1HashBigInt } from './utils.ts';
import { unpackBytes } from "../primitives/gadgets.ts";

class Bytes93 extends Bytes(93) {}
class Bytes64 extends Bytes(64) {}

function makeBytes(num: bigint, len: number): UInt8[] {
  const bytes = [];
  for (let i = 0; i < len; i++) {
    bytes.push(UInt8.from(num & 0xffn));
    num >>= 8n;
  }
  bytes.reverse();
  return bytes;
}

let sha2512ZkProgram = ZkProgram({
  name: 'sha2-verify',

  methods: {
    verifySha2512: {
      privateInputs: [Bytes93, Bytes64],

      async method(
        data: Bytes93,
        hash: Bytes64,
      ) {
        const hashed = SHA2.hash(512, data);
        // Provable.log('hashed length', hashed.length);
        for (let i = 0; i < 64; i++) {
          // Provable.log('byte', i, hashed.bytes[i], hash.bytes[i]);
          hashed.bytes[i].assertEquals(hash.bytes[i]);
        }
      }
    }
  }
});

let { verifySha2512 } = await sha2512ZkProgram.analyzeMethods();

console.log(verifySha2512.summary());

console.time('compile');
const forceRecompileEnabled = false;
await sha2512ZkProgram.compile({ forceRecompile: forceRecompileEnabled });
console.timeEnd('compile');

console.time('generate DG1 parameters and inputs');
const input1 = Bytes93.from(sampleDG1Bytes);
const input2 = Bytes64.from(makeBytes(sampleDG1HashBigInt, 64));
console.timeEnd('generate DG1 parameters and inputs');

console.time('prove DG1');
let { proof } = await sha2512ZkProgram.verifySha2512(input1, input2);
console.timeEnd('prove DG1');

console.time('verify DG1');
await sha2512ZkProgram.verify(proof);
console.timeEnd('verify DG1');
