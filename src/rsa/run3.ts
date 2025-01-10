import { ZkProgram, Field, UInt32 } from 'o1js';
import { Bigint4096, rsaVerify } from './rsa3.ts';
import { sha256Bigint, generateRsaParams, rsaSign } from './utils.ts';

let rsaZkProgram = ZkProgram({
  name: 'rsa-verify',

  methods: {
    verifyRsa: {
      privateInputs: [Bigint4096, Bigint4096, Bigint4096, UInt32],

      async method(
        message: Bigint4096,
        signature: Bigint4096,
        modulus: Bigint4096,
        publicExponent: UInt32,
      ) {
        rsaVerify(message, signature, modulus, publicExponent);
      },
    },
  },
});

let { verifyRsa } = await rsaZkProgram.analyzeMethods();

console.log(verifyRsa.summary());

console.time('compile');
const forceRecompileEnabled = false;
await rsaZkProgram.compile({ forceRecompile: forceRecompileEnabled });
console.timeEnd('compile');

console.time('generate RSA parameters and inputs (2048 bits)');
const input = await sha256Bigint('How are you!');
const params = generateRsaParams(4096);
const message = Bigint4096.from(input);
const signature = Bigint4096.from(rsaSign(input, params.d, params.n));
const modulus = Bigint4096.from(params.n);
const exponent = UInt32.from(params.e);
console.timeEnd('generate RSA parameters and inputs (2048 bits)');

console.time('prove');
let { proof } = await rsaZkProgram.verifyRsa(message, signature, modulus, exponent);
console.timeEnd('prove');

console.time('verify');
await rsaZkProgram.verify(proof);
console.timeEnd('verify');