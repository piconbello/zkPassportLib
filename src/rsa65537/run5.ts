import { ZkProgram } from 'o1js';
import { Bigint6144, rsaVerify65537 } from './rsa5.ts';
import { sha256Bigint, generateRsaParams, rsaSign } from './utils.ts';

let rsaZkProgram = ZkProgram({
  name: 'rsa-verify',

  methods: {
    verifyRsa65537: {
      privateInputs: [Bigint6144, Bigint6144, Bigint6144],

      async method(
        message: Bigint6144,
        signature: Bigint6144,
        modulus: Bigint6144
      ) {
        rsaVerify65537(message, signature, modulus);
      },
    },
  },
});

let { verifyRsa65537 } = await rsaZkProgram.analyzeMethods();

console.log(verifyRsa65537.summary());

console.time('compile');
const forceRecompileEnabled = false;
await rsaZkProgram.compile({ forceRecompile: forceRecompileEnabled });
console.timeEnd('compile');

console.time('generate RSA parameters and inputs (6144 bits)');
const input = await sha256Bigint('How are you!');
const params = generateRsaParams(6144);
const message = Bigint6144.from(input);
const signature = Bigint6144.from(rsaSign(input, params.d, params.n));
const modulus = Bigint6144.from(params.n);
console.timeEnd('generate RSA parameters and inputs (6144 bits)');

console.time('prove');
let { proof } = await rsaZkProgram.verifyRsa65537(message, signature, modulus);
console.timeEnd('prove');

console.time('verify');
await rsaZkProgram.verify(proof);
console.timeEnd('verify');