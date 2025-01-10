import { ZkProgram, Field, UInt32, Provable, Bool, Poseidon, SelfProof} from 'o1js';
import { Bigint4096, EXP_BIT_COUNT, Field36, rsaVerify } from './rsa3.ts';
import { sha256Bigint, generateRsaParams, rsaSign } from './utils.ts';



let rsaZkProgram = ZkProgram({
  name: 'rsa-verify',
  publicOutput: Bigint4096,

  methods: {
    init: {
      privateInputs: [Bigint4096, Bigint4096, Bool],
      async method(
        signature: Bigint4096,
        modulus: Bigint4096,
        nextExponent: Bool,
      ) {
        Bigint4096.check(signature)
        Bigint4096.check(modulus)
        Bool.check(nextExponent)
        let publicOutput = Provable.if(
          nextExponent,
          signature,
          Bigint4096.from(1n)
        );
        return { publicOutput };
      }
    },

    step: {
      privateInputs: [SelfProof, Bigint4096, Bigint4096, Bool],
      async method(
        proof: SelfProof<undefined, Bigint4096>,
        signature: Bigint4096,
        modulus: Bigint4096,
        nextExponent: Bool,
      ) {
        proof.verify();
        Bigint4096.check(proof.publicOutput);
        Bigint4096.check(signature)
        Bigint4096.check(modulus)
        Bool.check(nextExponent)
        let publicOutput = modulus.modSquare(proof.publicOutput);
        publicOutput = modulus.modMul(publicOutput, Provable.if(
          nextExponent,
          signature,
          Bigint4096.from(1n)
        ));
        return { publicOutput };
      }
    },

    final: {
      privateInputs: [SelfProof, Bigint4096],
      async method(
        proof: SelfProof<undefined, Bigint4096>, 
        message: Bigint4096
      ) {
        proof.verify();
        Bigint4096.check(proof.publicOutput);
        Bigint4096.check(message);
        Provable.assertEqual(proof.publicOutput, message);
        return { publicOutput: Bigint4096.from(0n) };
      }
    }
  },
});

let { init, step, final } = await rsaZkProgram.analyzeMethods();

console.log(init.summary());
console.log(step.summary());
console.log(final.summary());

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
const exponent = Field.from(params.e);
const exponentList = exponent.toBits(EXP_BIT_COUNT);
console.timeEnd('generate RSA parameters and inputs (2048 bits)');

console.time('prove');
let { proof } = await rsaZkProgram.init(signature, modulus, exponentList[EXP_BIT_COUNT-1]);
for (let i = EXP_BIT_COUNT-2; i >= 0; i--) {
  const { proof: nextProof } = await rsaZkProgram.step(proof, signature, modulus, exponentList[i]);
  proof = nextProof;
}
const { proof: finalProof } = await rsaZkProgram.final(proof, message);
proof = finalProof;
console.timeEnd('prove');
console.log('proof', proof);
console.log('proofjson', proof.toJSON());

console.time('verify');
const verified = await rsaZkProgram.verify(proof);
console.timeEnd('verify');
console.log('verified:', verified);