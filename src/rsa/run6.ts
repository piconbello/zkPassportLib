import { ZkProgram, Field, UInt32, Provable, Bool, Poseidon, SelfProof} from 'o1js';
import { Bigint6144, EXP_BIT_COUNT, Field53, rsaVerify } from './rsa6.ts';
import { sha256Bigint, generateRsaParams, rsaSign } from './utils.ts';



let rsaZkProgram = ZkProgram({
  name: 'rsa-verify',
  publicOutput: Bigint6144,

  methods: {
    init: {
      privateInputs: [Bigint6144, Bigint6144, Bool],
      async method(
        signature: Bigint6144,
        modulus: Bigint6144,
        nextExponent: Bool,
      ) {
        Bigint6144.check(signature)
        Bigint6144.check(modulus)
        Bool.check(nextExponent)
        let publicOutput = Provable.if(
          nextExponent,
          signature,
          Bigint6144.from(1n)
        );
        return { publicOutput };
      }
    },

    step: {
      privateInputs: [SelfProof, Bigint6144, Bigint6144, Bool],
      async method(
        proof: SelfProof<undefined, Bigint6144>,
        signature: Bigint6144,
        modulus: Bigint6144,
        nextExponent: Bool,
      ) {
        proof.verify();
        Bigint6144.check(proof.publicOutput);
        Bigint6144.check(signature)
        Bigint6144.check(modulus)
        Bool.check(nextExponent)
        let publicOutput = modulus.modSquare(proof.publicOutput);
        publicOutput = modulus.modMul(publicOutput, Provable.if(
          nextExponent,
          signature,
          Bigint6144.from(1n)
        ));
        return { publicOutput };
      }
    },

    final: {
      privateInputs: [SelfProof, Bigint6144],
      async method(
        proof: SelfProof<undefined, Bigint6144>, 
        message: Bigint6144
      ) {
        proof.verify();
        Bigint6144.check(proof.publicOutput);
        Bigint6144.check(message);
        Provable.assertEqual(proof.publicOutput, message);
        return { publicOutput: Bigint6144.from(0n) };
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

console.time('generate RSA parameters and inputs (6144 bits)');
const input = await sha256Bigint('How are you!');
const params = generateRsaParams(6144);
const message = Bigint6144.from(input);
const signature = Bigint6144.from(rsaSign(input, params.d, params.n));
const modulus = Bigint6144.from(params.n);
const exponent = Field.from(params.e);
const exponentList = exponent.toBits(EXP_BIT_COUNT);
console.timeEnd('generate RSA parameters and inputs (6144 bits)');

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