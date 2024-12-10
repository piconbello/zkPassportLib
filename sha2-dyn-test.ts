import {
  Bytes,
  DynamicProof,
  FeatureFlags,
  Struct,
  Undefined,
  VerificationKey,
  Void,
  ZkProgram,
} from "npm:o1js";
import {
  DynamicBytes,
  DynamicSHA2,
  DynamicString,
  Sha2FinalIteration,
  Sha2IterationState,
} from "npm:mina-credentials/dynamic";

console.log("Starting test :thumbsup:");

class Bytes32 extends Bytes(32) {}
class Payload extends DynamicString({ maxLength: 100 }) {}
class Sha2_Input extends Struct({
  payload: Payload,
}) {}
class Sha2_Output extends Struct({
  digest: Bytes32,
}) {}
class HashState extends Sha2IterationState(256) {}
const BLOCKS_PER_ITERATION = 7;
class HashFinalIteration
  extends Sha2FinalIteration(256, BLOCKS_PER_ITERATION) {}

// const Sha2PrivUpdate = ZkProgram({
//   name: "sha2-priv-update",
//   publicOutput: HashState,

//   methods: {
//     empty: {
//       privateInputs: [],
//       // deno-lint-ignore require-await
//       async method() {
//         return {
//           publicOutput: HashState.initial(),
//         };
//       },
//     },
//   },
// });

const Sha2Priv = ZkProgram({
  name: "privinput",
  publicOutput: Sha2_Output,

  methods: {
    finalize: {
      privateInputs: [Payload, HashFinalIteration],
      // deno-lint-ignore require-await
      async method(
        payload: Payload,
        finalIter: HashFinalIteration,
      ) {
        const initState = HashState.initial();
        const digest = DynamicSHA2.finalize(initState, finalIter, payload);
        return { publicOutput: new Sha2_Output({ digest }) };
      },
    },
  },
});

const privFF = await FeatureFlags.fromZkProgram(
  Sha2Priv,
);

export class DynPrivProof extends DynamicProof<
  Void,
  Sha2_Output
> {
  static override publicInputType = Void;
  static override publicOutputType = Sha2_Output;
  static override maxProofsVerified = 0 as const;
  static override featureFlags = privFF;
}

const DynCheckerPriv = ZkProgram({
  name: "privchecker",
  methods: {
    check: {
      privateInputs: [
        DynPrivProof,
        VerificationKey,
      ],
      // deno-lint-ignore require-await
      async method(proof, vk) {
        proof.verify(vk);
      },
    },
  },
});

const Sha2Pub = ZkProgram({
  name: "pubinput",
  publicInput: Sha2_Input,
  publicOutput: Sha2_Output,

  methods: {
    finalize: {
      privateInputs: [HashFinalIteration],
      // deno-lint-ignore require-await
      async method(
        inp: Sha2_Input,
        finalIter: HashFinalIteration,
      ) {
        const initState = HashState.initial();
        const digest = DynamicSHA2.finalize(initState, finalIter, inp.payload);
        return { publicOutput: new Sha2_Output({ digest }) };
      },
    },
  },
});

const pubFF = await FeatureFlags.fromZkProgram(
  Sha2Pub,
);

export class DynPubProof extends DynamicProof<
  Sha2_Input,
  Sha2_Output
> {
  static override publicInputType = Sha2_Input;
  static override publicOutputType = Sha2_Output;
  static override maxProofsVerified = 0 as const;
  static override featureFlags = pubFF;
}

const DynCheckerPub = ZkProgram({
  name: "pubchecker",
  methods: {
    check: {
      privateInputs: [
        DynPubProof,
        VerificationKey,
      ],
      // deno-lint-ignore require-await
      async method(proof, vk) {
        proof.verify(vk);
      },
    },
  },
});

///////////////

const payload = Payload.from("123");
const { iterations, final: finalIter } = DynamicSHA2.split(
  256,
  BLOCKS_PER_ITERATION,
  payload,
);
console.log(iterations.length);

console.time("compile priv");
const vkPriv = (await Sha2Priv.compile()).verificationKey;
console.timeEnd("compile priv");

console.time("prove priv");
const proofPriv = await Sha2Priv.finalize(payload, finalIter);
console.timeEnd("prove priv");

console.time("compile priv dyn");
await DynCheckerPriv.compile();
console.timeEnd("compile priv dyn");

console.time("prove priv dyn");
const dynamizedPriv = DynPrivProof.fromProof(proofPriv.proof);
const proofPrivDyn = await DynCheckerPriv.check(
  dynamizedPriv,
  vkPriv,
);
console.timeEnd("prove priv dyn");

console.time("verify priv dyn");
const isValid = await DynCheckerPriv.verify(proofPrivDyn.proof);
console.log("priv dyn validation:", isValid);
console.timeEnd("verify priv dyn");

/// now public
console.time("compile pub");
const vkPub = (await Sha2Pub.compile()).verificationKey;
console.timeEnd("compile pub");

console.time("prove pub");
const proofPub = await Sha2Pub.finalize(new Sha2_Input({ payload }), finalIter);
console.timeEnd("prove pub");

console.time("compile pub dyn");
await DynCheckerPub.compile();
console.timeEnd("compile pub dyn");

console.time("prove pub dyn");
const dynamizedPub = DynPubProof.fromProof(proofPub.proof);
const proofPubDyn = await DynCheckerPub.check(
  dynamizedPub,
  vkPub,
);
console.timeEnd("prove pub dyn");

console.time("verify pub dyn");
const isValidPub = await DynCheckerPub.verify(proofPubDyn.proof);
console.log("pub dyn validation:", isValidPub);
console.timeEnd("verify pub dyn");
