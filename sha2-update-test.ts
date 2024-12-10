/**
 * This example computes the SHA2 hash of a long string in multiple chunks, using recursion
 * and the `DynamicSHA2` `split()` / `update()` / `finalize()` API.
 */
import {
  Bytes,
  DynamicProof,
  FeatureFlags,
  Provable,
  SelfProof,
  Struct,
  VerificationKey,
  Void,
  ZkProgram,
} from "npm:o1js";
import {
  DynamicSHA2,
  DynamicString,
  Sha2FinalIteration,
  Sha2Iteration,
  Sha2IterationState,
} from "npm:mina-credentials/dynamic";

// function mapObject<
//   T extends Record<string, any>,
//   S extends Record<keyof T, any>,
// >(obj: T, fn: <K extends keyof T>(value: T[K], key: K) => S[K]): S {
//   let result = {} as S;
//   for (let key in obj) {
//     result[key] = fn(obj[key], key);
//   }
//   return result;
// }

const String = DynamicString({ maxLength: 850 });
const Bytes32 = Bytes(32);

/**
 * How many SHA2 blocks to process in each proof.
 */
const BLOCKS_PER_ITERATION = 7;

class State extends Sha2IterationState(256) {}
class Iteration extends Sha2Iteration(256, BLOCKS_PER_ITERATION) {}
class FinalIteration extends Sha2FinalIteration(256, BLOCKS_PER_ITERATION) {}

let sha2Update = ZkProgram({
  name: "sha2-update",
  publicOutput: State,

  methods: {
    empty: {
      privateInputs: [],
      async method() {
        return {
          publicOutput: State.initial(),
        };
      },
    },

    initial: {
      privateInputs: [Iteration],
      async method(iteration: Iteration) {
        let state = State.initial();
        let publicOutput = DynamicSHA2.update(state, iteration);
        return { publicOutput };
      },
    },

    recursive: {
      privateInputs: [SelfProof, Iteration],
      async method(proof: SelfProof<undefined, State>, iteration: Iteration) {
        proof.verify();
        let state = proof.publicOutput;
        let publicOutput = DynamicSHA2.update(state, iteration);
        return { publicOutput };
      },
    },
  },
});

class UpdateProof extends ZkProgram.Proof(sha2Update) {}
class Sha2_Output extends Struct({
  digest: Bytes32,
}) {}

let sha2Finalize = ZkProgram({
  name: "sha2-finalize",
  publicOutput: Sha2_Output,

  methods: {
    run: {
      privateInputs: [String, UpdateProof, FinalIteration],
      async method(
        string: DynamicString,
        proof: UpdateProof,
        iteration: FinalIteration,
      ) {
        // proof.verify();
        // let state = proof.publicOutput;
        const state = State.initial();
        // assert(false);
        let publicOutput = DynamicSHA2.finalize(state, iteration, string);
        return { publicOutput: new Sha2_Output({ digest: publicOutput }) };
      },
    },
  },
});

// console.log(mapObject(await sha2Update.analyzeMethods(), (m) => m.summary()));
// console.log(mapObject(await sha2Finalize.analyzeMethods(), (m) => m.summary()));

// split up string into chunks to be hashed

let longString = String.from("hello world!".repeat(Math.floor(12 / 12)));
console.log("string length", longString.toString().length);

let { iterations, final } = DynamicSHA2.split(
  256,
  BLOCKS_PER_ITERATION,
  longString,
);

console.log("number of iterations (including final):", iterations.length + 1);

console.time("compile");
await sha2Update.compile();
const vkFinal = (await sha2Finalize.compile()).verificationKey;
console.timeEnd("compile");

// let [first, ...rest] = iterations;

// console.time("proof (initial)");
// let { proof } = await sha2Update.initial(first!);
// console.timeEnd("proof (initial)");

// console.time(`proof (recursive ${rest.length}x)`);
// for (let iteration of rest) {
//   ({ proof } = await sha2Update.recursive(proof, iteration));
// }
// console.timeEnd(`proof (recursive ${rest.length}x)`);

// const proof = await UpdateProof.dummy(undefined, State.initial(), 1);
const proof = await sha2Update.empty();

console.time("proof (finalize)");
let { proof: finalProof } = await sha2Finalize.run(
  longString,
  proof.proof,
  final,
);
console.timeEnd("proof (finalize)");

console.log("public output:\n", finalProof.publicOutput.digest.toHex());

// compare with expected hash
console.log("expected hash:\n", DynamicSHA2.hash(256, longString).toHex());

export class DynProof extends DynamicProof<
  Void,
  Sha2_Output
> {
  static override publicInputType = Void;
  static override publicOutputType = Sha2_Output;
  static override maxProofsVerified = 1 as const;
  static override featureFlags = FeatureFlags.allMaybe;
}

const HashDynChecker = ZkProgram({
  name: "hash-dyn-checker-256",

  methods: {
    check: {
      privateInputs: [DynProof, VerificationKey],

      // deno-lint-ignore require-await
      async method(
        proof: DynProof,
        vk: VerificationKey,
      ) {
        proof.verify(vk);
      },
    },
  },
});

console.time("compile dyn");
await HashDynChecker.compile();
console.timeEnd("compile dyn");

const dynProof = DynProof.fromProof(finalProof);
console.time("proof (dyn)");
let { proof: dynProofProof } = await HashDynChecker.check(
  dynProof,
  vkFinal,
);
console.timeEnd("proof (dyn)");

const isValid = await HashDynChecker.verify(dynProofProof);
console.log("isValid", isValid);
