import {
  Bytes,
  DynamicProof,
  FeatureFlags,
  SelfProof,
  Struct,
  Void,
  ZkProgram,
} from "o1js";
import {
  DynamicBytes,
  DynamicSHA2,
  Sha2FinalIteration,
  Sha2Iteration,
  Sha2IterationState,
} from "mina-credentials/dynamic";

export class Bytes32 extends Bytes(32) {}

const BLOCKS_PER_ITERATION = 7;
class HashState extends Sha2IterationState(256) {}
class HashIteration extends Sha2Iteration(256, BLOCKS_PER_ITERATION) {}
class HashFinalIteration
  extends Sha2FinalIteration(256, BLOCKS_PER_ITERATION) {}

const SIZE_256_MAX = 1000;
export class INPUT_256 extends DynamicBytes({ maxLength: SIZE_256_MAX }) {}
export class Hash_Sha256_Input extends Struct({
  payload: INPUT_256,
}) {}
export class Hash_Sha256_Output extends Struct({
  digest: Bytes32,
}) {}

export const Hash_Sha256_Step = ZkProgram({
  name: "hash-sha256-step",
  publicOutput: HashState,

  methods: {
    empty: {
      privateInputs: [],
      // deno-lint-ignore require-await
      async method() {
        return { publicOutput: HashState.initial() };
      },
    },

    // init: {
    //   privateInputs: [HashIteration],
    //   // deno-lint-ignore require-await
    //   async method(iteration: HashIteration) {
    //     const state = HashState.initial();
    //     const publicOutput = DynamicSHA2.update(state, iteration);
    //     return { publicOutput };
    //   },
    // },

    update: {
      privateInputs: [SelfProof, HashIteration],
      // deno-lint-ignore require-await
      async method(
        proof: SelfProof<undefined, HashState>,
        iteration: HashIteration,
      ) {
        proof.verify();
        const state = proof.publicOutput;
        const publicOutput = DynamicSHA2.update(state, iteration);
        return { publicOutput };
      },
    },
  },
});

class UpdateProof extends ZkProgram.Proof(Hash_Sha256_Step) {}

export const Hash_Sha256_Final = ZkProgram({
  name: "hash-sha256-final",
  // publicInput: Hash_Sha256_Input,
  publicOutput: Hash_Sha256_Output,

  methods: {
    finalize: {
      privateInputs: [
        Hash_Sha256_Input,
        UpdateProof,
        HashFinalIteration,
      ],

      // deno-lint-ignore require-await
      async method(
        inp: Hash_Sha256_Input,
        proof: UpdateProof,
        finalIteration: HashFinalIteration,
      ) {
        const digest = DynamicSHA2.finalize(
          proof.publicOutput,
          finalIteration,
          inp.payload,
        );

        return {
          publicOutput: new Hash_Sha256_Output({ digest }),
        };
      },
    },
  },
});

// const ff = await FeatureFlags.fromZkProgram(Hash_Sha256_Final);

export class DynProof_Hash_Sha256 extends DynamicProof<
  // Hash_Sha256_Input,
  Void,
  Hash_Sha256_Output
> {
  static override publicInputType = Void;
  static override publicOutputType = Hash_Sha256_Output;
  static override maxProofsVerified = 1 as const;
  static override featureFlags = FeatureFlags.allMaybe;
}

export async function compile_hash_lds_256(
  status_callback: (status: string) => void = () => {},
) {
  await Hash_Sha256_Step.compile();
  status_callback("compiled step");
  const final = await Hash_Sha256_Final.compile();
  status_callback("compiled final");
  return final.verificationKey;
}

export async function prove_hash_lds_256(
  input: Hash_Sha256_Input,
  status_callback: (status: string) => void = () => {},
) {
  const { iterations, final } = DynamicSHA2.split(
    256,
    BLOCKS_PER_ITERATION,
    input.payload,
  );

  let updateProof: UpdateProof = (await Hash_Sha256_Step.empty()).proof;
  status_callback("proved empty");

  for (const [index, iter] of iterations.entries()) {
    const proof = await Hash_Sha256_Step.update(updateProof, iter);
    updateProof = proof.proof;
    status_callback(`proved step ${index + 1}`);
  }

  const proofFinal = await Hash_Sha256_Final.finalize(
    input,
    updateProof,
    final,
  );
  status_callback("proved final");

  return proofFinal.proof;
}
