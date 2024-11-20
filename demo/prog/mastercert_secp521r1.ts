import { Field, Hash, Provable, Struct, ZkProgram } from "o1js";
import { MyWitness } from "../certificateRegistry.ts";

export class MasterCert_Secp521r1_Input extends Struct({
  root: Field,
  x: Provable.Array(Field, 5),
  y: Provable.Array(Field, 5),
}) {}

export const MasterCert_Secp521r1 = ZkProgram({
  name: "mastercert-secp256r1",
  publicInput: MasterCert_Secp521r1_Input,

  methods: {
    verifyKnownMastercert: {
      privateInputs: [MyWitness],

      // deno-lint-ignore require-await
      async method(inp: MasterCert_Secp521r1_Input, witness: MyWitness) {
        const leaf = Hash.Poseidon.hash([...inp.x, ...inp.y]);
        const calcRoot = witness.calculateRoot(leaf);
        calcRoot.assertEquals(inp.root);
      },
    },
  },
});
