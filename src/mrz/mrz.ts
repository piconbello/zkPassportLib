import { ZkProgram, Field, Bytes, Poseidon, Provable } from 'o1js';

class Bytes88 extends Bytes(88) {}
class Bytes1024 extends Bytes(1024) {}

// LET'S DESIGN QUERY AS FOLLOWS:
// 

const mrzHeader = new Uint8Array([30, 45, 2, 1]);

const MrzZkProgram = ZkProgram({
  name: 'mrz-verify',
  publicOutput: Field, // poseidon hash of LDS
  publicInput: Field, // query to verify

  methods: {
    verify: {
      privateInputs: [
        Bytes88, // MRZ
        Bytes1024, // LDS
      ],
      async method(
        mrz: Bytes88,
        lds: Bytes1024,
      ) {
        let offset = Provable.witness(
          Struct({ mrz: Bytes88, lds: Bytes1024 }),
          () => {
            let mrzBytes = mrz.toBytes();
            let ldsBytes = lds.toBytes();
            let offset = 0;
            for (let i = 0; i < ldsBytes.length; ++i) {

            }
          }
        )
        const ldsFields = lds.toFields();
        ldsFields[offset].assertEquals(mrzHeader[0]);
        ldsFields[offset + 1].assertEquals(mrzHeader[1]);
        ldsFields[offset + 2].assertEquals(mrzHeader[2]);
        ldsFields[offset + 3].assertEquals(mrzHeader[3]);
        // TODO: Verify MRZ against LDS using a cryptographic library
        // Return the poseidon hash of LDS as the public output
        for (let i = 0; i < 88; ++i) {

        }

        return Poseidon.hash(lds.toFields());
      )
    }
  }


})