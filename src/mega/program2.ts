import { SelfProof, Field, ZkProgram, verify, Bytes, Provable, UInt32, Struct } from 'o1js';
import { DynamicBytes, DynamicSHA2, hashDynamic } from 'mina-credentials/dynamic';
import { SHA2 } from "../primitives/sha256.ts";

class DG1Bytes extends Bytes(93) {}

class LDSBytes extends DynamicBytes({ maxLength: 1200 }) {}

class Digest64 extends DynamicBytes({ maxLength: 64 }) {}

// function findDataGroupDigestWithinLDS(ldsRaw: LDSBytes, dgNumber: number): Digest64 {
//   const { dgDigest, dgDigestStart } = Provable.witness(
//     Struct({ dgDigest: Digest64, dgDigestStart: UInt32 }),
//     () => {
//       const n = Number(ldsRaw.length);
//       // 30 45 02 01 dgNumber 04 len
//       for (let i = 0; i < n - 8; ++i) {
//         if (
//           ldsRaw.array[i].toNumber() === 0x30 &&
//           ldsRaw.array[i + 1].toNumber() === 0x45 &&
//           ldsRaw.array[i + 2].toNumber() === 0x02 &&
//           ldsRaw.array[i + 3].toNumber() === 0x01 &&
//           ldsRaw.array[i + 4].toNumber() === dgNumber &&
//           ldsRaw.array[i + 5].toNumber() === 0x04
//         ) {
//           // we found it. read length
//           const len = ldsRaw.array[i + 6].toNumber();
//           if (i + 7 + len <= n) {
//             const dgDigestStart = UInt32.from(i + 7);
//             const dgDigest = Digest64.fromBytes(ldsRaw.array.slice(Number(dgDigestStart), Number(dgDigestStart) + len));
//             return {
//               dgDigestStart,
//               dgDigest,
//             }
//           }
//         }
//       }
//       throw new Error('DG Hash is missing from LDS');
//     }
//   );
  
//   dgDigest.length.assertLessThan(65);
//   dgDigest.length.add(dgDigestStart.value).assertLessThanOrEqual(ldsRaw.length);
//   ldsRaw.get(dgDigestStart).assertEquals(0x30);
//   ldsRaw.get(dgDigestStart.add(1)).assertEquals(0x45);
//   ldsRaw.get(dgDigestStart.add(2)).assertEquals(0x02);
//   ldsRaw.get(dgDigestStart.add(3)).assertEquals(0x01);
//   ldsRaw.get(dgDigestStart.add(4)).assertEquals(dgNumber);
//   ldsRaw.get(dgDigestStart.add(5)).assertEquals(0x04);
//   dgDigest.length.assertEquals(ldsRaw.get(dgDigestStart.add(6)).value);
//   return dgDigest;
// }

function findDataGroupDigestWithinLDS(ldsRaw: LDSBytes, dgNumber: number, len: number) {
  const { dgDigest, dgDigestStart } = Provable.witness(
    Struct({ dgDigest: Bytes(len), dgDigestStart: Field }),
    () => {
      const n = Number(ldsRaw.length);
      // 30 45 02 01 dgNumber 04 len
      for (let i = 0; i < n - 8; ++i) {
        if (
          ldsRaw.array[i].toNumber() === 0x30 &&
          ldsRaw.array[i + 1].toNumber() === 0x45 &&
          ldsRaw.array[i + 2].toNumber() === 0x02 &&
          ldsRaw.array[i + 3].toNumber() === 0x01 &&
          ldsRaw.array[i + 4].toNumber() === dgNumber &&
          ldsRaw.array[i + 5].toNumber() === 0x04 &&
          ldsRaw.array[i + 6].toNumber() === len
        ) {
          // we found it. read length
          if (i + 7 + len <= n) {
            const dgDigestStart = Field.from(i + 7);
            const dgDigest = Bytes.from(ldsRaw.array.slice(Number(dgDigestStart), Number(dgDigestStart) + len));
            return {
              dgDigestStart,
              dgDigest,
            }
          }
        }
      }
      throw new Error('DG Hash is missing from LDS');
    }
  );

  // ldsRaw.array[dgDigestStart].assertEquals(0x30);

  ldsRaw.getOrUnconstrained(dgDigestStart).assertEquals(0x30);
  ldsRaw.getOrUnconstrained(dgDigestStart.add(1)).assertEquals(0x45);
  ldsRaw.getOrUnconstrained(dgDigestStart.add(2)).assertEquals(0x02);
  ldsRaw.getOrUnconstrained(dgDigestStart.add(3)).assertEquals(0x01);
  ldsRaw.getOrUnconstrained(dgDigestStart.add(4)).assertEquals(dgNumber);
  ldsRaw.getOrUnconstrained(dgDigestStart.add(5)).assertEquals(0x04);
  ldsRaw.getOrUnconstrained(dgDigestStart.add(6)).assertEquals(len);
  for (let i = 0; i < len; i++) {
    ldsRaw.getOrUnconstrained(dgDigestStart.add(7 + i)).assertEquals(dgDigest.bytes[i]);
  }
  return dgDigest;
}

const MobileProgram = ZkProgram({
  name: 'zk-passport-mobile',
  publicInput: Field, // Query and timestamp combined.
  publicOutput: Field, // hash of LDS

  methods: {
    runSHA512: {
      privateInputs: [
        DG1Bytes,
        LDSBytes
      ],
      async method(publicInput: Field, dg1Bytes: DG1Bytes, ldsBytes: LDSBytes) {
        const dg1Hash = SHA2.hash(512, dg1Bytes);
        const dg1Digest = findDataGroupDigestWithinLDS(ldsBytes, 1, 512/8);
        for (let i = 0; i < 512/8; i++) {
          dg1Digest.bytes[i].assertEquals(dg1Hash.bytes[i]);
        }
        return { publicOutput: hashDynamic(ldsBytes) };
      }
    },


    runSHA512Alt: {
      privateInputs: [
        DG1Bytes,
        LDSBytes,
        Field, // dgDigestStart
      ],
      async method(publicInput: Field, dg1Bytes: DG1Bytes, ldsBytes: LDSBytes, dgDigestStart: Field) {
        const dg1Hash = SHA2.hash(512, dg1Bytes);
        // const dg1Digest = findDataGroupDigestWithinLDS(ldsBytes, 1, 512/8);
        ldsBytes.getOrUnconstrained(dgDigestStart).assertEquals(0x30);
        ldsBytes.getOrUnconstrained(dgDigestStart.add(1)).assertEquals(0x45);
        ldsBytes.getOrUnconstrained(dgDigestStart.add(2)).assertEquals(0x02);
        ldsBytes.getOrUnconstrained(dgDigestStart.add(3)).assertEquals(0x01);
        ldsBytes.getOrUnconstrained(dgDigestStart.add(4)).assertEquals(1); // dgNumber
        ldsBytes.getOrUnconstrained(dgDigestStart.add(5)).assertEquals(0x04);
        ldsBytes.getOrUnconstrained(dgDigestStart.add(6)).assertEquals(512/8); // len
        for (let i = 0; i < 512/8; i++) {
          ldsBytes.getOrUnconstrained(dgDigestStart.add(i+7)).assertEquals(dg1Hash.bytes[i]);
        }
        return { publicOutput: Field.from(0) };
      }
    },

    // runB: {
    //   privateInputs: [
    //     DG1Bytes,
    //     LDSBytes,
    //   ],
    // },
  }


})

const methods = await MobileProgram.analyzeMethods();
Object.values(methods).forEach((v) => {
  console.log(v.summary());
});