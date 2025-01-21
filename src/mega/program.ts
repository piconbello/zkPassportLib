import { ZkProgram, Struct, UInt64, UInt32, Field, Bytes, Provable, SelfProof } from 'o1js';
import { DynamicBytes, DynamicSHA2, hashDynamic } from 'mina-credentials/dynamic';

class ZkPassportState extends Struct({
  appId: Field,
  appUserId: Field,
  globalUserId: Field,
  timestamp: UInt64,
  query: Field, // TODO meaning of this field shall be clarified
  masterCertMerkleRoot: Field, // active master certificate merkle root
  validationMask: Field, // current validation mask
  commitmentDG1: Field,
  commitmentLDS: Field,
  commitmentLDSDigest: Field,
  commitmentCert: Field,
  commitmentCertDigest: Field,
  commitmentMasterCert: Field,
  commitmentMasterCertDigest: Field,
  commitmentMasterCertMerklePath: Field,
}) {

}

class DG1Bytes extends Bytes(93) {}

class LDSBytes extends DynamicBytes({ maxLength: 1200 }) {}

class Digest64 extends DynamicBytes({ maxLength: 64 }) {}

class CertBytes extends DynamicBytes({ maxLength: 1200 }) {} // todo decide actual max length

function findDataGroupDigestWithinLDS(ldsRaw: LDSBytes, dgNumber: number): Digest64 {
  const { dgDigest, dgDigestStart } = Provable.witness(
    Struct({ dgDigest: Digest64, dgDigestStart: UInt32 }),
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
          ldsRaw.array[i + 5].toNumber() === 0x04
        ) {
          // we found it. read length
          const len = ldsRaw.array[i + 6].toNumber();
          if (i + 7 + len <= n) {
            const dgDigestStart = UInt32.from(i + 7);
            const dgDigest = Digest64.fromBytes(ldsRaw.array.slice(Number(dgDigestStart), Number(dgDigestStart) + len));
            return {
              dgDigestStart,
              dgDigest,
            }
          }
        }
      }
      throw new Error('DG3 Hash is missing from LDS');
    }
  );
  
  dgDigest.length.assertLessThan(65);
  dgDigest.length.add(dgDigestStart.value).assertLessThanOrEqual(ldsRaw.length);
  ldsRaw.get(dgDigestStart).assertEquals(0x30);
  ldsRaw.get(dgDigestStart.add(1)).assertEquals(0x45);
  ldsRaw.get(dgDigestStart.add(2)).assertEquals(0x02);
  ldsRaw.get(dgDigestStart.add(3)).assertEquals(0x01);
  ldsRaw.get(dgDigestStart.add(4)).assertEquals(dgNumber);
  ldsRaw.get(dgDigestStart.add(5)).assertEquals(0x04);
  dgDigest.length.assertEquals(ldsRaw.get(dgDigestStart.add(6)).value);
  return dgDigest;
}

const megaProgram = ZkProgram({
  name: 'zk-passport-mega',
  publicOutput: ZkPassportState,
  
  methods: {
    init: {
      privateInputs: [
        Field, // appId
        UInt64, // timestamp
        Field, // query
        Field, // salt
        DG1Bytes, // DG1 raw
        LDSBytes, // LDS raw
        Digest64, // LDS digest
        CertBytes, // cert raw
        Digest64, // cert digest
        CertBytes, // master cert raw
        Digest64, // master cert digest
        Field, // master cert  merkle root
        Field, // TODO master cert merkle path? might require something else
        Digest64, // DG3 digest
      ],
      async method(
        appId: Field,
        timestamp: UInt64,
        query: Field,
        salt: Field,
        dg1Raw: DG1Bytes,
        ldsRaw: LDSBytes,
        ldsDigest: Digest64,
        certRaw: CertBytes,
        certDigest: Digest64,
        masterCertRaw: CertBytes,
        masterCertDigest: Digest64,
        masterCertMerkleRoot: Field,
        masterCertMerklePath: Field, // TODO its type will change.
        dg3Digest: Digest64,
      ) {
        const commitmentDG1 = hashDynamic([salt, hashDynamic(dg1Raw), appId]);
        const commitmentLDS = hashDynamic([salt, hashDynamic(ldsRaw), appId]);
        const commitmentLDSDigest = hashDynamic([salt, hashDynamic(ldsDigest), appId]);
        const commitmentCert = hashDynamic([salt, hashDynamic(certRaw), appId]);
        const commitmentCertDigest = hashDynamic([salt, hashDynamic(certDigest), appId]);
        const commitmentMasterCert = hashDynamic([salt, hashDynamic(masterCertRaw), appId]);
        const commitmentMasterCertDigest = hashDynamic([salt, hashDynamic(masterCertDigest), appId]);
        const commitmentMasterCertMerklePath = hashDynamic([salt, hashDynamic(masterCertMerklePath), appId]);

        // REMOVING DG3 DETECTION FROM LDS HERE AWARDS US AN ADDITIONAL 9K CONSTRAINTS, but causes additional 18.7K CONSTRAINTS IN A SEPARATE METHOD.
        // const { dg3Digest, dg3DigestStart } = Provable.witness(
        //   Struct({ dg3Digest: Digest64, dg3DigestStart: UInt32 }),
        //   () => {
        //     const n = Number(ldsRaw.length);
        //     // 30 45 02 01 03  04 len
        //     for (let i = 0; i < n - 8; ++i) {
        //       if (
        //         ldsRaw.array[i].toNumber() === 0x30 &&
        //         ldsRaw.array[i + 1].toNumber() === 0x45 &&
        //         ldsRaw.array[i + 2].toNumber() === 0x02 &&
        //         ldsRaw.array[i + 3].toNumber() === 0x01 &&
        //         ldsRaw.array[i + 4].toNumber() === 0x03 &&
        //         ldsRaw.array[i + 5].toNumber() === 0x04
        //       ) {
        //         // we found it. read length
        //         const len = ldsRaw.array[i + 6].toNumber();
        //         if (i + 7 + len <= n) {
        //           const dg3DigestStart = UInt32.from(i + 7);
        //           const dg3Digest = Digest64.fromBytes(ldsRaw.array.slice(Number(dg3DigestStart), Number(dg3DigestStart) + len));
        //           return {
        //             dg3DigestStart,
        //             dg3Digest,
        //           }
        //         }
        //       }
        //     }
        //     throw new Error('DG3 Hash is missing from LDS');
        //   }
        // );
        
        // dg3Digest.length.assertLessThan(65);
        // dg3Digest.length.add(dg3DigestStart.value).assertLessThanOrEqual(ldsRaw.length);
        // ldsRaw.get(dg3DigestStart).assertEquals(0x30);
        // ldsRaw.get(dg3DigestStart.add(1)).assertEquals(0x45);
        // ldsRaw.get(dg3DigestStart.add(2)).assertEquals(0x02);
        // ldsRaw.get(dg3DigestStart.add(3)).assertEquals(0x01);
        // ldsRaw.get(dg3DigestStart.add(4)).assertEquals(0x03);
        // ldsRaw.get(dg3DigestStart.add(5)).assertEquals(0x04);
        // dg3Digest.length.assertEquals(ldsRaw.get(dg3DigestStart.add(6)).value);

        const globalUserId = hashDynamic(dg3Digest);
        const appUserId = hashDynamic([globalUserId, appId]);
        const validationMask = Field.from(0);
        
        const publicOutput = new ZkPassportState({
          appId,
          appUserId,
          globalUserId,
          timestamp,
          query,
          masterCertMerkleRoot,
          validationMask,
          commitmentDG1,
          commitmentLDS,
          commitmentLDSDigest,
          commitmentCert,
          commitmentCertDigest,
          commitmentMasterCert,
          commitmentMasterCertDigest,
          commitmentMasterCertMerklePath,
        });
        return { publicOutput };
      }
    },

    step01_validateUUID: {
      privateInputs: [
        SelfProof, // self-proven state
        Field, // salt
        LDSBytes, // LDS raw
        Digest64, // DG3 digest
      ],
      async method(
        proof: SelfProof<undefined, ZkPassportState>,
        salt: Field,
        ldsRaw: LDSBytes,
        dg3Digest: Digest64,
      ) {
        proof.verify();
        const { publicOutput } = proof;

        const globalUserId = hashDynamic(dg3Digest);
        globalUserId.assertEquals(publicOutput.globalUserId);
        const appUserId = hashDynamic([globalUserId, publicOutput.appId]);
        appUserId.assertEquals(publicOutput.appUserId);

        publicOutput.commitmentLDS.assertEquals(hashDynamic([salt, hashDynamic(ldsRaw), publicOutput.appId]));

        const dg3DigestInLDS = findDataGroupDigestWithinLDS(ldsRaw, 3);
        dg3Digest.assertEquals(dg3DigestInLDS);
        publicOutput.validationMask.assertEquals(0);
        publicOutput.validationMask.add(1);
        publicOutput.validationMask.assertEquals(1);
        return { publicOutput };
      }
    },
    step02_validateUUID: {
      privateInputs: [
        SelfProof, // self-proven state
        Field, // salt
        LDSBytes, // LDS raw
        Digest64, // DG3 digest
      ],
      async method(
        proof: SelfProof<undefined, ZkPassportState>,
        salt: Field,
        ldsRaw: LDSBytes,
        dg3Digest: Digest64,
      ) {
        const { publicOutput } = proof;

        const globalUserId = hashDynamic(dg3Digest);
        globalUserId.assertEquals(publicOutput.globalUserId);
        const appUserId = hashDynamic([globalUserId, publicOutput.appId]);
        appUserId.assertEquals(publicOutput.appUserId);

        publicOutput.commitmentLDS.assertEquals(hashDynamic([salt, hashDynamic(ldsRaw), publicOutput.appId]));

        const dg3DigestInLDS = findDataGroupDigestWithinLDS(ldsRaw, 3);
        dg3Digest.assertEquals(dg3DigestInLDS);
        publicOutput.validationMask.assertEquals(0);
        publicOutput.validationMask.add(1);
        publicOutput.validationMask.assertEquals(1);
        return { publicOutput };
      }
    },
    step03_validateUUID: {
      privateInputs: [
        SelfProof, // self-proven state
        Field, // salt
        LDSBytes, // LDS raw
        Digest64, // DG3 digest
      ],
      async method(
        proof: SelfProof<undefined, ZkPassportState>,
        salt: Field,
        ldsRaw: LDSBytes,
        dg3Digest: Digest64,
      ) {
        const { publicOutput } = proof;

        const globalUserId = hashDynamic(dg3Digest);
        globalUserId.assertEquals(publicOutput.globalUserId);
        const appUserId = hashDynamic([globalUserId, publicOutput.appId]);
        appUserId.assertEquals(publicOutput.appUserId);

        publicOutput.commitmentLDS.assertEquals(hashDynamic([salt, hashDynamic(ldsRaw), publicOutput.appId]));

        const dg3DigestInLDS = findDataGroupDigestWithinLDS(ldsRaw, 3);
        dg3Digest.assertEquals(dg3DigestInLDS);
        publicOutput.validationMask.assertEquals(0);
        publicOutput.validationMask.add(1);
        publicOutput.validationMask.assertEquals(1);
        return { publicOutput };
      }
    },
    step04_validateUUID: {
      privateInputs: [
        SelfProof, // self-proven state
        Field, // salt
        LDSBytes, // LDS raw
        Digest64, // DG3 digest
      ],
      async method(
        proof: SelfProof<undefined, ZkPassportState>,
        salt: Field,
        ldsRaw: LDSBytes,
        dg3Digest: Digest64,
      ) {
        const { publicOutput } = proof;

        const globalUserId = hashDynamic(dg3Digest);
        globalUserId.assertEquals(publicOutput.globalUserId);
        const appUserId = hashDynamic([globalUserId, publicOutput.appId]);
        appUserId.assertEquals(publicOutput.appUserId);

        publicOutput.commitmentLDS.assertEquals(hashDynamic([salt, hashDynamic(ldsRaw), publicOutput.appId]));

        const dg3DigestInLDS = findDataGroupDigestWithinLDS(ldsRaw, 3);
        dg3Digest.assertEquals(dg3DigestInLDS);
        publicOutput.validationMask.assertEquals(0);
        publicOutput.validationMask.add(1);
        publicOutput.validationMask.assertEquals(1);
        return { publicOutput };
      }
    },
    step05_validateUUID: {
      privateInputs: [
        SelfProof, // self-proven state
        Field, // salt
        LDSBytes, // LDS raw
        Digest64, // DG3 digest
      ],
      async method(
        proof: SelfProof<undefined, ZkPassportState>,
        salt: Field,
        ldsRaw: LDSBytes,
        dg3Digest: Digest64,
      ) {
        const { publicOutput } = proof;

        const globalUserId = hashDynamic(dg3Digest);
        globalUserId.assertEquals(publicOutput.globalUserId);
        const appUserId = hashDynamic([globalUserId, publicOutput.appId]);
        appUserId.assertEquals(publicOutput.appUserId);

        publicOutput.commitmentLDS.assertEquals(hashDynamic([salt, hashDynamic(ldsRaw), publicOutput.appId]));

        const dg3DigestInLDS = findDataGroupDigestWithinLDS(ldsRaw, 3);
        dg3Digest.assertEquals(dg3DigestInLDS);
        publicOutput.validationMask.assertEquals(0);
        publicOutput.validationMask.add(1);
        publicOutput.validationMask.assertEquals(1);
        return { publicOutput };
      }
    },
    step06_validateUUID: {
      privateInputs: [
        SelfProof, // self-proven state
        Field, // salt
        LDSBytes, // LDS raw
        Digest64, // DG3 digest
      ],
      async method(
        proof: SelfProof<undefined, ZkPassportState>,
        salt: Field,
        ldsRaw: LDSBytes,
        dg3Digest: Digest64,
      ) {
        const { publicOutput } = proof;

        const globalUserId = hashDynamic(dg3Digest);
        globalUserId.assertEquals(publicOutput.globalUserId);
        const appUserId = hashDynamic([globalUserId, publicOutput.appId]);
        appUserId.assertEquals(publicOutput.appUserId);

        publicOutput.commitmentLDS.assertEquals(hashDynamic([salt, hashDynamic(ldsRaw), publicOutput.appId]));

        const dg3DigestInLDS = findDataGroupDigestWithinLDS(ldsRaw, 3);
        dg3Digest.assertEquals(dg3DigestInLDS);
        publicOutput.validationMask.assertEquals(0);
        publicOutput.validationMask.add(1);
        publicOutput.validationMask.assertEquals(1);
        return { publicOutput };
      }
    },
    step07_validateUUID: {
      privateInputs: [
        SelfProof, // self-proven state
        Field, // salt
        LDSBytes, // LDS raw
        Digest64, // DG3 digest
      ],
      async method(
        proof: SelfProof<undefined, ZkPassportState>,
        salt: Field,
        ldsRaw: LDSBytes,
        dg3Digest: Digest64,
      ) {
        const { publicOutput } = proof;

        const globalUserId = hashDynamic(dg3Digest);
        globalUserId.assertEquals(publicOutput.globalUserId);
        const appUserId = hashDynamic([globalUserId, publicOutput.appId]);
        appUserId.assertEquals(publicOutput.appUserId);

        publicOutput.commitmentLDS.assertEquals(hashDynamic([salt, hashDynamic(ldsRaw), publicOutput.appId]));

        const dg3DigestInLDS = findDataGroupDigestWithinLDS(ldsRaw, 3);
        dg3Digest.assertEquals(dg3DigestInLDS);
        publicOutput.validationMask.assertEquals(0);
        publicOutput.validationMask.add(1);
        publicOutput.validationMask.assertEquals(1);
        return { publicOutput };
      }
    },
  }
});


let { init, step01_validateUUID } = await megaProgram.analyzeMethods();

console.log(init.summary());
console.log(step01_validateUUID.summary());

console.time('compile');
const forceRecompileEnabled = false;
await megaProgram.compile({ forceRecompile: forceRecompileEnabled });
console.timeEnd('compile');