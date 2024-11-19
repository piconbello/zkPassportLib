import { Field, Hash, MerkleTree, MerkleWitness } from "npm:o1js";
import { MasterCert, PublicKeyEC, RSAPublicKey } from "./parse.ts";
import { bigintToLimbs } from "./utilsO1.ts";

// Math.ceil(Math.log2(1000)) + 1;
export const MERKLE_HEIGHT = 11;
export class MyWitness extends MerkleWitness(MERKLE_HEIGHT) {}

export class CertificateRegistry {
  private masterCerts: MasterCert[];
  private tree: MerkleTree;

  constructor(masterlist: MasterCert[]) {
    this.masterCerts = masterlist;

    const masterlistHashes = this.masterCerts.map(hashMasterCert);

    this.tree = new MerkleTree(MERKLE_HEIGHT);
    this.tree.fill(masterlistHashes);
  }

  public getRoot(): Field {
    return this.tree.getRoot();
  }

  public proveFor(
    pubkey: RSAPublicKey | PublicKeyEC,
  ): CertificateAuthorizationProof {
    const index = findMasterCert(this.masterCerts, pubkey);
    const witness = this.tree.getWitness(BigInt(index));
    const certificate = this.masterCerts[index];

    return {
      witness: new MyWitness(witness),
      certificate,
      root: this.getRoot(),
    };
  }
}

export type CertificateAuthorizationProof = {
  witness: MyWitness;
  certificate: MasterCert;
  root: Field;
};

export function isValidRegistryWitness(
  root: Field,
  certificate: MasterCert,
  witness: MyWitness,
): boolean {
  const certificateHash = hashMasterCert(certificate);
  const computedRoot = witness.calculateRoot(certificateHash);
  return computedRoot.equals(root).toBoolean();
}

function RSAtoFields(pubkey: RSAPublicKey) {
  return [
    Field(pubkey.exponent),
    ...bigintToLimbs(pubkey.modulus),
  ];
}

function ECtoFields(pubkey: PublicKeyEC) {
  return [
    ...bigintToLimbs(pubkey.x),
    ...bigintToLimbs(pubkey.y),
  ];
}

function hashMasterCert(
  masterCert: MasterCert,
): Field {
  let fields;
  if (masterCert.pubkey.type === "RSA") {
    fields = RSAtoFields(masterCert.pubkey);
  } else {
    fields = ECtoFields(masterCert.pubkey);
  }
  return Hash.Poseidon.hash(fields);
}

function findMasterCert(
  certs: MasterCert[],
  pubkey: RSAPublicKey | PublicKeyEC,
): number {
  const index = certs.findIndex((cert, i) => {
    if (cert.pubkey.type !== pubkey.type) {
      return false;
    }

    if (pubkey.type === "RSA") {
      const rsaPubkey = pubkey as RSAPublicKey;
      const certRsaPubkey = cert.pubkey as RSAPublicKey;
      return certRsaPubkey.modulus === rsaPubkey.modulus &&
        certRsaPubkey.exponent === rsaPubkey.exponent;
    } else {
      const ecPubkey = pubkey as PublicKeyEC;
      const certEcPubkey = cert.pubkey as PublicKeyEC;
      return certEcPubkey.x === ecPubkey.x &&
        certEcPubkey.y === ecPubkey.y &&
        certEcPubkey.curve === ecPubkey.curve;
    }
  });

  if (index === -1) {
    throw new Error("Public key not found in masterlist");
  }

  return index;
}
