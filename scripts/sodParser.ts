import * as asn1js from "npm:asn1js";
import {
  Certificate as PkiCertificate,
  ContentInfo,
  SignedData,
} from "npm:pkijs";
import { encodeBase64 } from "@std/encoding/base64";

export interface ValidityPeriod {
  notBefore: Date;
  notAfter: Date;
}

export interface Certificate {
  issuer: string;
  subject: string;
  serialNumber: number;
  validity: ValidityPeriod;
  signatureAlgorithm: string;
  publicKey: Uint8Array;
}

export interface SignedAttribute {
  type: string;
  values: unknown[];
}

export interface DataGroupHash {
  number: number;
  hash: Uint8Array;
}

export interface SignerInfo {
  version: number;
  digestAlgorithm: string;
  signatureAlgorithm: string;
  signature: Uint8Array;
  signedAttrs: SignedAttribute[];
}

export interface LDSSecurityObjectInfo {
  version: number;
  hashAlgorithm: string;
  datagroupHashes: Record<string, DataGroupHash>;
}

export interface SODObject {
  version: number;
  digestAlgorithms: string[];
  certificates: Certificate[];
  signerInfos: SignerInfo[];
  ldsSecurityObject: LDSSecurityObjectInfo;
}

export function parseSod(sodBytes: Uint8Array): SODObject {
  const result: SODObject = {
    version: 0,
    digestAlgorithms: [],
    certificates: [],
    signerInfos: [],
    ldsSecurityObject: {
      version: 0,
      hashAlgorithm: "",
      datagroupHashes: {},
    },
  };

  // Skip first 4 bytes and parse as ContentInfo
  const asn1 = asn1js.fromBER(sodBytes.slice(4));
  if (asn1.offset === -1) {
    throw new Error("ASN.1 parsing error");
  }

  const contentInfo = new ContentInfo({ schema: asn1.result });
  const signedData = new SignedData({ schema: contentInfo.content });

  result.version = signedData.version;

  // Extract digest algorithms
  result.digestAlgorithms = signedData.digestAlgorithms.map(
    (algo) => algo.algorithmId,
  );

  // Extract certificates and signer info
  result.certificates = parseCertificates(signedData);
  result.signerInfos = parseSignerInfos(signedData);

  // Parse LDS Security Object
  result.ldsSecurityObject = parseLDSSecurityObject(signedData);

  return result;
}

function parseCertificates(signedData: SignedData): Certificate[] {
  const certificates: Certificate[] = [];

  if (signedData.certificates && signedData.certificates.length > 0) {
    for (const certChoice of signedData.certificates) {
      // Access the certificate through the chosen property
      if (certChoice.hasOwnProperty("value")) {
        const cert = (certChoice as any).value as PkiCertificate;

        const certInfo: Certificate = {
          issuer: cert.issuer.typesAndValues.map((tv: any) =>
            `${tv.type}=${tv.value.valueBlock.value}`
          ).join(", "),
          subject: cert.subject.typesAndValues.map((tv: any) =>
            `${tv.type}=${tv.value.valueBlock.value}`
          ).join(", "),
          serialNumber: parseInt(cert.serialNumber.valueBlock.toString()),
          validity: {
            notBefore: cert.notBefore.value,
            notAfter: cert.notAfter.value,
          },
          signatureAlgorithm: cert.signatureAlgorithm.algorithmId,
          publicKey: new Uint8Array(
            cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex,
          ),
        };
        certificates.push(certInfo);
      }
    }
  }

  return certificates;
}
function parseSignerInfos(signedData: SignedData): SignerInfo[] {
  const signerInfos: SignerInfo[] = [];

  for (const signer of signedData.signerInfos) {
    const signedAttrs: SignedAttribute[] = [];

    if (signer.signedAttrs) {
      // Access the attributes array directly
      const attributes = signer.signedAttrs.attributes || [];

      for (const attr of attributes) {
        try {
          const attrInfo: SignedAttribute = {
            type: attr.type,
            values: Array.from(attr.values || []).map((v: any) => {
              if (v.valueBlock) {
                return v.valueBlock.value;
              }
              return v;
            }),
          };
          signedAttrs.push(attrInfo);
        } catch (error) {
          console.warn("Error parsing signed attribute:", error);
        }
      }
    }

    const signerInfo: SignerInfo = {
      version: signer.version,
      digestAlgorithm: signer.digestAlgorithm.algorithmId,
      signatureAlgorithm: signer.signatureAlgorithm.algorithmId,
      signature: new Uint8Array(signer.signature.valueBlock.valueHex),
      signedAttrs,
    };
    signerInfos.push(signerInfo);
  }

  return signerInfos;
}

function parseLDSSecurityObject(signedData: SignedData): LDSSecurityObjectInfo {
  const result: LDSSecurityObjectInfo = {
    version: 0,
    hashAlgorithm: "",
    datagroupHashes: {},
  };

  if (signedData.encapContentInfo && signedData.encapContentInfo.eContent) {
    const asn1Result = asn1js.fromBER(
      signedData.encapContentInfo.eContent.valueBlock.valueHex,
    );

    if (asn1Result.offset === -1) {
      throw new Error("Failed to parse LDS Security Object");
    }

    const sequence = asn1Result.result as asn1js.Sequence;

    // Access version (first element)
    result.version = (sequence.valueBlock.value[0] as asn1js.Integer)
      .valueBlock.valueDec;

    // Access hash algorithm (second element)
    const hashAlgoSequence = sequence.valueBlock.value[1] as asn1js.Sequence;
    result.hashAlgorithm =
      (hashAlgoSequence.valueBlock.value[0] as asn1js.ObjectIdentifier)
        .valueBlock.toString();

    // Access datagroup hashes (third element)
    const dgHashesSequence = sequence.valueBlock.value[2] as asn1js.Sequence;
    for (const dgHash of dgHashesSequence.valueBlock.value) {
      const dgHashSeq = dgHash as asn1js.Sequence;
      const dgNum = (dgHashSeq.valueBlock.value[0] as asn1js.Integer)
        .valueBlock.valueDec;
      const dgHashValue = new Uint8Array(
        (dgHashSeq.valueBlock.value[1] as asn1js.OctetString)
          .valueBlock.valueHex,
      );

      result.datagroupHashes[`DG${dgNum}`] = {
        hash: dgHashValue,
        number: dgNum,
      };
    }
  }

  return result;
}

function getDigestAlgoFromOID(oid: string): string {
  const mapping: Record<string, string> = {
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "2.16.840.1.101.3.4.2.5": "sha512-224",
    "2.16.840.1.101.3.4.2.6": "sha512-256",
    "2.16.840.1.101.3.4.2.7": "sha3-224",
    "2.16.840.1.101.3.4.2.8": "sha3-256",
    "2.16.840.1.101.3.4.2.9": "sha3-384",
    "2.16.840.1.101.3.4.2.10": "sha3-512",
    "2.16.840.1.101.3.4.2.11": "shake128",
    "2.16.840.1.101.3.4.2.12": "shake256",
  };
  return mapping[oid]!;
}

interface ParsedSOD {
  dgHashes: Record<string, string>;
  lds: string;
  signedAttributes: string;
  digestAlgorithm: string;
  signature: string;
}

export function parseSodSimpler(sodBytes: Uint8Array): ParsedSOD {
  // Skip first 4 bytes and parse as ContentInfo
  const asn1 = asn1js.fromBER(sodBytes.slice(4));
  if (asn1.offset === -1) {
    throw new Error("ASN.1 parsing error");
  }

  const contentInfo = new ContentInfo({ schema: asn1.result });
  const signedData = new SignedData({ schema: contentInfo.content });

  // Get LDS Security Object
  const dgHashes: Record<string, string> = {};
  if (signedData.encapContentInfo && signedData.encapContentInfo.eContent) {
    const asn1Result = asn1js.fromBER(
      signedData.encapContentInfo.eContent.valueBlock.valueHex,
    );
    const sequence = asn1Result.result as asn1js.Sequence;

    // Get hash algorithm
    const hashAlgoSequence = sequence.valueBlock.value[1] as asn1js.Sequence;
    const hashAlgoOID =
      (hashAlgoSequence.valueBlock.value[0] as asn1js.ObjectIdentifier)
        .valueBlock.toString();

    // Get datagroup hashes
    const dgHashesSequence = sequence.valueBlock.value[2] as asn1js.Sequence;
    for (const dgHash of dgHashesSequence.valueBlock.value) {
      const dgHashSeq = dgHash as asn1js.Sequence;
      const dgNum = (dgHashSeq.valueBlock.value[0] as asn1js.Integer)
        .valueBlock.valueDec;
      const dgHashValue = new Uint8Array(
        (dgHashSeq.valueBlock.value[1] as asn1js.OctetString)
          .valueBlock.valueHex,
      );
      dgHashes[dgNum.toString()] = encodeBase64(dgHashValue);
    }
  }

  const signedAttrsSet = new asn1js.Set({
    value: signedData.signerInfos[0].signedAttrs!.toSchema().valueBlock.value,
  });

  const signature = new Uint8Array(
    signedData.signerInfos[0].signature.valueBlock.valueHex,
  );

  return {
    dgHashes,
    lds: encodeBase64(
      new Uint8Array(
        signedData.encapContentInfo.eContent?.valueBlock.valueHex || [],
      ),
    ),
    signedAttributes: encodeBase64(new Uint8Array(signedAttrsSet.toBER())),
    digestAlgorithm: getDigestAlgoFromOID(
      signedData.signerInfos[0].digestAlgorithm.algorithmId,
    ),
    signature: encodeBase64(signature),
  };
}

// Example usage
async function main() {
  const sodBytes = await Deno.readFile("halit-sod");
  const result = parseSodSimpler(sodBytes);
  console.log("\n=== SOD Parsing Results ===");
  console.log(JSON.stringify(result, (key, value) => {
    if (value instanceof Uint8Array) {
      return btoa(String.fromCharCode(...value));
    }
    return value;
  }, 2));
}

if (import.meta.main) {
  main();
}
