import * as asn1js from "npm:asn1js";
import {
  DataGroupNumber,
  DigestAlgo,
  getDigestAlgoOID,
} from "../src/common.ts";
import { digestFunc } from "./common.ts";

export function prepareLDSSecurityObject(
  dgHashes: Map<DataGroupNumber, Uint8Array>,
  hashAlgo: DigestAlgo,
): asn1js.Sequence {
  // Sort and convert hash entries to ASN.1 sequences
  const hashSequences = Array.from(dgHashes.entries())
    .sort(([a], [b]) => a - b) // Sort by datagroup number
    .map(([dgNumber, hash]) =>
      new asn1js.Sequence({
        value: [
          new asn1js.Integer({ value: dgNumber }),
          new asn1js.OctetString({ valueHex: hash }),
        ],
      })
    );

  // Use a shorter form for the algorithm identifier
  const algorithmIdentifier = new asn1js.Sequence({
    value: [
      new asn1js.ObjectIdentifier({ value: getDigestAlgoOID(hashAlgo) }),
      // new asn1js.Null(),
    ],
  });

  return new asn1js.Sequence({
    value: [
      new asn1js.Integer({ value: 0 }),
      // Hash algorithm identifier
      algorithmIdentifier,
      // Sequence of datagroup hashes
      new asn1js.Sequence({
        value: hashSequences,
      }),
    ],
  });
}

export function prepareSignedAttributes(ldsHash: Uint8Array): asn1js.Set {
  const OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
  const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
  const OID_ICAO_LDS_SOD = "2.23.136.1.1.1";
  return new asn1js.Set({
    value: [
      // Content Type attribute
      new asn1js.Sequence({
        value: [
          new asn1js.ObjectIdentifier({ value: OID_CONTENT_TYPE }),
          new asn1js.Set({
            value: [
              new asn1js.ObjectIdentifier({ value: OID_ICAO_LDS_SOD }),
            ],
          }),
        ],
      }),
      // Message Digest attribute
      new asn1js.Sequence({
        value: [
          new asn1js.ObjectIdentifier({ value: OID_MESSAGE_DIGEST }),
          new asn1js.Set({
            value: [
              new asn1js.OctetString({ valueHex: ldsHash }),
            ],
          }),
        ],
      }),
    ],
  });
}

export function mockLdsAndSignedAttrs(
  dg1: Uint8Array,
  digestAlgo: DigestAlgo,
  mockDGs: Set<DataGroupNumber> = new Set(),
) {
  const hasher = digestFunc(digestAlgo);
  const dgHashes = new Map<DataGroupNumber, Uint8Array>();

  const localMockDGs = new Set(mockDGs);
  // 2 and 14 are mandatory, dg1 is not random.
  localMockDGs.add(2);
  localMockDGs.add(14);
  localMockDGs.delete(1);

  for (const dgNumber of localMockDGs) {
    const randomData = new Uint8Array(32);
    crypto.getRandomValues(randomData);
    dgHashes.set(dgNumber, hasher(randomData));
  }

  dgHashes.set(1, hasher(dg1));

  const ldsAsn1 = prepareLDSSecurityObject(dgHashes, digestAlgo);
  const lds = new Uint8Array(ldsAsn1.toBER());
  const signedAttrsAsn1 = prepareSignedAttributes(hasher(lds));
  const signedAttrs = new Uint8Array(signedAttrsAsn1.toBER());

  return {
    lds,
    signedAttrs,
  };
}
