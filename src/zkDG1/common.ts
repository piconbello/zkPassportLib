import {
  Bytes,
  DynamicProof,
  FeatureFlags,
  Field,
  Struct,
  UInt8,
  Void,
} from "o1js";
import { Bytes74, DigestAlgo, lengthOID } from "../common.ts";

/// Exported

export class DG1_TD3 extends Bytes(93) {}

export function extractBirthdayTD3(td3: DG1_TD3) {
  const offset = dobOffsetInDG1("TD3");
  return extractBirthday(td3.bytes, offset);
}

export function dg1OffsetInLDS(algo: DigestAlgo): number {
  /*
  The offset of DG1 in LDS is calculated like:
    1. SEQUENCE tag + length (2 bytes)
    2. Version INTEGER tag + length + value (3 bytes)
    3. hashAlgorithm SEQUENCE tag + length (2 bytes)
    4. algorithm OID tag + length (2 bytes)
    5. OID value (19 or 20 bytes)
    6. NULL tag + length (2 bytes)
    7. dataGroupHashes SEQUENCE tag + length (2 bytes)
    8. First DataGroupHash SEQUENCE starts here

    Total: 2 + 3 + 2 + 2 + 19 or 20 + 2 + 2 = 29 or 30 bytes
  */
  return 10 + lengthOID(algo);
}

/// Not exported

function dobOffsetInDG1(type: "TD1" | "TD2" | "TD3") {
  /*
  DG1 length and YYMMDD positions:
  1. Passport (TD3): 93 characters (88 MRZ + 5 additional)
     YYMMDD is at DG1[5+57:5+57+6] // positions 62-67
  2. ID Card (TD1): 95 characters (90 MRZ + 5 additional)
     YYMMDD is at DG1[5+30:5+30+6] // positions 35-40
  3. Visa/Travel Document (TD2): 77 characters (72 MRZ + 5 additional)
     YYMMDD is at DG1[5+49:5+49+6] // positions 54-59
  */
  if (type === "TD1") {
    return 35;
  } else if (type === "TD2") {
    return 54;
  } else if (type === "TD3") {
    return 62;
  }
  throw Error("unreachable");
}

function extractBirthday(
  bytes: UInt8[],
  offset: number,
): [Field, Field, Field] {
  // Year (2 digits)
  const year = bytes[offset].value.sub(Field(48)).mul(Field(10)).add(
    bytes[offset + 1].value.sub(Field(48)),
  );

  // Month (2 digits)
  const month = bytes[offset + 2].value.sub(Field(48)).mul(Field(10)).add(
    bytes[offset + 3].value.sub(Field(48)),
  );

  // Day (2 digits)
  const day = bytes[offset + 4].value.sub(Field(48)).mul(Field(10)).add(
    bytes[offset + 5].value.sub(Field(48)),
  );

  return [year, month, day];
}

export class ZkTD3_PubInput_74 extends Struct({
  dg1: DG1_TD3,
  signedAttrs: Bytes74,
}) {}

export class DynProofZkTD3_74 extends DynamicProof<ZkTD3_PubInput_74, Void> {
  static override publicInputType = ZkTD3_PubInput_74;
  static override publicOutputType = Void;
  static override maxProofsVerified = 0 as const;
  static override featureFlags = FeatureFlags.allMaybe;
}
