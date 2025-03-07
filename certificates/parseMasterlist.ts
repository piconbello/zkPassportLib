// Credits:
// - https://github.com/AndyQ/NFCPassportReader/tree/89813bafed0490d1dab17e1c2c243e41bebcd455/scripts
// - https://wiki.yobi.be/index.php/Main_Page

import { decodeBase64, encodeBase64 } from "@std/encoding/base64";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { sha1 } from "@noble/hashes/sha1";
import { certificatePEM } from "./common.ts";

// Constants
const CONSTANTS = {
  CMS_SIGNED_DATA_OID: "1.2.840.113549.1.7.2",
  LDIF_CERT_PREFIX: "pkdMasterListContent:: ",
  FILE_EXTENSION: ".ldif",
} as const;

/**
 * Extracts CMS structures from LDIF content
 * @param contentLDIF - Raw LDIF file content
 * @returns Array of decoded CMS structures
 */
function extractCMSFromLDIF(contentLDIF: string): Uint8Array[] {
  const lines = contentLDIF.split("\n");
  const certs: string[] = [];
  let currentCertBuilder = {
    isCollecting: false,
    content: "",
  };

  for (const line of lines) {
    if (line.startsWith(CONSTANTS.LDIF_CERT_PREFIX)) {
      currentCertBuilder = {
        isCollecting: true,
        content: line.substring(CONSTANTS.LDIF_CERT_PREFIX.length),
      };
      continue;
    }

    if (!line.startsWith(" ") && currentCertBuilder.isCollecting) {
      certs.push(currentCertBuilder.content);
      currentCertBuilder = { isCollecting: false, content: "" };
      continue;
    }

    if (currentCertBuilder.isCollecting) {
      currentCertBuilder.content += line;
    }
  }

  if (currentCertBuilder.content) {
    certs.push(currentCertBuilder.content);
  }

  return certs.map((cert) => decodeBase64(cert.trim()));
}

/**
 * Initializes PKI environment
 */
function initializePKIEnvironment(): void {
  pkijs.setEngine(
    "default",
    new pkijs.CryptoEngine({
      crypto,
      subtle: crypto.subtle,
    }),
  );
}

/**
 * Extracts eContent from a CMS structure
 * @param cmsData - Raw CMS data
 * @throws Error if CMS structure is invalid
 */
function extractEContentFromCMS(cmsData: Uint8Array): Uint8Array {
  initializePKIEnvironment();

  const asn1Data = asn1js.fromBER(cmsData.buffer);
  if (asn1Data.offset === -1) {
    throw new Error("Failed to parse CMS: Invalid ASN.1 structure");
  }

  const contentInfo = new pkijs.ContentInfo({ schema: asn1Data.result });
  if (contentInfo.contentType !== CONSTANTS.CMS_SIGNED_DATA_OID) {
    throw new Error(`Unsupported CMS type: ${contentInfo.contentType}`);
  }

  const signedData = new pkijs.SignedData({ schema: contentInfo.content });
  const eContent = signedData.encapContentInfo.eContent;

  if (!eContent?.valueBlock?.valueHex) {
    throw new Error("CMS structure contains no content");
  }

  return new Uint8Array(eContent.valueBlock.valueHex);
}

/**
 * Extracts certificates from eContent
 * @param eContent - Decoded eContent data
 */
function extractCertificatesFromContent(
  eContent: Uint8Array,
): pkijs.Certificate[] {
  const asn1Content = asn1js.fromBER(eContent.buffer);
  if (asn1Content.offset === -1) {
    throw new Error("Failed to parse certificates: Invalid ASN.1 structure");
  }

  const certificates: pkijs.Certificate[] = [];
  const contentValue = asn1Content.result.valueBlock.value;

  if (contentValue && contentValue[1] instanceof asn1js.Set) {
    contentValue[1].valueBlock.value
      .filter((item): item is asn1js.Sequence =>
        item instanceof asn1js.Sequence
      )
      .forEach((sequence) => {
        const cert = new pkijs.Certificate({ schema: sequence });
        certificates.push(cert);
      });
  }

  return certificates;
}

/**
 * Removes duplicate certificates based on their fingerprints
 * @param certificates - Array of certificate data
 */

function deduplicateCertificates(
  certificates: pkijs.Certificate[],
): pkijs.Certificate[] {
  const uniqueCerts = new Map<string, pkijs.Certificate>();

  certificates.forEach((certificate) => {
    try {
      const fingerprint = encodeBase64(sha1(certificate.tbsView));
      uniqueCerts.set(fingerprint, certificate);
    } catch (error) {
      console.warn("Skipping invalid certificate:", error.message);
    }
  });

  return Array.from(uniqueCerts.values());
}

/**
 * Main function to extract and process certificates from LDIF file
 * @param ldifPath - Path to LDIF file
 * @throws Error if file extension is invalid or file operations fail
 */

export function certificatesFromLDIF(ldifPath: string): pkijs.Certificate[] {
  if (!ldifPath.endsWith(CONSTANTS.FILE_EXTENSION)) {
    throw new Error(
      `Invalid file type. Expected ${CONSTANTS.FILE_EXTENSION} file`,
    );
  }

  try {
    const ldifContent = Deno.readTextFileSync(ldifPath);
    const cmss = extractCMSFromLDIF(ldifContent);

    const certificates = cmss.flatMap((cms) => {
      const eContent = extractEContentFromCMS(cms);
      return extractCertificatesFromContent(eContent);
    });

    const turkishCerts = certificates.filter((cert) => {
      const countryValue = cert.subject.typesAndValues.find((tv) =>
        tv.type === "2.5.4.6"
      )?.value.valueBlock.value;
      return countryValue === "TR";
    });
    console.log(`Found ${turkishCerts.length} Turkish certificates`);

    return deduplicateCertificates(certificates);
  } catch (error) {
    throw new Error(`Failed to process LDIF file: ${error.message}`);
  }
}

/**
 * Serializes an array of certificates into a single Uint8Array using ASN.1 encoding
 * @param certificates - Array of certificates to serialize
 * @returns Uint8Array containing the serialized certificates
 */
export function serializeCertificates(
  certificates: pkijs.Certificate[],
): Uint8Array {
  // Create an ASN.1 SEQUENCE to hold all certificates
  const certSequence = new asn1js.Sequence({
    value: certificates.map((cert) => cert.toSchema()),
  });

  // Encode the sequence to DER format
  return new Uint8Array(certSequence.toBER(false));
}

/**
 * Deserializes a Uint8Array back into an array of certificates
 * @param serializedData - Uint8Array containing serialized certificates
 * @returns Array of Certificate objects
 * @throws Error if deserialization fails
 */
export function deserializeCertificates(
  serializedData: Uint8Array,
): pkijs.Certificate[] {
  try {
    // Parse the ASN.1 structure
    const asn1Data = asn1js.fromBER(serializedData.buffer);
    if (asn1Data.offset === -1) {
      throw new Error("Invalid ASN.1 structure");
    }

    // The root should be a SEQUENCE containing all certificates
    const sequence = asn1Data.result;
    if (!(sequence instanceof asn1js.Sequence)) {
      throw new Error("Expected ASN.1 SEQUENCE");
    }

    // Convert each value in the sequence back to a Certificate object
    return sequence.valueBlock.value.map((certSchema) =>
      new pkijs.Certificate({ schema: certSchema })
    );
  } catch (error) {
    throw new Error(`Failed to deserialize certificates: ${error.message}`);
  }
}

export function serializeCertificatesPEM(
  certificates: pkijs.Certificate[],
): string {
  return certificates.map(certificatePEM).join("\n");
}

if (import.meta.main) {
  try {
    if (Deno.args.length !== 1) {
      console.error("Usage: script.ts <ldif_file_path>");
      Deno.exit(1);
    }

    const inputFile = Deno.args[0];
    const certificates = certificatesFromLDIF(inputFile);
    console.log(
      `Successfully extracted ${certificates.length} unique certificates`,
    );

    const turkishCerts = certificates.filter((cert) => {
      const countryValue = cert.subject.typesAndValues.find((tv) =>
        tv.type === "2.5.4.6"
      )?.value.valueBlock.value;
      return countryValue === "TR";
    });
    console.log(`Found ${turkishCerts.length} Turkish certificates`);

    const outputFile = inputFile.replace(".ldif", ".der");
    Deno.writeFileSync(outputFile, serializeCertificates(certificates));
    Deno.writeTextFileSync(
      inputFile.replace(".ldif", ".pem"),
      serializeCertificatesPEM(certificates),
    );
    console.log(
      `Successfully have written ${outputFile}`,
    );
  } catch (error) {
    console.error("Error:", error.message);
    Deno.exit(1);
  }
}
