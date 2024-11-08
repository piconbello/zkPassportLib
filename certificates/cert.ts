import { decodeBase64, encodeBase64 } from "@std/encoding/base64";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { deserializeCertificates } from "./parseMasterlist.ts";
import { parseSodSimpler } from "../scripts/sodParser.ts";

function certFromSod(sodPath: string) {
  const sodBytes = Deno.readFileSync(sodPath);
  const result = parseSodSimpler(sodBytes);
  return result.certificate;
}

if (import.meta.main) {
  const masterlistFile = "./certificates/icaopkd-002-complete-000288.der";
  const masterlistSerialized = Deno.readFileSync(masterlistFile);
  const masterCerts: pkijs.Certificate[] = deserializeCertificates(
    masterlistSerialized,
  );

  const leafCert: pkijs.Certificate = certFromSod("./certificates/ege-sod");

  // Set up the crypto engine
  pkijs.setEngine(
    "newEngine",
    new pkijs.CryptoEngine({
      name: "",
      crypto: crypto,
      subtle: crypto.subtle,
    }),
  );

  console.log("Leaf Certificate Details:");
  console.log("Valid from:", leafCert.notBefore.value);
  console.log("Valid to:", leafCert.notAfter.value);
  console.log("Signature Algorithm:", leafCert.signatureAlgorithm.algorithmId);
  console.log(
    "Public Key Algorithm:",
    leafCert.subjectPublicKeyInfo.algorithm.algorithmId,
  );

  // Try to get curve information from leaf certificate
  try {
    const leafParams = leafCert.subjectPublicKeyInfo.algorithm.algorithmParams;
    if (leafParams) {
      const curveOid = leafParams.valueBlock.toString();
      console.log("Leaf Certificate Curve OID:", curveOid);
    }
  } catch (e) {
    console.log("Couldn't extract leaf certificate curve info");
  }

  for (let i = 0; i < masterCerts.length; i++) {
    const masterCert = masterCerts[i];
    const masterSubjectStr = masterCert.subject.typesAndValues
      .map((tv) => `${tv.type}:${tv.value.valueBlock.value}`)
      .join(",");

    const leafIssuerStr = leafCert.issuer.typesAndValues
      .map((tv) => `${tv.type}:${tv.value.valueBlock.value}`)
      .join(",");

    if (leafIssuerStr === masterSubjectStr) {
      console.log("\nFound potential matching certificate #", i);
      console.log("Valid from:", masterCert.notBefore.value);
      console.log("Valid to:", masterCert.notAfter.value);
      console.log(
        "Signature Algorithm:",
        masterCert.signatureAlgorithm.algorithmId,
      );
      console.log(
        "Public Key Algorithm:",
        masterCert.subjectPublicKeyInfo.algorithm.algorithmId,
      );

      // Try to get curve information
      try {
        const params =
          masterCert.subjectPublicKeyInfo.algorithm.algorithmParams;
        if (params) {
          const curveOid = params.valueBlock.toString();
          console.log("Curve OID:", curveOid);

          // Map well-known curve OIDs
          const curveMap = {
            "1.2.840.10045.3.1.7": "P-256",
            "1.3.132.0.34": "P-384",
            "1.3.132.0.35": "P-521",
          };
          console.log("Curve Name:", curveMap[curveOid] || "Unknown");
        }
      } catch (e) {
        console.log("Couldn't extract curve info");
      }

      // Only try to verify if the certificate is valid at the time the leaf cert was issued
      const leafDate = leafCert.notBefore.value;
      const masterValidFrom = masterCert.notBefore.value;
      const masterValidTo = masterCert.notAfter.value;

      if (leafDate >= masterValidFrom && leafDate <= masterValidTo) {
        console.log("Certificate was valid when leaf cert was issued");
        try {
          const isValid = await leafCert.verify(masterCert);
          console.log("Signature verification:", isValid);
          if (isValid) {
            console.log("This is the correct signing certificate!");
            break;
          }
        } catch (error) {
          console.log("Verification failed:", error.message);
        }
      } else {
        console.log("Certificate was NOT valid when leaf cert was issued");
      }
    }
  }
}
