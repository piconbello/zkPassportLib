import { decodeBase64, encodeBase64 } from "@std/encoding/base64";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { deserializeCertificates } from "./parseMasterlist.ts";
import { parseSodSimpler } from "../scripts/sodParser.ts";
import { encodeHex } from "@std/encoding";

function certFromSod(sodPath: string) {
  const sodBytes = Deno.readFileSync(sodPath);
  const result = parseSodSimpler(sodBytes);
  return result.certificate;
}

const OID_SUBJECT_KEY_IDENTIFIER = "2.5.29.14";
const OID_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";

function getAuthorityKeyIdentifier(certificate: pkijs.Certificate) {
  const authExt = certificate.extensions!.find((extension) =>
    extension.extnID === OID_AUTHORITY_KEY_IDENTIFIER
  )!;
  const aki = authExt.parsedValue as pkijs.AuthorityKeyIdentifier;
  const id = new Uint8Array(aki.keyIdentifier!.getValue());
  if (id.length === 0) {
    console.error(aki);
    throw new Error("auth key identifier is empty");
  }
  return id;
}

function getSubjectKeyIdentifier(
  certificate: pkijs.Certificate,
): Uint8Array | null {
  if (!certificate.extensions) {
    return null;
  }
  const subjIdExt = certificate.extensions.find((e) =>
    e.extnID == OID_SUBJECT_KEY_IDENTIFIER
  );
  if (!subjIdExt || !subjIdExt.parsedValue) {
    return null;
  }
  const id = new Uint8Array(subjIdExt.parsedValue.getValue());
  // if (id.length === 0) {
  //   console.log(subjIdExt);
  //   throw new Error("subj key identifier is empty");
  // }
  return id;
}

if (import.meta.main) {
  pkijs.setEngine(
    "newEngine",
    new pkijs.CryptoEngine({
      name: "",
      crypto: crypto,
      subtle: crypto.subtle,
    }),
  );

  const masterlistFile = "./certificates/icaopkd-002-complete-000284.der";
  const masterlistSerialized = Deno.readFileSync(masterlistFile);
  const masterCerts: pkijs.Certificate[] = deserializeCertificates(
    masterlistSerialized,
  );

  const leafCert: pkijs.Certificate = certFromSod("./certificates/halit-sod");
  const leafAuthId = getAuthorityKeyIdentifier(leafCert);
  console.log("leaf auth id", encodeHex(leafAuthId));
  const leafAuthIdB64 = encodeBase64(leafAuthId);
  console.log(leafCert.toSchema().toString());

  for (const masterCert of masterCerts) {
    const subjId = getSubjectKeyIdentifier(masterCert);
    if (!subjId) {
      continue;
    }
    const subjIdB64 = encodeBase64(subjId);
    if (leafAuthIdB64 === subjIdB64) {
      // console.log(encodeHex(subjId));
      console.log(masterCert.toSchema().toString());
      try {
        console.log(await leafCert.verify(masterCert));
      } catch (e) {
        console.log(false);
      }
    }
  }
  console.log("DONE");
  Deno.exit(0);

  const turkishCerts = masterCerts.filter((cert) => {
    const countryValue = cert.subject.typesAndValues.find((tv) =>
      tv.type === "2.5.4.6"
    )?.value.valueBlock.value;
    return countryValue === "TR";
  });
  // console.log(`Found ${turkishCerts.length} Turkish certificates`);
  // turkishCerts.forEach((cert, index) => {
  //   const subjectStr = cert.subject.typesAndValues
  //     .map((tv) => `${tv.type}:${tv.value.valueBlock.value}`)
  //     .join(",");
  //   console.log(`\nCertificate #${index}:`);
  //   console.log("Subject:", subjectStr);
  //   console.log("Valid from:", cert.notBefore.value);
  //   console.log("Valid to:", cert.notAfter.value);
  // });

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
  const leafIssuerStr = leafCert.issuer.typesAndValues
    .map((tv) => `${tv.type}:${tv.value.valueBlock.value}`)
    .join(",");
  console.log("Leaf Issuer:", leafIssuerStr);

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

    // Add these debug lines
    // console.log("\nComparing:");
    // console.log("Leaf Issuer:", leafIssuerStr);
    // console.log("Master Subject:", masterSubjectStr);

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

  console.log("HERHEREER");

  for (const masterCert of turkishCerts) {
    // Check if the certificate was valid when the leaf cert was issued
    const leafDate = leafCert.notBefore.value;
    const masterValidFrom = masterCert.notBefore.value;
    const masterValidTo = masterCert.notAfter.value;

    console.log(
      "\nTrying verification with certificate valid during leaf issuance:",
    );
    console.log("Master cert valid from:", masterValidFrom);
    console.log("Master cert valid to:", masterValidTo);

    try {
      const isValid = await leafCert.verify(masterCert);
      console.log("Signature verification:", isValid);
      if (isValid) {
        console.log("Found matching certificate!");
        // Print more details about the matching certificate
        const subjectStr = masterCert.subject.typesAndValues
          .map((tv) => `${tv.type}:${tv.value.valueBlock.value}`)
          .join(",");
        console.log("Matching certificate subject:", subjectStr);
        break;
      }
    } catch (error) {
      console.log("Verification failed:", error.message);
    }
  }

  console.log(
    "\nLeaf Certificate Authority Key Identifier:",
    leafCert.extensions?.find((ext) => ext.extnID === "2.5.29.35")
      ?.parsedValue.keyIdentifier.valueBlock.valueHex,
  );

  console.log("\nSearching for matching Turkish certificate...");
  turkishCerts.forEach((cert, index) => {
    const ski = cert.extensions?.find((ext) => ext.extnID === "2.5.29.14")
      ?.parsedValue.valueBlock.valueHex;

    if (ski === "7ce974a8510321722d50f4e90bd3f5ca3ecf822a") {
      console.log(`\nFound matching certificate #${index}!`);
      console.log("Valid from:", cert.notBefore.value);
      console.log("Valid to:", cert.notAfter.value);

      // Print additional details about this certificate
      const subjectStr = cert.subject.typesAndValues
        .map((tv) => `${tv.type}:${tv.value.valueBlock.value}`)
        .join(",");
      console.log("Subject:", subjectStr);
      console.log(
        "Public Key Algorithm:",
        cert.subjectPublicKeyInfo.algorithm.algorithmId,
      );
    }
  });
}
