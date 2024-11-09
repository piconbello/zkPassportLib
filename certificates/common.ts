import { encodeBase64 } from "@std/encoding";
import * as pkijs from "pkijs";

export function certificatePEM(cert: pkijs.Certificate): string {
  // console.log(cert);
  const derBuffer = cert.toSchema().toBER(false);
  const der = new Uint8Array(derBuffer);
  const b64 = encodeBase64(der);
  const pemLines = b64.match(/.{1,64}/g) || [b64];
  // Add PEM header, body, and footer
  return [
    "-----BEGIN CERTIFICATE-----",
    ...pemLines,
    "-----END CERTIFICATE-----",
  ].join("\n");
}
