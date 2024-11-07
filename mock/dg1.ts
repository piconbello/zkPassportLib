import { faker } from "@faker-js/faker";
import { encodeBase64 } from "@std/encoding/base64";
import countries from "i18n-iso-countries";
import en from "i18n-iso-countries/langs/en.json" with { type: "json" };
countries.registerLocale(en);

const ALL_COUNTRY_CODES = Object.keys(countries.getAlpha3Codes());

export interface MRZOptions {
  name?: string;
  surname?: string;
  passportNumber?: string;
  nationality?: string; // ISO 3166-1 alpha-3
  dateOfBirth?: string; // YYMMDD
  sex?: "M" | "F";
  expirationDate?: string; // YYMMDD
  personalNumber?: string;
  countryCode?: string; // ISO 3166-1 alpha-3
}

export interface DG1Output {
  name: string;
  surname: string;
  passportNumber: string;
  nationality: string; // ISO 3166-1 alpha-3
  dateOfBirth: string; // YYMMDD
  sex: "M" | "F";
  expirationDate: string; // YYMMDD
  personalNumber: string;
  countryCode: string; // ISO 3166-1 alpha-3
  mrz: string;
  dg1: Uint8Array;
}

export function generateDG1(opt: MRZOptions = {}): DG1Output {
  function calculateCheckDigit(str: string): string {
    const weights = [7, 3, 1];
    let sum = 0;

    for (let i = 0; i < str.length; i++) {
      const char = str[i];
      const value = char >= "0" && char <= "9"
        ? parseInt(char)
        : char === "<"
        ? 0
        : char.charCodeAt(0) - 55; // A=10, B=11, etc.
      sum += value * weights[i % 3];
    }

    return (sum % 10).toString();
  }

  function padRight(str: string, length: number): string {
    return (str + "<".repeat(length)).slice(0, length);
  }

  function sanitizeName(str: string): string {
    return str.toUpperCase()
      .replace(/[^A-Z\s]/g, "") // Keep spaces for now
      .trim();
  }

  // Generate or use provided data
  const name = sanitizeName(opt.name || faker.person.firstName());
  const surname = sanitizeName(opt.surname || faker.person.lastName());
  const passportNumber =
    (opt.passportNumber || faker.string.alphanumeric({ length: 9 }))
      .toUpperCase();
  const nationality = (opt.nationality ||
    faker.helpers.arrayElement(ALL_COUNTRY_CODES)).toUpperCase();
  const dob = opt.dateOfBirth ||
    faker.date.birthdate({ min: 10, max: 85, mode: "age" })
      .toISOString().slice(2, 10).replace(/-/g, "");
  const sex = opt.sex || faker.helpers.arrayElement(["M", "F"]);
  const expDate = opt.expirationDate || faker.date.future()
    .toISOString().slice(2, 10).replace(/-/g, "");
  const personalNumber = padRight(
    (opt.personalNumber || faker.string.alphanumeric({ length: 14 }))
      .toUpperCase(),
    14,
  );
  const countryCode = (opt.countryCode || opt.nationality ||
    faker.helpers.arrayElement(ALL_COUNTRY_CODES)).toUpperCase();

  // Format name field (39 characters total)
  const formattedName = name.replace(/\s+/g, "<");
  const formattedSurname = surname.replace(/\s+/g, "<");
  const nameField = padRight(`${formattedSurname}<<${formattedName}`, 39);

  // Build the MRZ lines (ensure exactly 44 characters per line)
  const line1 = `P<${countryCode}${nameField}`.slice(0, 44);

  // Build document number with check digit
  const docNumberCheck = calculateCheckDigit(passportNumber);
  const dobCheck = calculateCheckDigit(dob);
  const expDateCheck = calculateCheckDigit(expDate);
  const personalNumberCheck = calculateCheckDigit(personalNumber);

  // Final check digit calculation - corrected to match the expected output
  const finalCheckStr =
    `${passportNumber}${docNumberCheck}${nationality}${dob}${dobCheck}${sex}${expDate}${expDateCheck}${personalNumber}${personalNumberCheck}`;
  const finalCheck = calculateCheckDigit(finalCheckStr);

  const line2 =
    `${passportNumber}${docNumberCheck}${nationality}${dob}${dobCheck}${sex}${expDate}${expDateCheck}${personalNumber}${personalNumberCheck}${finalCheck}`;

  // Combine into final MRZ
  const mrz = `${line1}${line2}`;

  // Convert to byte array (for DG1 format)
  const mrzBytes = new TextEncoder().encode(mrz);

  // Create DG1 structure with proper tags
  const tag = new Uint8Array([0x61]); // Tag for DG1
  const subTag = new Uint8Array([0x5F, 0x1F]); // Sub-tag for MRZ data
  const mrzLength = new Uint8Array([mrzBytes.length]);
  const totalLength = new Uint8Array([mrzBytes.length + 3]); // +3 for subtag and length

  // Combine all parts
  const dg1 = new Uint8Array([
    ...tag,
    ...totalLength,
    ...subTag,
    ...mrzLength,
    ...mrzBytes,
  ]);

  return {
    name,
    surname,
    passportNumber,
    nationality,
    dateOfBirth: dob,
    sex,
    expirationDate: expDate,
    personalNumber,
    countryCode,
    mrz: `${line1}\n${line2}`,
    dg1,
  };
}

if (import.meta.main) {
  const got = generateDG1();
  console.log(got);
  console.log(got.mrz.slice(0, 44) + got.mrz.slice(45));
  console.log(encodeBase64(got.dg1));
}
