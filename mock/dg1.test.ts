import { assertEquals } from "jsr:@std/assert";
import { generateDG1, MRZOptions } from "./dg1.ts";
import { parse as parseMRZ } from "mrz";
import { faker } from "@faker-js/faker";

Deno.test("Fuzzy MRZ Testing Suite", async (t) => {
  faker.seed(42);
  function generate(options: MRZOptions = {}) {
    const dg1Out = generateDG1(options);
    const mrzSingleLine = new TextDecoder().decode(dg1Out.dg1.slice(5));
    const mrzDoubleLine = mrzSingleLine.slice(0, 44) + "\n" +
      mrzSingleLine.slice(44);
    return { ...dg1Out, parsed: parseMRZ(mrzDoubleLine) };
  }

  await t.step("generates 100 valid DG1s", () => {
    for (let i = 0; i < 100; i++) {
      generate();
    }
  });

  await t.step("validates date of birth format and parsing", () => {
    // Test with specific date
    const specificDOB = "940513"; // May 13, 1994
    const result = generate({ dateOfBirth: specificDOB });

    // Check if the generated DOB matches input
    assertEquals(
      result.dateOfBirth,
      specificDOB,
      "Generated DOB should match input DOB",
    );

    // Check if parsed DOB matches input
    assertEquals(
      result.parsed.fields.birthDate,
      specificDOB,
      "Parsed DOB should match input DOB",
    );

    // Test 100 random generations
    for (let i = 0; i < 100; i++) {
      const randomResult = generate();

      // Verify DOB format
      const dobRegex = /^\d{6}$/;
      assertEquals(
        dobRegex.test(randomResult.dateOfBirth),
        true,
        "DOB should be 6 digits",
      );

      // Verify parsed DOB matches generated DOB
      assertEquals(
        randomResult.parsed.fields.birthDate,
        randomResult.dateOfBirth,
        "Parsed DOB should match generated DOB",
      );

      // Verify month is between 01-12
      const month = parseInt(randomResult.dateOfBirth.substring(2, 4));
      assertEquals(
        month >= 1 && month <= 12,
        true,
        `Month should be between 1-12, got ${month}`,
      );

      // Verify day is between 01-31
      const day = parseInt(randomResult.dateOfBirth.substring(4, 6));
      assertEquals(
        day >= 1 && day <= 31,
        true,
        `Day should be between 1-31, got ${day}`,
      );
    }
  });
});
