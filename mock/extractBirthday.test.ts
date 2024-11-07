import { extractBirthdayTD3 } from "../src/zkDG1/common.ts";

import { assertEquals } from "jsr:@std/assert";
import { generateDG1, MRZOptions } from "./dg1.ts";
import { Bytes } from "o1js";

import { faker } from "@faker-js/faker";

Deno.test("Extract Birthday Test Suite", async (t) => {
  faker.seed(42);

  function generateAndExtract(options: MRZOptions = {}) {
    const dg1Out = generateDG1(options);
    const dg1 = Bytes.from(dg1Out.dg1);
    const [year, month, day] = extractBirthdayTD3(dg1);
    return {
      ...dg1Out,
      extracted: {
        year: Number(year.toString()),
        month: Number(month.toString()),
        day: Number(day.toString()),
      },
    };
  }

  await t.step("extracts specific birthday correctly, old person", () => {
    // Test with May 13, 1994
    const result = generateAndExtract({ dateOfBirth: "940513" });

    assertEquals(result.extracted.year, 94);
    assertEquals(result.extracted.month, 5);
    assertEquals(result.extracted.day, 13);
  });

  await t.step("extracts specific birthday correctly, young person", () => {
    // Test with May 13, 2003
    const result = generateAndExtract({ dateOfBirth: "030513" });

    assertEquals(result.extracted.year, 3);
    assertEquals(result.extracted.month, 5);
    assertEquals(result.extracted.day, 13);
  });

  await t.step("validates 100 random birthdays", () => {
    for (let i = 0; i < 100; i++) {
      const result = generateAndExtract();
      const dateStr = result.dateOfBirth; // Format: YYMMDD

      // Parse expected values
      const expectedYear = parseInt(dateStr.substring(0, 2));
      const expectedMonth = parseInt(dateStr.substring(2, 4));
      const expectedDay = parseInt(dateStr.substring(4, 6));

      // Verify extraction
      assertEquals(
        result.extracted.month,
        expectedMonth,
        `Month mismatch for date ${dateStr}`,
      );
      assertEquals(
        result.extracted.day,
        expectedDay,
        `Day mismatch for date ${dateStr}`,
      );

      assertEquals(
        result.extracted.year,
        expectedYear,
        `Year mismatch for date ${dateStr}`,
      );

      // Additional validation
      assertEquals(
        result.extracted.month >= 1 && result.extracted.month <= 12,
        true,
        `Invalid month: ${result.extracted.month}`,
      );
      assertEquals(
        result.extracted.day >= 1 && result.extracted.day <= 31,
        true,
        `Invalid day: ${result.extracted.day}`,
      );
    }
  });
});
