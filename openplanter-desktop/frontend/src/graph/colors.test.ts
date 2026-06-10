import { describe, it, expect } from "vitest";
import { CATEGORY_COLORS, getCategoryColor } from "./colors";

describe("CATEGORY_COLORS", () => {
  it("has all expected categories", () => {
    const expected = [
      "registries",
      "advisories",
      "code-search",
      "threat-intel",
      "scanners",
    ];
    for (const cat of expected) {
      expect(CATEGORY_COLORS[cat]).toBeDefined();
    }
  });

  it("all values are hex colors", () => {
    for (const [, color] of Object.entries(CATEGORY_COLORS)) {
      expect(color).toMatch(/^#[0-9a-f]{6}$/i);
    }
  });
});

describe("getCategoryColor", () => {
  it("returns correct color for known category", () => {
    expect(getCategoryColor("code-search")).toBe("#79c0ff");
    expect(getCategoryColor("registries")).toBe("#56d364");
    expect(getCategoryColor("threat-intel")).toBe("#f97583");
  });

  it("returns default gray for unknown category", () => {
    expect(getCategoryColor("unknown")).toBe("#8b949e");
    expect(getCategoryColor("")).toBe("#8b949e");
    expect(getCategoryColor("foobar")).toBe("#8b949e");
  });
});
