import { expect, test } from "vitest";

test("vitest runs in a jsdom environment", () => {
  expect(typeof document).toBe("object");
  expect(document.createElement("div").tagName).toBe("DIV");
});
