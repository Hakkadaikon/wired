import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
  server: {
    fs: {
      // golden vectors live outside this package, in ../testvectors.
      allow: [path.resolve(__dirname, ".."), path.resolve(__dirname)],
    },
  },
  test: {
    environment: "node",
  },
});
