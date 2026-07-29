import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
  resolve: {
    alias: { "@": path.resolve(__dirname, "src") },
  },
  server: {
    fs: {
      // golden vectors live outside this package, in ../testvectors.
      allow: [path.resolve(__dirname, ".."), path.resolve(__dirname)],
    },
  },
  test: {
    environment: "jsdom",
  },
});
