import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
    // Vendor copy of @jitsi/rnnoise-wasm's dist/rnnoise-sync.js (worklets
    // cannot `import`, so this is fetched as text at runtime) -- not our
    // code to lint.
    "public/worklets/rnnoise-sync.js",
  ]),
]);

export default eslintConfig;
