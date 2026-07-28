import { defineConfig } from "vite";
import path from "node:path";

// Framework-less TS/JS chat UI: public/index.html is the vite root, src/ is
// referenced from it via a relative script tag. `pnpm build` emits dist/.
export default defineConfig({
  root: path.resolve(__dirname, "public"),
  build: {
    outDir: path.resolve(__dirname, "dist"),
    emptyOutDir: true,
  },
});
