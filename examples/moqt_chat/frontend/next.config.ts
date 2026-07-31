import type { NextConfig } from "next";

// GitHub Pages serves this repo's Pages site at /wired/, with docs.yml's
// Doxygen output at its root -- so this app's own build lives under the
// /wired/moqt_chat/ subpath there. NEXT_PUBLIC_BASE_PATH is unset (empty
// basePath, root-relative assets) for every other consumer of `out/`
// (justfile's serve-frontend, e2e/run.sh, `next dev`), and is set to
// /wired/moqt_chat only by the docs.yml Pages build.
const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "";

const nextConfig: NextConfig = {
  // The app is fully client-side, so a static export (out/) is enough; the
  // justfile's serve-frontend recipe serves it over TLS.
  output: "export",
  basePath,
};

export default nextConfig;
