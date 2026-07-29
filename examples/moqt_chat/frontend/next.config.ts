import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // The app is fully client-side, so a static export (out/) is enough; the
  // justfile's serve-frontend recipe serves it over TLS.
  output: "export",
};

export default nextConfig;
