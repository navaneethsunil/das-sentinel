import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Self-contained server bundle for the Docker runtime stage (no node_modules copy).
  output: "standalone",
};

export default nextConfig;
