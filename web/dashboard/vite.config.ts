import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The build lands in the Go package that embeds it. Everything is emitted as
// separate files (no inline script or style): the server's CSP forbids both.
export default defineConfig({
  plugins: [react()],
  base: "./",
  build: {
    outDir: "../../internal/dashboard/dist",
    emptyOutDir: true,
    sourcemap: false,
    target: "es2022",
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
  },
});
