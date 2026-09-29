import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// __TERMS_VERSION__ is injected at build time (see package.json build
// script) — it must match portaledge's portal.Service.TermsVersion so
// the consent audit trail references the same terms the guest saw.
export default defineConfig({
  plugins: [react()],
  define: {
    __TERMS_VERSION__: JSON.stringify("2026-09"),
  },
  build: {
    // Emit straight into the Go embed package (portaledge's captive
    // page): npm run build refreshes the bundle the daemon compiles in.
    outDir: "src/webportal/dist",
    emptyOutDir: true,
    sourcemap: false,
  },
});
