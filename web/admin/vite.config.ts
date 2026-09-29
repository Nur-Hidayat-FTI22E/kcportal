import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` proxies /api to a locally-forwarded admin API
// (ssh -L 8083:127.0.0.1:8083 kotacloud-captive@...) so development
// never needs CORS or a deployed GUI. Production serves the built
// dist/ from the same origin as the API — no proxy involved.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8083",
    },
  },
  build: {
    // Emit straight into the Go embed package — internal/api/webadmin
    // carries //go:embed all:dist, so `npm run build` refreshes the
    // bundle the daemon compiles in (dist/ is committed; CI stays
    // Go-only).
    outDir: "../../internal/api/webadmin/dist",
    emptyOutDir: true,
    sourcemap: false,
  },
});
