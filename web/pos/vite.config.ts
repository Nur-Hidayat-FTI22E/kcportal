import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    // Emit straight into the Go embed package served by pos-cafe.
    outDir: "../../internal/pos/web/dist",
    emptyOutDir: true,
    sourcemap: false,
  },
});
