import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The Python server (easyhunt dashboard --serve) owns /api/state on :8765.
// In dev mode, vite runs on :5173 and proxies API + report fetches there so
// `npm run dev` works against a running backend unchanged.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8765",
      "/reports": "http://127.0.0.1:8765",
    },
  },
  build: {
    outDir: "dist",
    target: "es2020",
  },
});
