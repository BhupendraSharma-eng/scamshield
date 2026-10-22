import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Dev: proxy /api to the FastAPI backend. Prod: `bun run build` → dist/, served by FastAPI at /.
// GitHub Pages build sets VITE_BASE=/<repo>/ (see .github/workflows/pages.yml).
export default defineConfig({
  base: process.env.VITE_BASE ?? "/",
  plugins: [react(), tailwindcss()],
  server: {
    host: true,
    port: 5173,
    proxy: { "/api": "http://127.0.0.1:8000" },
  },
});
