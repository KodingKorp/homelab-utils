import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri serves the dev server and bundles `dist/`. Fixed port so the Rust side can find it.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
    watch: {
      // Don't watch the Rust crate — Tauri handles rebuilding it.
      ignored: ["**/src-tauri/**"],
    },
  },
});
