import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

/**
 * Resolve Supabase URL + anon key from common env names (Vercel often has
 * SUPABASE_URL + NEXT_PUBLIC_SUPABASE_ANON_KEY without VITE_ prefix).
 */
export default defineConfig(({ mode }) => {
  const fileEnv = loadEnv(mode, process.cwd(), "");
  const env = { ...fileEnv, ...process.env };

  const supabaseUrl =
    env.SUPABASE_URL ||
    env.VITE_SUPABASE_URL ||
    env.NEXT_PUBLIC_SUPABASE_URL ||
    "";
  const supabaseAnon =
    env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
    env.VITE_SUPABASE_ANON_KEY ||
    "";

  return {
  plugins: [react()],
  define: {
    __SOC_SUPABASE_URL__: JSON.stringify(supabaseUrl),
    __SOC_SUPABASE_ANON__: JSON.stringify(supabaseAnon),
  },
  envPrefix: ["VITE_", "NEXT_PUBLIC_"],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
        timeout: 0,
        proxyTimeout: 0,
        configure: (proxy) => {
          proxy.on("proxyRes", (proxyRes, req, res) => {
            if (
              proxyRes.headers["content-type"]?.includes("text/event-stream")
            ) {
              res.setHeader("X-Accel-Buffering", "no");
              res.setHeader("Cache-Control", "no-cache, no-transform");
              res.setHeader("Connection", "keep-alive");
              proxyRes.headers["cache-control"] = "no-cache, no-transform";
            }
          });
        },
      },
    },
  },
  };
});
