import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// `npm run dev` serves the UI on :5173 and proxies /api to `wrangler pages dev` on :8788
// (run `npm run build && npm run dev:api` in a second terminal for a working API).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { proxy: { '/api': 'http://127.0.0.1:8788' } },
  build: { target: 'es2022', sourcemap: false },
});
