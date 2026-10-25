import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react()],
  server: {
    // Same rule as the API: reachable from this machine only.
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: {
      // changeOrigin rewrites Host to 127.0.0.1:4000 so the API's Host check passes.
      // The Origin header is passed through untouched, so the CSRF check still applies.
      '/api': { target: 'http://127.0.0.1:4000', changeOrigin: true },
    },
  },
});
