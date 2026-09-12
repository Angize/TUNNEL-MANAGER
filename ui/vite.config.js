import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const api = process.env.TNL_API || 'http://127.0.0.1:8099'

export default defineConfig({
  plugins: [react()],
  base: '/',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    assetsDir: 'assets',
    sourcemap: false,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: api, changeOrigin: false },
    },
  },
})
