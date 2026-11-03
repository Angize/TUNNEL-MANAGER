import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const api = process.env.TNL_API || 'http://127.0.0.1:8080'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': { target: api },
    },
  },
})
