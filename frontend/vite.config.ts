import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  // GitHub Pages repo name (only for demo build)
  base: process.env.VITE_USE_MOCK_API === "true" ? "/ChronoGuard/" : "/",
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
})
