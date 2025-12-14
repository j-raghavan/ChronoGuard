import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  // GitHub Pages repo name
  base: process.env.NODE_ENV === "production" ? "/ChronoGuard/" : "/",
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
})
