import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  // The console is served under /ui/ by the Go binary; without this, the built
  // index.html requests /assets/... at the site root, which is the echo
  // endpoint, so the page loads blank.
  base: '/ui/',
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})
