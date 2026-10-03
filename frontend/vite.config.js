import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // The backend (cd backend && python main.py) serves the API on port 8000.
  server: { proxy: { '/api': 'http://127.0.0.1:8000' } },
})
