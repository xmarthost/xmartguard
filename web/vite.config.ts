import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/api': { target: 'http://localhost:8080', ws: true },
      '/install.sh': 'http://localhost:8080',
      '/uninstall.sh': 'http://localhost:8080',
      '/downloads': 'http://localhost:8080',
    },
  },
});
