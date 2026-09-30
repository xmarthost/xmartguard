import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    rollupOptions: {
      output: {
        // Libraries in their own files: they stay cached across portal updates.
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined;
          if (/[\\/]node_modules[\\/](?:recharts|d3-|victory-vendor|decimal\.js-light|es-toolkit|immer|reselect|redux|@reduxjs|react-redux|use-sync-external-store)/.test(id)) return 'charts';
          if (/[\\/]node_modules[\\/](?:react|react-dom|react-router|react-router-dom|scheduler)[\\/]/.test(id)) return 'react';
          if (/[\\/]node_modules[\\/]lucide-react[\\/]/.test(id)) return 'icons';
          return 'vendor';
        },
      },
    },
  },
  server: {
    proxy: {
      '/api': { target: 'http://localhost:8080', ws: true },
      '/install.sh': 'http://localhost:8080',
      '/uninstall.sh': 'http://localhost:8080',
      '/downloads': 'http://localhost:8080',
    },
  },
});
