import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The dev server proxies the admin API so `npm run dev` works against the live
// backend with no CORS handling. Reviewers never run this: they get the built
// output served by Spring Boot from the same origin.
export default defineConfig({
  // The built output is served by Spring Boot from /dashboard/, so asset URLs
  // in index.html have to carry that prefix. Getting this wrong produces a
  // blank page with 404s rather than a build failure.
  base: '/dashboard/',
  plugins: [react()],
  server: {
    proxy: {
      '/internal': 'http://localhost:8080',
    },
  },
});
