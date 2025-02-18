import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import path from "path"
import basicSsl from '@vitejs/plugin-basic-ssl'


// https://vitejs.dev/config/
export default defineConfig({

  plugins: [react(), basicSsl({
    /** name of certification */
    name: 'test',
    /** custom trust domains */
    domains: ['*.custom.com'],
    /** custom certification directory */
    certDir: '../certs'
  })],
  resolve: {
    alias: {
      //@ts-ignore
      "@": path.resolve(__dirname, "./src"),
    },
  },
})
