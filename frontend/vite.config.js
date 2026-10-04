import { createReadStream, existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// OCR files served from our own origin under /ocr/, so reading attachments works without internet.
// Tesseract picks one of the three LSTM cores by browser support; pdf.js needs the cmaps and wasm decoders.
const OCR_FILES = {
  'tesseract/worker.min.js': 'tesseract.js/dist/worker.min.js',
  'tesseract/core/tesseract-core-lstm.wasm.js': 'tesseract.js-core/tesseract-core-lstm.wasm.js',
  'tesseract/core/tesseract-core-simd-lstm.wasm.js': 'tesseract.js-core/tesseract-core-simd-lstm.wasm.js',
  'tesseract/core/tesseract-core-relaxedsimd-lstm.wasm.js': 'tesseract.js-core/tesseract-core-relaxedsimd-lstm.wasm.js',
  'tesseract/lang/eng.traineddata.gz': '@tesseract.js-data/eng/4.0.0_best_int/eng.traineddata.gz',
  'tesseract/lang/pol.traineddata.gz': '@tesseract.js-data/pol/4.0.0_best_int/pol.traineddata.gz',
  'pdfjs/cmaps': 'pdfjs-dist/cmaps',
  'pdfjs/standard_fonts': 'pdfjs-dist/standard_fonts',
  'pdfjs/wasm': 'pdfjs-dist/wasm',
  'pdfjs/iccs': 'pdfjs-dist/iccs',
}

function ocrFiles() {
  const files = {}
  for (const [to, from] of Object.entries(OCR_FILES)) {
    const source = join('node_modules', from)
    if (!existsSync(source)) continue
    if (statSync(source).isDirectory()) {
      for (const name of readdirSync(source)) files[`ocr/${to}/${name}`] = join(source, name)
    } else {
      files[`ocr/${to}`] = source
    }
  }
  return files
}

function ocrAssets() {
  return {
    name: 'ocr-assets',
    configureServer(server) {
      const files = ocrFiles()
      server.middlewares.use((req, res, next) => {
        const source = files[decodeURIComponent(req.url.split('?')[0]).slice(1)]
        if (!source) return next()
        // Sent as plain bytes: Tesseract gunzips the language data itself.
        res.setHeader('Content-Type', source.endsWith('.js') ? 'text/javascript' : 'application/octet-stream')
        createReadStream(source).pipe(res)
      })
    },
    generateBundle() {
      for (const [fileName, source] of Object.entries(ocrFiles())) {
        this.emitFile({ type: 'asset', fileName, source: readFileSync(source) })
      }
    },
  }
}

export default defineConfig({
  plugins: [react(), tailwindcss(), ocrAssets()],
  // The backend (cd backend && python main.py) serves the API on port 8000.
  server: { proxy: { '/api': 'http://127.0.0.1:8000' } },
})
