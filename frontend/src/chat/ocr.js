import pdfWorkerUrl from 'pdfjs-dist/build/pdf.worker.min.mjs?url'

// Served by the ocr-assets plugin in vite.config.js. Absolute, since Tesseract loads them from a blob worker.
const ASSETS = new URL(`${import.meta.env.BASE_URL}ocr/`, location.href).href

const MAX_FILE_BYTES = 25 * 1024 * 1024
const MAX_PDF_PAGES = 30
// A page with less text than this in its text layer is a scan, so it goes through OCR.
const MIN_PAGE_TEXT = 40
// Specks and fragments come back as a few characters at middling confidence ("hyy =" at 70); those count as no text.
const NOISE_CHARS = 10
const NOISE_CONFIDENCE = 80
// Tesseract reads best at about 300 dpi; PDF units are 1/72 inch.
const PDF_SCALE = 300 / 72
const MAX_CANVAS_PIXELS = 16_000_000

export const ACCEPT = '.pdf,.png,.jpg,.jpeg,application/pdf,image/png,image/jpeg'

export class ReadError extends Error {}

function kindOf(file) {
  if (file.type === 'application/pdf' || /\.pdf$/i.test(file.name)) return 'pdf'
  if (['image/png', 'image/jpeg'].includes(file.type) || /\.(png|jpe?g)$/i.test(file.name)) return 'image'
  return null
}

// The reason a file can't be read, before trying.
export function checkFile(file) {
  if (!kindOf(file)) return 'Only PDF, JPG and PNG'
  if (file.size > MAX_FILE_BYTES) return 'Over 25 MB'
  if (file.size === 0) return 'Empty file'
  return null
}

let worker = null
// One Tesseract worker runs one job at a time, so jobs queue here and `report` belongs to the running one.
let queue = Promise.resolve()
let report = null

function getWorker() {
  worker ??= import('tesseract.js')
    .then(({ createWorker }) =>
      // English first: it decides ties between the two models.
      createWorker(['eng', 'pol'], 1, {
        workerPath: `${ASSETS}tesseract/worker.min.js`,
        corePath: `${ASSETS}tesseract/core`,
        langPath: `${ASSETS}tesseract/lang`,
        logger: (m) => m.status === 'recognizing text' && report?.(m.progress),
        // Failed jobs still reject their own promise; without this the worker also throws globally.
        errorHandler: () => {},
      }),
    )
    .catch(() => {
      worker = null
      throw new ReadError('Text recognition failed to start')
    })
  return worker
}

function recognize(canvas, signal, onProgress) {
  const job = queue.then(async () => {
    signal.throwIfAborted()
    const tesseract = await getWorker()
    report = onProgress
    try {
      const { text, confidence } = (await tesseract.recognize(canvas)).data
      return text.replace(/\s/g, '').length < NOISE_CHARS && confidence < NOISE_CONFIDENCE ? '' : text
    } finally {
      report = null
      // Lets the browser free the pixels straight away.
      canvas.width = 0
    }
  })
  queue = job.catch(() => {})
  return job
}

function whiteCanvas(width, height) {
  const canvas = document.createElement('canvas')
  canvas.width = Math.round(width)
  canvas.height = Math.round(height)
  const context = canvas.getContext('2d')
  // Transparent pixels would otherwise read as black, hiding dark text.
  context.fillStyle = '#fff'
  context.fillRect(0, 0, canvas.width, canvas.height)
  return { canvas, context }
}

async function readImage(file, signal, onProgress) {
  let bitmap
  try {
    // Applies the EXIF rotation of phone photos.
    bitmap = await createImageBitmap(file)
  } catch {
    throw new ReadError('Not a readable image')
  }
  const longest = Math.max(bitmap.width, bitmap.height)
  // Small screenshots are upscaled so letters are tall enough for Tesseract; huge photos are scaled down.
  const scale = Math.min(longest < 2000 ? Math.min(2, 2000 / longest) : 1, Math.sqrt(MAX_CANVAS_PIXELS / (bitmap.width * bitmap.height)))
  const { canvas, context } = whiteCanvas(bitmap.width * scale, bitmap.height * scale)
  context.imageSmoothingQuality = 'high'
  context.drawImage(bitmap, 0, 0, canvas.width, canvas.height)
  bitmap.close()
  return recognize(canvas, signal, onProgress)
}

async function readPdf(file, signal, onProgress) {
  const pdfjs = await import('pdfjs-dist')
  pdfjs.GlobalWorkerOptions.workerSrc = pdfWorkerUrl
  let pdf
  try {
    pdf = await pdfjs.getDocument({
      data: new Uint8Array(await file.arrayBuffer()),
      cMapUrl: `${ASSETS}pdfjs/cmaps/`,
      standardFontDataUrl: `${ASSETS}pdfjs/standard_fonts/`,
      wasmUrl: `${ASSETS}pdfjs/wasm/`,
      iccUrl: `${ASSETS}pdfjs/iccs/`,
      isEvalSupported: false,
    }).promise
  } catch (e) {
    throw new ReadError(e?.name === 'PasswordException' ? 'Password protected' : 'Not a readable PDF')
  }

  try {
    const pages = pdf.numPages
    if (pages > MAX_PDF_PAGES) throw new ReadError(`${pages} pages, up to ${MAX_PDF_PAGES}`)
    const texts = []
    for (let n = 1; n <= pages; n++) {
      signal.throwIfAborted()
      const page = await pdf.getPage(n)
      const { items } = await page.getTextContent()
      let text = items.map((item) => item.str + (item.hasEOL ? '\n' : '')).join('')
      if (text.replace(/\s/g, '').length < MIN_PAGE_TEXT) {
        const base = page.getViewport({ scale: 1 })
        const scale = Math.min(PDF_SCALE, Math.sqrt(MAX_CANVAS_PIXELS / (base.width * base.height)))
        const viewport = page.getViewport({ scale })
        const { canvas, context } = whiteCanvas(viewport.width, viewport.height)
        await page.render({ canvas, canvasContext: context, viewport }).promise
        text = await recognize(canvas, signal, (p) => onProgress((n - 1 + p) / pages))
      }
      page.cleanup()
      texts.push(text)
      onProgress(n / pages)
    }
    return texts.map(tidy).filter(Boolean).join('\n\n')
  } finally {
    pdf.destroy()
  }
}

const tidy = (text) =>
  text
    .replace(/\r\n?/g, '\n')
    .replace(/[ \t]+$/gm, '')
    .replace(/\n{3,}/g, '\n\n')
    .trim()

// The file's text: the PDF text layer where a page has one, OCR (English and Polish) for scans and images.
// `onProgress` gets 0 to 1. Rejects with ReadError (its message is shown to the user) or the signal's AbortError.
export async function readFile(file, { signal, onProgress }) {
  try {
    const text = tidy(
      kindOf(file) === 'pdf' ? await readPdf(file, signal, onProgress) : await readImage(file, signal, onProgress),
    )
    if (!text) throw new ReadError('No text found')
    return text
  } catch (e) {
    if (e instanceof ReadError || signal.aborted) throw e
    throw new ReadError('Could not read the file')
  }
}
