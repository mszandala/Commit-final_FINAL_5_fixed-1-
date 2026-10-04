import { useEffect, useRef, useState } from 'react'
import { checkFile, readFile } from './ocr'

let nextId = 1

// Files in the composer, each read to text as soon as it's added.
// status: 'reading' (with percent), 'done' (with text) or 'error' (with the reason).
export function useAttachments() {
  const [files, setFiles] = useState([])
  const reads = useRef(new Map())

  useEffect(() => {
    const running = reads.current
    return () => running.forEach((read) => read.abort())
  }, [])

  const update = (id, change) => setFiles((prev) => prev.map((f) => (f.id === id ? { ...f, ...change } : f)))

  function add(list) {
    for (const file of list) {
      const id = nextId++
      const problem = checkFile(file)
      setFiles((prev) => [
        ...prev,
        { id, name: file.name, status: problem ? 'error' : 'reading', percent: 0, error: problem },
      ])
      if (problem) continue

      const read = new AbortController()
      reads.current.set(id, read)
      // Tesseract reports progress many times a second; re-render only when the whole percent changes.
      let percent = 0
      const onProgress = (progress) => {
        if (Math.floor(progress * 100) === percent) return
        percent = Math.floor(progress * 100)
        update(id, { percent })
      }
      readFile(file, { signal: read.signal, onProgress })
        .then((text) => update(id, { status: 'done', text }))
        .catch((e) => read.signal.aborted || update(id, { status: 'error', error: e.message }))
        .finally(() => reads.current.delete(id))
    }
  }

  function remove(id) {
    reads.current.get(id)?.abort()
    setFiles((prev) => prev.filter((f) => f.id !== id))
  }

  return { files, add, remove, clear: () => setFiles([]) }
}

// What the backend gets: the typed text, then each file's text under its name.
// It's all one message, so every control checks file text the same way as typed text.
export function composeMessage(text, files) {
  return [text.trim(), ...files.map((f) => `Text of the attached file "${f.name}":\n"""\n${f.text}\n"""`)]
    .filter(Boolean)
    .join('\n\n')
}
