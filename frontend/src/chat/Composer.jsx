import { useRef, useState } from 'react'
import { ArrowUp, Paperclip } from 'lucide-react'
import Attachment from './Attachment'

export default function Composer({ disabled, onSend }) {
  const [text, setText] = useState('')
  const [files, setFiles] = useState([])
  const picker = useRef(null)
  // Files aren't sent yet (the API takes text only), so a message needs text.
  const canSend = !disabled && text.trim()

  function submit(e) {
    e.preventDefault()
    if (!canSend) return
    onSend(text.trim(), files)
    setText('')
    setFiles([])
  }

  function addFiles(e) {
    setFiles((prev) => [...prev, ...e.target.files])
    // Lets the same file be picked again after removing it.
    e.target.value = ''
  }

  return (
    <form
      onSubmit={submit}
      className="space-y-2 rounded-md border border-line bg-white p-2 pl-3 focus-within:border-blue"
    >
      {files.length > 0 && (
        <div className="flex flex-wrap gap-1.5 pt-1">
          {files.map((file, i) => (
            <Attachment
              key={`${file.name}-${i}`}
              file={file}
              onRemove={() => setFiles((prev) => prev.filter((_, j) => j !== i))}
            />
          ))}
        </div>
      )}
      <div className="flex items-end gap-1.5">
        <textarea
          rows={2}
          value={text}
          disabled={disabled}
          placeholder="Message"
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) submit(e)
          }}
          className="flex-1 resize-none bg-transparent py-1 placeholder:text-grey/60 focus:outline-none"
        />
        <input ref={picker} type="file" multiple hidden onChange={addFiles} />
        <button
          type="button"
          aria-label="Attach files"
          title="Mock: files aren't sent to the backend yet"
          disabled={disabled}
          onClick={() => picker.current.click()}
          className="grid size-8 place-items-center rounded-md text-red-text hover:bg-page disabled:opacity-40"
        >
          <Paperclip size={16} />
        </button>
        <button
          type="submit"
          aria-label="Send"
          disabled={!canSend}
          className="grid size-8 place-items-center rounded-md bg-navy text-white disabled:bg-line disabled:text-grey"
        >
          <ArrowUp size={16} />
        </button>
      </div>
    </form>
  )
}
