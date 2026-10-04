import { useLayoutEffect, useRef, useState } from 'react'
import { ArrowUp, Paperclip, Ruler } from 'lucide-react'
import { formatNumber } from '../format'
import { useMeta } from '../meta'
import Attachment from './Attachment'
import { composeMessage } from './attachments'
import { ACCEPT } from './ocr'

const LENGTH_WARNING = 0.8

// `attachments` comes from useAttachments in Chat, which also takes files dropped anywhere on the chat.
export default function Composer({ disabled, onSend, attachments, dragging }) {
  // MAX_PROMPT_CHARS in the backend; a backend that doesn't send it has no limit here.
  const { maxPromptChars = Infinity } = useMeta()
  const [text, setText] = useState('')
  const box = useRef(null)
  const picker = useRef(null)
  const { files } = attachments
  const read = files.filter((f) => f.status === 'done')
  const length = composeMessage(text, read).length
  const reading = files.some((f) => f.status === 'reading')
  const failed = files.some((f) => f.status === 'error')
  const tooLong = length > maxPromptChars
  const canSend = !disabled && !reading && !failed && !tooLong && (text.trim() || read.length > 0)

  // Grows with the text up to eight lines, then scrolls.
  useLayoutEffect(() => {
    const fit = () => {
      box.current.style.height = 'auto'
      box.current.style.height = `${box.current.scrollHeight}px`
    }
    fit()
    window.addEventListener('resize', fit)
    return () => window.removeEventListener('resize', fit)
  }, [text])

  function submit(e) {
    e.preventDefault()
    if (!canSend) return
    onSend(text.trim(), read)
    setText('')
    attachments.clear()
  }

  function paste(e) {
    if (!e.clipboardData.files.length) return
    e.preventDefault()
    attachments.add(e.clipboardData.files)
  }

  function pick(e) {
    attachments.add(e.target.files)
    // Lets the same file be picked again after removing it.
    e.target.value = ''
  }

  return (
    <>
      {length >= maxPromptChars * LENGTH_WARNING && (
        <p className={`flex items-center gap-1.5 text-[13px] ${tooLong ? 'text-red-text' : 'text-amber-text'}`}>
          <Ruler size={14} />
          {tooLong ? 'Too long: ' : ''}
          {formatNumber(length)} of {formatNumber(maxPromptChars)} characters
        </p>
      )}
      <form
        onSubmit={submit}
        className={`space-y-2 rounded-md border bg-white p-2 pl-3 focus-within:border-blue ${dragging ? 'border-blue' : 'border-line'}`}
      >
        {files.length > 0 && (
          <div className="flex flex-wrap gap-1.5 pt-1">
            {files.map((file) => (
              <Attachment key={file.id} file={file} onRemove={() => attachments.remove(file.id)} />
            ))}
          </div>
        )}
        <div className="flex items-end gap-1.5">
          <textarea
            ref={box}
            rows={2}
            value={text}
            disabled={disabled}
            placeholder="Message"
            onChange={(e) => setText(e.target.value)}
            onPaste={paste}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) submit(e)
            }}
            className="max-h-[calc(8lh+0.5rem)] flex-1 resize-none bg-transparent py-1 placeholder:text-grey/60 focus:outline-none"
          />
          <input ref={picker} type="file" accept={ACCEPT} multiple hidden onChange={pick} />
          <button
            type="button"
            aria-label="Attach PDF or image"
            title="Attach PDF, JPG or PNG"
            disabled={disabled}
            onClick={() => picker.current.click()}
            className="grid size-8 place-items-center rounded-md text-grey hover:bg-page hover:text-ink disabled:opacity-40"
          >
            <Paperclip size={16} />
          </button>
          <button
            type="submit"
            aria-label="Send"
            title={reading ? 'Still reading the files' : failed ? 'Remove the files that could not be read' : undefined}
            disabled={!canSend}
            className="grid size-8 place-items-center rounded-md bg-navy text-white disabled:bg-line disabled:text-grey"
          >
            <ArrowUp size={16} />
          </button>
        </div>
      </form>
    </>
  )
}
