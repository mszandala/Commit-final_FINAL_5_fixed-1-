import { useState } from 'react'
import { ArrowUp } from 'lucide-react'

export default function Composer({ disabled, onSend }) {
  const [text, setText] = useState('')
  const canSend = !disabled && text.trim()

  function submit(e) {
    e.preventDefault()
    if (!canSend) return
    onSend(text.trim())
    setText('')
  }

  return (
    <form onSubmit={submit} className="rounded-md border border-line bg-white p-2 pl-3 focus-within:border-blue">
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
