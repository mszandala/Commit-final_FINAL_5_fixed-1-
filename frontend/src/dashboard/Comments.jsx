import { useEffect, useState } from 'react'
import { Trash2 } from 'lucide-react'
import { addComment, deleteComment, getComments } from '../api'
import { refreshEvents } from '../events'
import Button from '../ui/Button'

// QA feedback on a saved conversation. Comments belong to the conversation; one added from a
// turn's row also remembers that turn.
export default function Comments({ conversationId, eventId }) {
  const [comments, setComments] = useState(null)
  const [text, setText] = useState('')
  const [failed, setFailed] = useState(false)

  async function load() {
    try {
      setComments(await getComments(conversationId))
    } catch {
      setComments([])
    }
  }

  useEffect(() => {
    load()
  }, [conversationId])

  // Reloads the list and the comment counts in the log table.
  async function change(action) {
    setFailed(false)
    try {
      await action()
      await load()
      refreshEvents()
      return true
    } catch {
      setFailed(true)
      return false
    }
  }

  async function submit(e) {
    e.preventDefault()
    if (!text.trim()) return
    if (await change(() => addComment(conversationId, { text, eventId }))) setText('')
  }

  return (
    <div className="mt-2.5 border-t border-line pl-3 pt-2.5 text-[13px]">
      <p className="mb-1.5 text-grey">Comments on this conversation</p>
      {comments?.length > 0 && (
        <ul className="mb-2 space-y-1">
          {comments.map((c) => (
            <li key={c.id} className="group flex items-baseline gap-2">
              <span className="shrink-0 text-grey">
                {c.author}, {new Date(c.time).toLocaleString('en-GB', { dateStyle: 'short', timeStyle: 'short' })}
                {c.eventId != null && `, turn #${c.eventId}`}
              </span>
              <span className="min-w-0 flex-1 whitespace-pre-wrap break-words text-ink">{c.text}</span>
              <button
                aria-label="Delete comment"
                onClick={() => change(() => deleteComment(c.id))}
                className="shrink-0 self-center text-grey opacity-0 hover:text-red-text focus:opacity-100 group-hover:opacity-100"
              >
                <Trash2 size={14} />
              </button>
            </li>
          ))}
        </ul>
      )}
      <form onSubmit={submit} className="flex items-start gap-2">
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={1}
          placeholder="Add a comment, for example what should have happened"
          aria-label="Comment"
          className="min-h-8 flex-1 resize-y rounded-md border border-line bg-white px-2.5 py-1.5 text-sm outline-none focus:border-blue"
        />
        <Button size="sm" type="submit" disabled={!text.trim()}>
          Add
        </Button>
      </form>
      {failed && <p className="mt-1 text-red-text">Could not save the change</p>}
    </div>
  )
}
