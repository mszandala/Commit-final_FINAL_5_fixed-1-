import { useEffect, useId, useRef, useState } from 'react'
import { Check, X } from 'lucide-react'
import { formatNumber } from '../format'
import { fold } from './search'

// Who the report covers: a chip per person, added by typing a name or role and picking from the
// list. No chips means everyone. The list stays open while picking, so several people go in one
// go; clicking a picked person again takes them out. Backspace in the empty box drops the last chip.
// `counts` is turns per user in the report's period, shown beside each name.
//
// The box stays one line high: chips scroll sideways (wheel or trackpad), and adding one scrolls to
// the end so the input stays in view. The list shows at most MAX_SHOWN people; typing narrows it.
const MAX_SHOWN = 8

export default function PeoplePicker({ people, selected, onChange, counts }) {
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const box = useRef(null)
  const strip = useRef(null)
  const input = useRef(null)
  const listId = useId()

  const q = fold(query.trim())
  const matches = people.filter((p) => !q || fold(`${p.user} ${p.role}`).includes(q))
  const shown = matches.slice(0, MAX_SHOWN)
  const current = Math.min(active, shown.length - 1)

  const toEnd = () => {
    strip.current.scrollLeft = strip.current.scrollWidth
  }
  useEffect(toEnd, [selected.length])

  useEffect(() => {
    if (!open) return
    const onPointer = (e) => !box.current.contains(e.target) && setOpen(false)
    document.addEventListener('mousedown', onPointer)
    return () => document.removeEventListener('mousedown', onPointer)
  }, [open])

  const toggle = (user) => {
    onChange(selected.includes(user) ? selected.filter((u) => u !== user) : [...selected, user])
    setQuery('')
    setActive(0)
  }

  const onKeyDown = (e) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault()
      setOpen(true)
      if (shown.length) setActive((current + (e.key === 'ArrowDown' ? 1 : shown.length - 1)) % shown.length)
    } else if (e.key === 'Enter') {
      e.preventDefault()
      if (open && shown[current]) toggle(shown[current].user)
    } else if (e.key === 'Escape') {
      setOpen(false)
    } else if (e.key === 'Backspace' && !query && selected.length) {
      onChange(selected.slice(0, -1))
    }
  }

  const byUser = Object.fromEntries(people.map((p) => [p.user, p]))

  return (
    <div ref={box} className="relative w-[28rem] max-w-full shrink">
      <div
        onMouseDown={(e) => {
          // Clicks on the box's empty space land in the input, without stealing them from chips.
          if (e.target === e.currentTarget || e.target === strip.current) {
            e.preventDefault()
            input.current.focus()
            setOpen(true)
          }
        }}
        className="flex h-[34px] cursor-text items-center gap-1 rounded-md border border-line bg-white px-1 focus-within:border-blue"
      >
        <div
          ref={strip}
          // A mouse wheel scrolls the chips sideways; a trackpad already does.
          onWheel={(e) => {
            if (!e.deltaX) strip.current.scrollLeft += e.deltaY
          }}
          className="flex min-w-0 flex-1 items-center gap-1 overflow-x-auto [scrollbar-width:none]"
        >
          {selected.map((user) => (
            <span
              key={user}
              className="inline-flex shrink-0 items-center gap-0.5 whitespace-nowrap rounded-sm bg-blue-light/60 py-0.5 pl-2 pr-0.5 text-sm text-ink"
              title={byUser[user] ? `${user}, ${byUser[user].role}` : user}
            >
              <span className="max-w-48 truncate">{user}</span>
              <button
                onClick={() => toggle(user)}
                aria-label={`Remove ${user}`}
                className="grid size-5 place-items-center rounded-sm text-grey hover:bg-white/70 hover:text-ink"
              >
                <X size={12} />
              </button>
            </span>
          ))}
          <input
            ref={input}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value)
              setActive(0)
              setOpen(true)
            }}
            onFocus={() => {
              setOpen(true)
              toEnd()
            }}
            onKeyDown={onKeyDown}
            // Tabbing away closes the list; clicks on it keep the focus here.
            onBlur={() => setOpen(false)}
            placeholder={selected.length ? 'Add people' : 'All users'}
            aria-label="People in the report"
            role="combobox"
            aria-expanded={open}
            aria-controls={listId}
            aria-activedescendant={open && shown[current] ? `${listId}-${current}` : undefined}
            spellCheck={false}
            autoComplete="off"
            className="h-6 min-w-24 flex-1 bg-transparent px-1.5 text-sm outline-none placeholder:text-grey/60"
          />
        </div>
        {selected.length > 0 && (
          <button
            onClick={() => {
              onChange([])
              input.current.focus()
            }}
            aria-label="Remove everyone, report on all users"
            title="Back to all users"
            className="grid size-6 shrink-0 place-items-center rounded-sm text-grey hover:bg-page hover:text-ink"
          >
            <X size={14} />
          </button>
        )}
      </div>
      {open && (
        <ul
          id={listId}
          role="listbox"
          aria-multiselectable
          className="absolute left-0 top-full z-20 mt-1.5 w-full rounded-md border border-line bg-white py-1 shadow-sm"
        >
          {shown.map((p, i) => {
            const picked = selected.includes(p.user)
            return (
              <li
                key={p.user}
                id={`${listId}-${i}`}
                role="option"
                aria-selected={picked}
                // Keeps focus in the input, so typing and arrows carry on after a click.
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => toggle(p.user)}
                onMouseMove={() => i !== current && setActive(i)}
                className={`flex cursor-pointer items-baseline gap-2.5 px-2.5 py-1.5 text-sm ${i === current ? 'bg-page' : ''}`}
              >
                <Check size={14} className={`shrink-0 self-center ${picked ? 'text-navy' : 'invisible'}`} />
                <span className="min-w-0 truncate" title={p.user}>
                  {p.user}
                </span>
                <span className="max-w-[40%] shrink-0 truncate text-[13px] text-grey">{p.role}</span>
                <span className="ml-auto shrink-0 text-[13px] tabular-nums text-grey" title="Turns in this period">
                  {counts[p.user] ? formatNumber(counts[p.user]) : <>&ndash;</>}
                </span>
              </li>
            )
          })}
          {shown.length === 0 && <li className="px-2.5 py-1.5 text-sm text-grey">No one matches</li>}
          {matches.length > shown.length && (
            <li className="border-t border-line px-2.5 pb-0.5 pt-1.5 text-[13px] text-grey">
              {formatNumber(matches.length - shown.length)} more
            </li>
          )}
        </ul>
      )}
    </div>
  )
}
