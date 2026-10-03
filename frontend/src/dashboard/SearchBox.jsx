import { useId, useRef } from 'react'
import { Search } from 'lucide-react'
import { tokenize } from './search'

const COLORS = {
  field: 'text-violet',
  op: 'text-violet',
  number: 'text-amber-text',
  range: 'text-amber-text',
  quoted: 'text-green-text',
  regex: 'text-green-text',
  bool: 'text-navy',
  not: 'text-navy',
  paren: 'text-grey',
  unknown: 'text-red-text underline decoration-wavy decoration-red underline-offset-4',
}

// The same textarea in both modes, so switching keeps focus and the caret. In advanced mode its
// text is transparent over a coloured copy; the copy also sets the height, so long queries wrap.
// Only colour differs between the two layers: any change to font, size or spacing misaligns them.
const TEXT = 'col-start-1 row-start-1 px-2 py-1.5 text-sm'

export default function SearchBox({ value, onChange, advanced, onToggle, error }) {
  const input = useRef(null)
  const errorId = useId()
  return (
    <div className={`flex items-start gap-1.5 ${advanced ? 'order-first basis-full' : 'ml-auto max-w-72 grow basis-40'}`}>
      <div
        className={`flex min-w-0 flex-1 items-start rounded-md border bg-white ${
          error ? 'border-red' : 'border-line focus-within:border-blue'
        }`}
      >
        <Search size={16} className="ml-2.5 mt-2 shrink-0 text-grey" />
        <div className="grid min-w-0 flex-1">
          {advanced && (
            <div aria-hidden className={`${TEXT} whitespace-pre-wrap break-words`}>
              {tokenize(value).map((t, i) => (
                <span key={i} className={COLORS[t.kind]}>
                  {t.text}
                </span>
              ))}
              {/* Keeps one line of height when empty. */}
              {'\u200b'}
            </div>
          )}
          <textarea
            ref={input}
            rows={1}
            wrap={advanced ? 'soft' : 'off'}
            value={value}
            onChange={(e) => onChange(e.target.value.replace(/\n/g, ' '))}
            onKeyDown={(e) => e.key === 'Enter' && e.preventDefault()}
            placeholder={advanced ? 'role:hr -level:info details:salaries tokens:>1000' : 'Search'}
            aria-label={advanced ? 'Search query' : 'Search logs'}
            aria-invalid={!!error}
            aria-describedby={error ? errorId : undefined}
            spellCheck={false}
            autoComplete="off"
            className={`${TEXT} resize-none overflow-hidden bg-transparent outline-none placeholder:text-grey/60 ${
              advanced ? 'whitespace-pre-wrap break-words text-transparent caret-ink' : ''
            }`}
          />
        </div>
        {error && (
          <span id={errorId} className="shrink-0 py-1.5 pr-2.5 text-[13px] leading-5 text-red-text">
            {error}
          </span>
        )}
      </div>
      {/* A short word in a thin frame, not an icon: a search icon beside the box read as "apply search". */}
      <button
        aria-pressed={advanced}
        aria-label="Advanced search"
        title="Advanced search"
        onClick={() => {
          onToggle()
          input.current.focus()
        }}
        className={`h-[34px] shrink-0 rounded-md border px-2 text-[13px] ${
          advanced ? 'border-navy bg-navy text-white' : 'border-line text-grey hover:bg-white hover:text-ink'
        }`}
      >
        Adv.
      </button>
    </div>
  )
}
