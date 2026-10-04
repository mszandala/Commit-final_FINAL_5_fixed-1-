import { ShieldAlert } from 'lucide-react'
import { useMeta } from '../meta'

export default function Examples({ disabled, onPick }) {
  const { examples } = useMeta()

  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-1.5 text-xs font-medium text-grey">
        <ShieldAlert size={13} className="text-navy" />
        <span>Suggested Test Prompts (Verify Guardrails & Security Enforcement):</span>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {examples.map((text) => (
          <button
            key={text}
            disabled={disabled}
            onClick={() => onPick(text)}
            className="rounded-md border border-line bg-page/40 px-2 py-1 text-left text-xs text-ink/80 transition hover:border-navy hover:bg-white hover:text-navy disabled:pointer-events-none disabled:opacity-50"
            title={text}
          >
            {text}
          </button>
        ))}
      </div>
    </div>
  )
}
