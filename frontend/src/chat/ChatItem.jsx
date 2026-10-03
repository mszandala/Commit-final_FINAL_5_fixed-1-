import { Ban, CloudOff, EyeOff, Flag, RotateCw } from 'lucide-react'
import { CONTROLS, REDACTED_PII } from '../mock/config'
import Button from '../ui/Button'
import Notice from '../ui/Notice'
import Attachment from './Attachment'
import Pending from './Pending'
import ToolCall from './ToolCall'

const VERDICTS = {
  warn: { icon: Flag, tone: 'amber', title: (control) => `Flagged by ${control}` },
  redact: { icon: EyeOff, tone: 'amber', title: (control) => `Redacted by ${control}` },
  block: { icon: Ban, tone: 'red', title: (control) => `Blocked by ${control}` },
}

// "Prompt guard" -> "prompt guard", but "PII policy" stays.
const midSentence = (name) => (/^[A-Z]{2}/.test(name) ? name : name[0].toLowerCase() + name.slice(1))

// The backend replaces redacted values with [TYPE]; show those as tags.
function Reply({ text }) {
  return (
    <p className="whitespace-pre-wrap leading-relaxed">
      {text.split(/\[([A-Z-]+)\]/).map((part, i) =>
        i % 2 === 0 ? (
          part
        ) : (
          <span key={i} className="rounded-sm bg-amber/25 px-1 py-px text-xs font-semibold uppercase tracking-wide">
            {REDACTED_PII[part] ?? part}
          </span>
        ),
      )}
    </p>
  )
}

export default function ChatItem({ item, onRetry }) {
  if (item.kind === 'session') {
    return (
      <div className="flex items-center gap-3 text-[13px] text-grey">
        <span className="h-px flex-1 bg-line" />
        {item.name}, {item.role}
        <span className="h-px flex-1 bg-line" />
      </div>
    )
  }

  if (item.kind === 'user') {
    return (
      <div className="flex flex-col items-end gap-1.5">
        {item.files.map((file, i) => (
          <Attachment key={`${file.name}-${i}`} file={file} />
        ))}
        {item.text && (
          <p className="max-w-[85%] whitespace-pre-wrap rounded-md bg-blue-light/35 px-3.5 py-2">{item.text}</p>
        )}
      </div>
    )
  }

  if (item.kind === 'error') {
    return (
      <Notice icon={CloudOff} title="Cannot reach the server">
        <Button size="sm" icon={RotateCw} onClick={onRetry} className="mt-2">
          Retry
        </Button>
      </Notice>
    )
  }

  const notice = item.verdict && VERDICTS[item.verdict.decision]

  return (
    <div className="space-y-3">
      {item.tools.length > 0 && (
        <div className="space-y-1.5">
          {item.tools.map((call, i) => (
            <ToolCall key={i} call={call} />
          ))}
        </div>
      )}
      {item.kind === 'pending' && <Pending stage={item.stage} />}
      {item.text && <Reply text={item.text} />}
      {notice && (
        <Notice icon={notice.icon} tone={notice.tone} title={notice.title(midSentence(CONTROLS[item.verdict.stage]))}>
          <p className="text-ink">{item.verdict.reason}</p>
        </Notice>
      )}
    </div>
  )
}
