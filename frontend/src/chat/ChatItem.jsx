import { Ban, CloudOff, EyeOff, Flag, RotateCw } from 'lucide-react'
import { useMeta } from '../meta'
import Button from '../ui/Button'
import Notice from '../ui/Notice'
import Attachment from './Attachment'
import Markdown from './Markdown'
import Pending from './Pending'
import ToolCall from './ToolCall'

const VERDICTS = {
  warn: { icon: Flag, tone: 'amber', title: (control) => `Flagged by ${control}` },
  refuse: { icon: Flag, tone: 'amber', title: () => 'Declined by the chatbot' },
  redact: { icon: EyeOff, tone: 'amber', title: (control) => `Redacted by ${control}` },
  block: { icon: Ban, tone: 'red', title: (control) => `Blocked by ${control}` },
}

// "Prompt guard" -> "prompt guard", but "PII policy" stays.
const midSentence = (name) => (/^[A-Z]{2}/.test(name) ? name : name[0].toLowerCase() + name.slice(1))

export default function ChatItem({ item, onRetry }) {
  const { controls } = useMeta()

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
        {item.files.length > 0 && (
          <div className="flex max-w-[85%] flex-wrap justify-end gap-1.5">
            {item.files.map((file, i) => (
              <Attachment key={i} file={{ ...file, status: 'done' }} />
            ))}
          </div>
        )}
        {item.text && (
          <p className="max-w-[85%] cursor-text whitespace-pre-wrap rounded-md bg-blue-light/35 px-3.5 py-2">{item.text}</p>
        )}
      </div>
    )
  }

  if (item.kind === 'error') {
    // 0: no answer at all. 502: the backend answered but the model call failed. For anything else
    // the backend says what went wrong.
    const title = { 0: 'Cannot reach the server', 502: 'The model call failed' }[item.status] ?? 'The server returned an error'
    return (
      <Notice icon={CloudOff} title={title}>
        {![0, 502].includes(item.status) && <p className="text-ink">{item.detail}</p>}
        <Button size="sm" icon={RotateCw} onClick={onRetry} className="mt-2">
          Retry
        </Button>
      </Notice>
    )
  }

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
      {item.text && <Markdown text={item.text} />}
      {item.verdicts?.filter((verdict) => VERDICTS[verdict.decision]).map((verdict, i) => {
        const notice = VERDICTS[verdict.decision]
        return (
          <Notice
            key={i}
            icon={notice.icon}
            tone={notice.tone}
            title={notice.title(midSentence(controls[verdict.stage] ?? verdict.stage))}
          >
            <p className="text-ink">{verdict.reason}</p>
          </Notice>
        )
      })}
    </div>
  )
}
