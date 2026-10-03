import {
  BookOpen,
  Bot,
  ChartLine,
  ChevronRight,
  FileSearch,
  FileText,
  Landmark,
  Megaphone,
  Mic,
  SquareTerminal,
  Users,
} from 'lucide-react'
import { CONTROLS } from '../mock/config'
import StatusTag from '../ui/StatusTag'

// Project files are named owner_repo; people know them by the repo.
const project = (name) => name.split('_').slice(1).join('_') || name

const filtered = (label, { column, value }) => (column ? `${label}, ${column} ${value}` : label)

const TOOLS = {
  list_projects: { icon: FileSearch, label: (a) => (a.search ? `Search projects for “${a.search}”` : 'List projects') },
  read_project: { icon: BookOpen, label: (a) => `Read ${project(a.name)}` },
  read_employee_records: { icon: Users, label: (a) => filtered('Read employee records', a) },
  read_client_records: { icon: Landmark, label: (a) => filtered('Read client records', a) },
  read_bank_campaigns: { icon: Megaphone, label: (a) => filtered('Read campaign results', a) },
  read_stock_prices: { icon: ChartLine, label: () => 'Read stock prices' },
  list_earnings_calls: { icon: Mic, label: () => 'List earnings calls' },
  read_earnings_call: { icon: Mic, label: () => 'Read earnings call' },
  run_python: { icon: SquareTerminal, label: () => 'Run Python code' },
  create_subagent: { icon: Bot, label: () => 'Hand off to a subagent' },
  read_file: { icon: FileText, label: (a) => `Read ${a.filename}` },
  list_files: { icon: FileText, label: () => 'List files' },
}

const literal = (v) => (typeof v === 'string' && v.includes('\n') ? `"""\n${v}\n"""` : JSON.stringify(v))
const rawCall = ({ tool, args }) =>
  `${tool}(${Object.entries(args)
    .map(([k, v]) => `${k}=${literal(v)}`)
    .join(', ')})`

export default function ToolCall({ call }) {
  const { icon: Icon, label } = TOOLS[call.tool] ?? { icon: SquareTerminal, label: () => call.tool }

  return (
    <details className="group text-sm text-grey">
      <summary className="flex w-fit list-none items-center gap-1.5 hover:text-ink [&::-webkit-details-marker]:hidden">
        <Icon size={14} className="shrink-0" />
        <span className={call.allowed ? '' : 'line-through'}>{label(call.args)}</span>
        {!call.allowed && <StatusTag status="Blocked" />}
        <ChevronRight size={14} className="shrink-0 transition-transform group-open:rotate-90" />
      </summary>
      <div className="mt-1.5 space-y-1.5">
        {!call.allowed && (
          <p className="text-ink">
            {CONTROLS[call.stage]}: {call.reason}
          </p>
        )}
        <pre className="whitespace-pre-wrap break-words rounded-md bg-page px-3 py-2 font-mono text-[12.5px] leading-relaxed text-ink">
          {rawCall(call)}
        </pre>
      </div>
    </details>
  )
}
