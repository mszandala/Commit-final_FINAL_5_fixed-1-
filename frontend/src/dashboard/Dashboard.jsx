import { useState } from 'react'
import Logs from './Logs'
import Overview from './Overview'

const TABS = [
  { id: 'logs', label: 'Logs' },
  { id: 'dashboard', label: 'Dashboard' },
]

export default function Dashboard({ configOpen, onOpenConfig, onLeaveConfig }) {
  const [tab, setTab] = useState('logs')
  // Query or filters the dashboard opened the log with; picking the tab by hand starts it clean.
  const [logsView, setLogsView] = useState(undefined)
  const show = (id, view) => {
    setLogsView(view)
    setTab(id)
  }

  return (
    <section className="flex h-full flex-col">
      <header className="flex h-14 shrink-0 items-stretch border-b border-line bg-white px-6">
        <nav role="tablist" className="flex gap-6">
          {TABS.map((t) => (
            <button
              key={t.id}
              role="tab"
              aria-selected={!configOpen && tab === t.id}
              onClick={() => (configOpen ? onLeaveConfig(() => show(t.id)) : show(t.id))}
              className={`-mb-px border-b-2 text-sm ${
                !configOpen && tab === t.id ? 'border-navy text-navy' : 'border-transparent text-grey hover:text-ink'
              }`}
            >
              {t.label}
            </button>
          ))}
        </nav>
        <button
          aria-pressed={configOpen}
          onClick={() => (configOpen ? onLeaveConfig() : onOpenConfig())}
          className={`my-auto ml-auto rounded-md px-3 py-1.5 text-sm ${
            configOpen ? 'bg-navy text-white' : 'text-grey hover:bg-page hover:text-ink'
          }`}
        >
          Config
        </button>
      </header>
      <div role="tabpanel" className="min-h-0 flex-1">
        {tab === 'logs' ? <Logs initial={logsView} /> : <Overview onOpenLogs={(view) => show('logs', view)} />}
      </div>
    </section>
  )
}
