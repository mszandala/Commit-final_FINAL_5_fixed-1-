import { useState } from 'react'
import cat from '../assets/cat.jpg'

const TABS = [
  { id: 'logs', label: 'Logs' },
  { id: 'dashboard', label: 'Dashboard' },
]

export default function Dashboard() {
  const [tab, setTab] = useState('logs')

  return (
    <section className="flex h-full flex-col">
      <header className="flex h-14 shrink-0 items-stretch border-b border-line bg-white px-6">
        <nav role="tablist" className="flex gap-6">
          {TABS.map((t) => (
            <button
              key={t.id}
              role="tab"
              aria-selected={tab === t.id}
              onClick={() => setTab(t.id)}
              className={`-mb-px border-b-2 text-sm ${
                tab === t.id ? 'border-navy text-navy' : 'border-transparent text-grey hover:text-ink'
              }`}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </header>
      <div role="tabpanel" className="grid flex-1 place-items-center overflow-y-auto p-6">
        <img src={cat} alt="Cat" className="w-[480px]" />
      </div>
    </section>
  )
}
