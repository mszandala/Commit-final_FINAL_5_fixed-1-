import { useState } from 'react'
import Chat from './chat/Chat'
import Config from './config/Config'
import Dashboard from './dashboard/Dashboard'
import { getConfig } from './mock/config'
import Button from './ui/Button'
import Dialog from './ui/Dialog'

export default function App() {
  const [configOpen, setConfigOpen] = useState(false)
  const [saved, setSaved] = useState(getConfig)
  const [draft, setDraft] = useState(getConfig)
  // What to do after leaving config, held while the unsaved changes prompt is up.
  const [afterLeave, setAfterLeave] = useState(null)
  const dirty = JSON.stringify(draft) !== JSON.stringify(saved)

  function leaveConfig(next = () => {}) {
    if (dirty) return setAfterLeave(() => next)
    setConfigOpen(false)
    next()
  }

  function decide(keep) {
    keep ? setSaved(draft) : setDraft(saved)
    setConfigOpen(false)
    afterLeave()
    setAfterLeave(null)
  }

  return (
    <main className="relative flex h-screen">
      <div className="w-[440px] shrink-0 border-r border-line">
        <Chat />
      </div>
      <div className="min-w-0 flex-1">
        <Dashboard configOpen={configOpen} onOpenConfig={() => setConfigOpen(true)} onLeaveConfig={leaveConfig} />
      </div>
      {/* Covers both panes below their headers; the panes stay mounted so chat and tabs keep their state. */}
      {configOpen && (
        <div className="absolute inset-x-0 bottom-0 top-14 bg-page">
          <Config config={draft} dirty={dirty} onChange={setDraft} onSave={() => setSaved(draft)} />
        </div>
      )}
      <Dialog open={afterLeave !== null} title="Keep unsaved changes?" onCancel={() => setAfterLeave(null)}>
        <Button onClick={() => decide(false)}>Discard</Button>
        <Button variant="primary" onClick={() => decide(true)}>
          Keep
        </Button>
      </Dialog>
    </main>
  )
}
