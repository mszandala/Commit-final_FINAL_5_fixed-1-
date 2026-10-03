import { useEffect, useState } from 'react'
import { CloudOff, RotateCw } from 'lucide-react'
import { getConfig, getConfigDefaults, getMeta, getRoles, updateConfig } from './api'
import Chat from './chat/Chat'
import Config from './config/Config'
import Dashboard from './dashboard/Dashboard'
import { refreshEvents } from './events'
import { MetaContext } from './meta'
import Button from './ui/Button'
import Dialog from './ui/Dialog'
import Notice from './ui/Notice'

// The form edits this shape. The API never returns the key, so `apiKey` holds only a new one.
const toForm = (c) => ({
  provider: c.provider,
  model: c.model,
  apiKey: '',
  apiKeySet: c.apiKeySet,
  apiKeyHint: c.apiKeyHint,
  sensitivity: c.sensitivity,
  piiThreshold: c.piiThreshold,
  guardMode: c.guardMode,
  maskPii: c.maskPii,
  roles: c.roles.map(({ id, label, access, pii }) => ({ id, label, access, pii })),
})

const toUpdate = (form) => ({
  provider: form.provider,
  model: form.model,
  ...(form.apiKey && { apiKey: form.apiKey }),
  ...(form.sensitivity && { sensitivity: form.sensitivity }),
  guardMode: form.guardMode,
  maskPii: form.maskPii,
  roles: form.roles,
})

export default function App() {
  // meta, people (GET /roles) and the saved config, loaded once.
  const [loaded, setLoaded] = useState(null)
  const [loadFailed, setLoadFailed] = useState(false)
  const [configOpen, setConfigOpen] = useState(false)
  const [saved, setSaved] = useState(null)
  const [draft, setDraft] = useState(null)
  const [saveError, setSaveError] = useState(null)
  // What to do after leaving config, held while the unsaved changes prompt is up.
  const [afterLeave, setAfterLeave] = useState(null)
  const dirty = JSON.stringify(draft) !== JSON.stringify(saved)

  async function load() {
    setLoadFailed(false)
    try {
      const [meta, people, config] = await Promise.all([getMeta(), getRoles(), getConfig()])
      setLoaded({ meta, people })
      setSaved(toForm(config))
      setDraft(toForm(config))
      refreshEvents()
    } catch {
      setLoadFailed(true)
    }
  }

  useEffect(() => {
    load()
  }, [])

  async function save(form = draft) {
    setSaveError(null)
    try {
      const config = toForm(await updateConfig(toUpdate(form)))
      setSaved(config)
      setDraft(config)
      return true
    } catch (e) {
      setSaveError(e.message)
      return false
    }
  }

  async function resetDraft() {
    try {
      setDraft({ ...toForm(await getConfigDefaults()), apiKeySet: saved.apiKeySet, apiKeyHint: saved.apiKeyHint })
    } catch (e) {
      setSaveError(e.message)
    }
  }

  function leaveConfig(next = () => {}) {
    if (dirty) return setAfterLeave(() => next)
    setConfigOpen(false)
    next()
  }

  async function decide(keep) {
    if (keep && !(await save())) return setAfterLeave(null)
    if (!keep) setDraft(saved)
    setConfigOpen(false)
    afterLeave()
    setAfterLeave(null)
  }

  if (!loaded) {
    return (
      <main className="grid h-screen place-items-center bg-page">
        {loadFailed && (
          <Notice icon={CloudOff} title="Cannot reach the server">
            <Button size="sm" icon={RotateCw} onClick={load} className="mt-2">
              Retry
            </Button>
          </Notice>
        )}
      </main>
    )
  }

  return (
    <MetaContext.Provider value={loaded.meta}>
      <main className="relative flex h-screen">
        <div className="w-[440px] shrink-0 border-r border-line">
          <Chat people={loaded.people} />
        </div>
        <div className="min-w-0 flex-1">
          <Dashboard configOpen={configOpen} onOpenConfig={() => setConfigOpen(true)} onLeaveConfig={leaveConfig} />
        </div>
        {/* Covers both panes below their headers; the panes stay mounted so chat and tabs keep their state. */}
        {configOpen && (
          <div className="absolute inset-x-0 bottom-0 top-14 bg-page">
            <Config
              config={draft}
              dirty={dirty}
              error={saveError}
              onChange={setDraft}
              onReset={resetDraft}
              onSave={() => save()}
            />
          </div>
        )}
        <Dialog open={afterLeave !== null} title="Keep unsaved changes?" onCancel={() => setAfterLeave(null)}>
          <Button onClick={() => decide(false)}>Discard</Button>
          <Button variant="primary" onClick={() => decide(true)}>
            Keep
          </Button>
        </Dialog>
      </main>
    </MetaContext.Provider>
  )
}
