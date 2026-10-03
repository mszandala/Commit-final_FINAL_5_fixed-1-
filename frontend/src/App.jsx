import Chat from './chat/Chat'
import Dashboard from './dashboard/Dashboard'

export default function App() {
  return (
    <main className="flex h-screen">
      <div className="w-[440px] shrink-0 border-r border-line">
        <Chat />
      </div>
      <div className="min-w-0 flex-1">
        <Dashboard />
      </div>
    </main>
  )
}
