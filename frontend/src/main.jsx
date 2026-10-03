import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource/instrument-sans/latin-400.css'
import '@fontsource/instrument-sans/latin-600.css'
import './index.css'
import App from './App'

// Local-only tools live in src/dev (git-excluded); nothing happens if it's missing
import.meta.env.DEV && Object.values(import.meta.glob('./dev/*.jsx')).forEach((load) => load())

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
