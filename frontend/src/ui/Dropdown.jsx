import { useEffect, useRef, useState } from 'react'

const VARIANTS = {
  menu: {
    trigger: '-mx-2 flex items-center gap-2.5 rounded-md px-2 py-1 hover:bg-page',
    panel: 'w-80',
  },
  field: {
    trigger:
      'flex w-full items-center justify-between rounded-md border border-line bg-white px-2.5 py-1.5 text-left text-sm outline-none focus-visible:border-blue aria-expanded:border-blue',
    panel: 'w-full',
  },
  filter: {
    trigger:
      'flex shrink-0 items-center gap-2 rounded-md border border-line bg-white px-2.5 py-1.5 text-sm outline-none focus-visible:border-blue aria-expanded:border-blue',
    panel: '',
  },
  cell: {
    trigger:
      'flex max-w-full items-start gap-1.5 rounded-md border border-transparent px-2 py-1 text-left hover:border-line hover:bg-white aria-expanded:border-blue aria-expanded:bg-white',
    panel: 'w-48',
  },
}

const PLACEMENTS = {
  down: 'top-full mt-1.5',
  up: 'bottom-full mb-1.5',
}

export default function Dropdown({ trigger, label, variant = 'menu', placement = 'down', children }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    if (!open) return
    const onPointer = (e) => !ref.current.contains(e.target) && setOpen(false)
    const onKey = (e) => e.key === 'Escape' && setOpen(false)
    document.addEventListener('mousedown', onPointer)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onPointer)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  return (
    <div ref={ref} className="relative">
      <button
        aria-label={label}
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className={VARIANTS[variant].trigger}
      >
        {trigger}
      </button>
      {open && (
        <div className={`absolute left-0 z-20 rounded-md border border-line bg-white shadow-sm ${PLACEMENTS[placement]} ${VARIANTS[variant].panel}`}>
          {children(() => setOpen(false))}
        </div>
      )}
    </div>
  )
}
