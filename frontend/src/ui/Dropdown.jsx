import { useEffect, useRef, useState } from 'react'

export default function Dropdown({ trigger, label, children }) {
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
        className="-mx-2 flex items-center gap-2.5 rounded-md px-2 py-1 hover:bg-page"
      >
        {trigger}
      </button>
      {open && (
        <div className="absolute left-0 top-full z-10 mt-1.5 w-80 rounded-md border border-line bg-white shadow-sm">
          {children(() => setOpen(false))}
        </div>
      )}
    </div>
  )
}
