import { useEffect, useRef } from 'react'

export default function Dialog({ open, title, onCancel, children }) {
  const ref = useRef(null)

  useEffect(() => {
    const dialog = ref.current
    if (open && !dialog.open) {
      dialog.showModal()
      // Otherwise the first button gets focus and looks preselected.
      dialog.focus()
    }
    if (!open) dialog.close()
  }, [open])

  return (
    <dialog
      ref={ref}
      tabIndex={-1}
      onCancel={(e) => {
        e.preventDefault()
        onCancel()
      }}
      // The panel fills the dialog, so a click that lands on the dialog itself is on the backdrop.
      onClick={(e) => e.target === ref.current && onCancel()}
      className="m-auto w-96 rounded-md border border-line bg-white text-ink outline-none backdrop:bg-ink/20"
    >
      <div className="p-5">
        <h2 className="font-semibold text-navy">{title}</h2>
        <div className="mt-5 flex justify-end gap-2">{children}</div>
      </div>
    </dialog>
  )
}
