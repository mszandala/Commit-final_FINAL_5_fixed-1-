import { FileText, X } from 'lucide-react'
import { formatSize } from '../format'

// Mock, shown in red: the API takes text only, so files never reach the backend.
export default function Attachment({ file, onRemove }) {
  return (
    <span
      title="Mock: not sent to the backend"
      className="inline-flex max-w-full items-center gap-1.5 rounded-md border border-red bg-white py-1 pr-1.5 pl-2 text-sm text-red-text"
    >
      <FileText size={14} className="shrink-0" />
      <span className="truncate">{file.name}</span>
      <span className="shrink-0">{formatSize(file.size)}</span>
      {onRemove && (
        <button
          type="button"
          aria-label={`Remove ${file.name}`}
          onClick={onRemove}
          className="grid size-5 shrink-0 place-items-center rounded-sm text-grey hover:bg-page hover:text-ink"
        >
          <X size={14} />
        </button>
      )}
    </span>
  )
}
