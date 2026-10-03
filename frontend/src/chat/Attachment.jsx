import { FileText, X } from 'lucide-react'
import { formatSize } from '../format'

export default function Attachment({ file, onRemove }) {
  return (
    <span className="inline-flex max-w-full items-center gap-1.5 rounded-md border border-line bg-white py-1 pr-1.5 pl-2 text-sm">
      <FileText size={14} className="shrink-0 text-grey" />
      <span className="truncate">{file.name}</span>
      <span className="shrink-0 text-grey">{formatSize(file.size)}</span>
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
