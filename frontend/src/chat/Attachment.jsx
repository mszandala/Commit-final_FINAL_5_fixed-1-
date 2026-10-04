import { FileText, Image, LoaderCircle, X } from 'lucide-react'

const STYLES = {
  reading: 'border-line text-grey',
  done: 'border-line text-ink',
  error: 'border-red text-red-text',
}

// A file chip: in the composer while its text is read, and above the sent message.
export default function Attachment({ file, onRemove }) {
  const Icon = file.status === 'reading' ? LoaderCircle : /\.(png|jpe?g)$/i.test(file.name) ? Image : FileText

  return (
    <span
      title={file.status === 'error' ? `${file.name}: ${file.error}` : file.name}
      className={`inline-flex max-w-full items-center gap-1.5 rounded-md border bg-white py-1 pl-2 text-sm ${STYLES[file.status]} ${onRemove ? 'pr-1.5' : 'pr-2'}`}
    >
      <Icon size={14} className={`shrink-0 ${file.status === 'reading' ? 'animate-spin' : ''} ${file.status === 'done' ? 'text-grey' : ''}`} />
      <span className="truncate">{file.name}</span>
      {file.status === 'reading' && <span className="shrink-0 tabular-nums">{file.percent}%</span>}
      {file.status === 'error' && <span className="shrink-0">{file.error}</span>}
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
