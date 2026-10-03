import { LoaderCircle } from 'lucide-react'

export default function Pending() {
  return (
    <p className="flex items-center gap-2 text-sm text-grey">
      <LoaderCircle size={14} className="animate-spin" />
      Sample status
    </p>
  )
}
