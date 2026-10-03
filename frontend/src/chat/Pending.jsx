import { LoaderCircle } from 'lucide-react'

export default function Pending({ stage }) {
  return (
    <p className="flex items-center gap-1.5 text-sm text-grey">
      <LoaderCircle size={14} className="animate-spin" />
      {stage}
    </p>
  )
}
