import { getExamples } from '../mock/chat'

export default function Examples({ disabled, onPick }) {
  return (
    <ul className="-mx-2">
      {getExamples().map((text) => (
        <li key={text}>
          <button
            disabled={disabled}
            onClick={() => onPick(text)}
            className="block w-full truncate rounded-md px-2 py-1 text-left text-sm text-grey hover:bg-page hover:text-ink disabled:pointer-events-none disabled:opacity-50"
          >
            {text}
          </button>
        </li>
      ))}
    </ul>
  )
}
