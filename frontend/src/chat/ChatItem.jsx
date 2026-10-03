import Attachment from './Attachment'

export default function ChatItem({ item }) {
  if (item.kind === 'user') {
    return (
      <div className="flex flex-col items-end gap-1.5">
        {item.files.map((file, i) => (
          <Attachment key={`${file.name}-${i}`} file={file} />
        ))}
        {item.text && (
          <p className="max-w-[85%] whitespace-pre-wrap rounded-md bg-blue-light/35 px-3.5 py-2">{item.text}</p>
        )}
      </div>
    )
  }

  return <p className="whitespace-pre-wrap leading-relaxed">{item.reply}</p>
}
