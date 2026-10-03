import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { REDACTED_PII } from '../mock/config'

// The backend replaces redacted values with [TYPE]; only known types become tags.
const MARKER = new RegExp(`\\[(${Object.keys(REDACTED_PII).join('|')})\\]`)

const tag = (type) => ({
  type: 'element',
  tagName: 'span',
  properties: { className: 'rounded-sm bg-amber/25 px-1 py-px text-xs font-semibold uppercase tracking-wide' },
  children: [{ type: 'text', value: REDACTED_PII[type] }],
})

function rehypeRedactions() {
  const walk = (node) => {
    node.children = node.children.flatMap((child) => {
      if (child.children) walk(child)
      if (child.type !== 'text') return [child]
      return child.value
        .split(MARKER)
        .map((part, i) => (i % 2 ? tag(part) : { type: 'text', value: part }))
        .filter((n) => n.type !== 'text' || n.value)
    })
  }
  return walk
}

// Only 400 and 600 weights are loaded, so bold maps to semibold.
const components = {
  ul: ({ node, ...props }) => <ul className="list-disc space-y-1 pl-5 marker:text-grey" {...props} />,
  ol: ({ node, ...props }) => <ol className="list-decimal space-y-1 pl-5 marker:text-grey" {...props} />,
  li: ({ node, ...props }) => <li className="pl-0.5 [&>ol]:mt-1 [&>ul]:mt-1" {...props} />,
  h1: ({ node, ...props }) => <h3 className="font-semibold" {...props} />,
  h2: ({ node, ...props }) => <h3 className="font-semibold" {...props} />,
  h3: ({ node, ...props }) => <h3 className="font-semibold" {...props} />,
  h4: ({ node, ...props }) => <h4 className="font-semibold" {...props} />,
  strong: ({ node, ...props }) => <strong className="font-semibold" {...props} />,
  a: ({ node, ...props }) => (
    <a className="underline decoration-line underline-offset-2 hover:text-blue" target="_blank" rel="noreferrer" {...props} />
  ),
  blockquote: ({ node, ...props }) => <blockquote className="border-l-2 border-line pl-3" {...props} />,
  hr: () => <hr className="border-line" />,
  // The pre below resets this look for fenced blocks.
  code: ({ node, className, ...props }) => (
    <code className="rounded-sm bg-page px-1 py-px font-mono text-[13px]" {...props} />
  ),
  pre: ({ node, ...props }) => (
    <pre
      className="overflow-x-auto rounded-md bg-page px-3 py-2 font-mono text-[12.5px] leading-relaxed [&>code]:bg-transparent [&>code]:p-0 [&>code]:text-[length:inherit]"
      {...props}
    />
  ),
  table: ({ node, ...props }) => (
    <div className="overflow-x-auto rounded-md border border-line">
      <table className="w-full border-separate border-spacing-0 text-sm tabular-nums" {...props} />
    </div>
  ),
  tbody: ({ node, ...props }) => <tbody className="[&_tr:last-child_td]:border-b-0" {...props} />,
  th: ({ node, ...props }) => (
    <th className="border-b border-line px-2.5 py-1.5 text-left text-[13px] font-normal text-grey" {...props} />
  ),
  td: ({ node, ...props }) => <td className="border-b border-line px-2.5 py-1.5" {...props} />,
  // An image could load any URL and leak data, so only its alt text shows.
  img: ({ alt }) => alt || null,
}

export default function Markdown({ text }) {
  return (
    <div className="min-w-0 cursor-text space-y-3 leading-relaxed">
      <ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeRedactions]} components={components}>
        {text}
      </ReactMarkdown>
    </div>
  )
}
