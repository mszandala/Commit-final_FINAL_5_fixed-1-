const VARIANTS = {
  primary: 'bg-navy text-white border-navy',
  secondary: 'bg-white text-navy border-line hover:bg-page',
}

const SIZES = {
  sm: 'px-2.5 py-1 text-sm',
  md: 'px-3.5 py-2',
}

export default function Button({ variant = 'secondary', size = 'md', icon: Icon, children, className = '', ...props }) {
  return (
    <button
      className={`inline-flex items-center gap-1.5 rounded-md border disabled:opacity-40 ${VARIANTS[variant]} ${SIZES[size]} ${className}`}
      {...props}
    >
      {Icon && <Icon size={size === 'sm' ? 14 : 16} />}
      {children}
    </button>
  )
}
