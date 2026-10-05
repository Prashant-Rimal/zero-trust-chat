import QRCode from 'qrcode'
import { useEffect, useMemo, useRef } from 'react'
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from 'react'

const variants = {
  primary: 'bg-rail text-white hover:bg-rail-soft',
  soft: 'bg-sage text-ink hover:bg-sage-strong',
  ghost: 'text-ink hover:bg-sage',
  outline: 'border border-line bg-panel text-ink hover:bg-paper',
  danger: 'border border-danger/30 bg-danger-soft text-danger hover:bg-danger/15',
}

export function Button({ variant = 'outline', className = '', ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: keyof typeof variants }) {
  return (
    <button
      type="button"
      {...props}
      className={`inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${variants[variant]} ${className}`}
    />
  )
}

export function Field({ label, hint, ...props }: InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: string }) {
  return (
    <label className="block text-sm">
      <span className="mb-1.5 block font-medium">{label}</span>
      <input {...props} className="w-full rounded-lg border border-line bg-panel px-3 py-2.5 text-[15px] placeholder:text-muted/60 focus:border-moss focus:outline-none" />
      {hint && <span className="mt-1.5 block text-xs text-muted">{hint}</span>}
    </label>
  )
}

const tones = {
  neutral: 'bg-paper text-muted border-line',
  good: 'bg-sage text-moss border-sage-strong',
  warn: 'bg-warn-soft text-warn border-warn/25',
  danger: 'bg-danger-soft text-danger border-danger/25',
}
export function Badge({ tone = 'neutral', children }: { tone?: keyof typeof tones; children: ReactNode }) {
  return <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-semibold tracking-wide whitespace-nowrap ${tones[tone]}`}>{children}</span>
}

export function Modal({ open, title, onClose, children, wide = false }: { open: boolean; title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    const dialog = ref.current
    if (!dialog) return
    if (open && !dialog.open) dialog.showModal()
    if (!open && dialog.open) dialog.close()
  }, [open])
  return (
    <dialog
      ref={ref}
      onClose={onClose}
      onClick={(event) => event.target === ref.current && onClose()}
      className={`m-auto w-[calc(100%-2rem)] rounded-2xl border border-line bg-panel p-0 text-ink shadow-2xl ${wide ? 'max-w-2xl' : 'max-w-md'}`}
    >
      {open && (
        <div className="max-h-[85vh] overflow-y-auto p-6">
          <div className="mb-4 flex items-start justify-between gap-4">
            <h2 className="text-lg font-semibold">{title}</h2>
            <button type="button" onClick={onClose} aria-label="Close" className="-mt-1 -mr-2 rounded-lg px-2 py-1 text-xl leading-none text-muted hover:bg-sage">
              ×
            </button>
          </div>
          {children}
        </div>
      )}
    </dialog>
  )
}

/** Rendered as SVG rects from the module matrix: no innerHTML, no image requests. */
export function Qr({ value, size = 168, label }: { value: string; size?: number; label: string }) {
  const path = useMemo(() => {
    const { modules } = QRCode.create(value, { errorCorrectionLevel: 'M' })
    let d = ''
    for (let y = 0; y < modules.size; y++) for (let x = 0; x < modules.size; x++) if (modules.get(y, x)) d += `M${x} ${y}h1v1h-1z`
    return { d, n: modules.size }
  }, [value])
  return (
    <svg role="img" aria-label={label} width={size} height={size} viewBox={`-2 -2 ${path.n + 4} ${path.n + 4}`} className="rounded-lg border border-line bg-white" shapeRendering="crispEdges">
      <path d={path.d} fill="#16241f" />
    </svg>
  )
}

export function PageHeader({ eyebrow, title, description, actions }: { eyebrow: string; title: string; description: string; actions?: ReactNode }) {
  return (
    <header className="mb-8 flex flex-wrap items-end justify-between gap-4">
      <div className="max-w-2xl">
        <p className="eyebrow mb-2">{eyebrow}</p>
        <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">{title}</h1>
        <p className="mt-2 text-[15px] text-muted">{description}</p>
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </header>
  )
}

export function Panel({ title, description, children, actions }: { title?: string; description?: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="rounded-2xl border border-line bg-panel p-5 sm:p-6">
      {(title || actions) && (
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div>
            {title && <h2 className="font-semibold">{title}</h2>}
            {description && <p className="mt-1 text-sm text-muted">{description}</p>}
          </div>
          {actions}
        </div>
      )}
      {children}
    </section>
  )
}

export function Stat({ label, value, hint, tone = 'neutral' }: { label: string; value: ReactNode; hint: string; tone?: 'neutral' | 'warn' }) {
  return (
    <div className={`rounded-2xl border p-5 ${tone === 'warn' ? 'border-warn/30 bg-warn-soft' : 'border-line bg-panel'}`}>
      <p className="text-sm text-muted">{label}</p>
      <p className="mt-1 text-3xl font-semibold tabular-nums">{value}</p>
      <p className="mt-1 text-xs text-muted">{hint}</p>
    </div>
  )
}

export const when = (time: number) => new Date(time).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
export const clock = (time: number) => new Date(time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })

export function relative(time: number, now = Date.now()) {
  const seconds = Math.round((time - now) / 1000)
  const abs = Math.abs(seconds)
  const text = abs < 90 ? `${abs}s` : abs < 5400 ? `${Math.round(abs / 60)}m` : abs < 129_600 ? `${Math.round(abs / 3600)}h` : `${Math.round(abs / 86_400)}d`
  return seconds >= 0 ? `in ${text}` : `${text} ago`
}
