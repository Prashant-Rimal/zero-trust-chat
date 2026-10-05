import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useEffect, useMemo, useRef, useState } from 'react'
import type { Conversation, LocalMessage, Notice } from '~/client/messenger'
import { getMessenger, guard, noteSend, toast, useApp, withStepUp } from '~/client/session'
import { Badge, Button, Field, Modal, Qr, clock, relative } from '~/components/ui'

export const Route = createFileRoute('/chat')({
  validateSearch: (search: Record<string, unknown>): { c?: string } => (typeof search.c === 'string' ? { c: search.c } : {}),
  component: Chat,
})

const LIFETIMES = [
  { seconds: 60, label: '1 minute' },
  { seconds: 3600, label: '1 hour' },
  { seconds: 86_400, label: '24 hours' },
  { seconds: 7 * 86_400, label: '7 days' },
]
const MAX_FILE = 8 * 1024 * 1024 - 64

function Chat() {
  const app = useApp()
  const messenger = getMessenger()
  const { c: selected } = Route.useSearch()
  const navigate = useNavigate()
  const [creating, setCreating] = useState(false)
  const conversations = messenger.conversations
  const current = conversations.find((c) => c.id === selected)
  const open = (id?: string) => void navigate({ to: '/chat', search: id ? { c: id } : {} })

  return (
    <div className="flex h-full">
      <aside className={`w-full shrink-0 flex-col border-r border-line bg-paper md:flex md:w-80 ${current ? 'hidden' : 'flex'}`}>
        <div className="flex items-center justify-between px-5 pt-6 pb-4">
          <h1 className="text-lg font-semibold">Messages</h1>
          <Button variant="soft" onClick={() => setCreating(true)}>
            + New
          </Button>
        </div>
        <div className="min-h-0 flex-1 space-y-1 overflow-y-auto px-3 pb-4">
          {conversations.length === 0 && <p className="px-3 py-8 text-center text-sm text-muted">No conversations yet. Start one with someone in your workspace.</p>}
          {conversations.map((c) => (
            <ConversationRow key={c.id} conversation={c} active={c.id === selected} onOpen={() => open(c.id)} version={app.version} />
          ))}
        </div>
      </aside>
      <section className={`min-w-0 flex-1 flex-col bg-panel md:flex ${current ? 'flex' : 'hidden'}`}>
        {current ? (
          <Thread key={current.id} conversation={current} onBack={() => open()} />
        ) : (
          <div className="flex h-full flex-col items-center justify-center p-8 text-center">
            <p className="eyebrow mb-3">End-to-end encrypted</p>
            <h2 className="text-xl font-semibold">Pick a conversation</h2>
            <p className="mt-2 max-w-sm text-sm text-muted">Messages are encrypted on your device before they leave it. The server only ever relays ciphertext.</p>
          </div>
        )}
      </section>
      <NewConversation open={creating} onClose={() => setCreating(false)} onCreated={open} />
    </div>
  )
}

function ConversationRow({ conversation: c, active, onOpen }: { conversation: Conversation; active: boolean; onOpen: () => void; version: number }) {
  const messenger = getMessenger()
  const last = messenger.messages(c.id).at(-1)
  const others = c.members.filter((m) => m !== messenger.me.user.id)
  const allVerified = others.length > 0 && others.every((m) => messenger.isVerified(m))
  return (
    <button type="button" onClick={onOpen} className={`flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left transition-colors ${active ? 'bg-sage' : 'hover:bg-sage/60'}`}>
      <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-rail text-sm font-semibold text-white">{c.kind === 'group' ? '#' : c.title.slice(0, 2).toUpperCase()}</span>
      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-1.5">
          <span className="truncate font-medium">{c.title}</span>
          {c.problem ? <span title={c.problem} className="text-danger">⚠</span> : allVerified ? <span title="Verified" className="text-moss">✓</span> : null}
        </span>
        <span className="block truncate text-xs text-muted">{last ? `${last.mine ? 'You: ' : ''}${last.text || (last.file ? `📎 ${last.file.name}` : '')}` : c.kind === 'group' ? `${c.members.length} members` : 'No messages yet'}</span>
      </span>
      {last && <span className="shrink-0 text-[11px] text-muted">{clock(last.created)}</span>}
    </button>
  )
}

function Thread({ conversation: c, onBack }: { conversation: Conversation; onBack: () => void }) {
  const app = useApp()
  const messenger = getMessenger()
  const [text, setText] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [lifetime, setLifetime] = useState(86_400)
  const [sending, setSending] = useState(false)
  const [info, setInfo] = useState(false)
  const [, setNow] = useState(0)
  const scroller = useRef<HTMLDivElement>(null)
  const picker = useRef<HTMLInputElement>(null)

  const items = useMemo(() => {
    const rows: Array<{ at: number; message?: LocalMessage; notice?: Notice }> = [
      ...messenger.messages(c.id).map((message) => ({ at: message.created, message })),
      ...messenger.notices(c.id).map((notice) => ({ at: notice.created, notice })),
    ]
    return rows.sort((a, b) => a.at - b.at)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [c.id, app.version])

  useEffect(() => {
    scroller.current?.scrollTo({ top: scroller.current.scrollHeight })
  }, [items.length])
  // Re-render so expired messages disappear without waiting for other activity.
  useEffect(() => {
    const timer = setInterval(() => setNow((n) => n + 1), 5000)
    return () => clearInterval(timer)
  }, [])

  const others = c.members.filter((m) => m !== messenger.me.user.id)
  const verified = others.length > 0 && others.every((m) => messenger.isVerified(m))

  async function send() {
    if (sending || (!text.trim() && !file)) return
    if (file && file.size > MAX_FILE) return toast('Attachments are limited to 8 MB.', true)
    setSending(true)
    try {
      const attachment = file ? { name: file.name, type: file.type || 'application/octet-stream', bytes: new Uint8Array(await file.arrayBuffer()) } : undefined
      const sent = await messenger.send(c.id, text.trim(), { lifetimeSeconds: lifetime, file: attachment })
      noteSend({ encryptMs: sent.encryptMs, totalMs: sent.totalMs, recipients: sent.recipients })
      setText('')
      setFile(null)
    } finally {
      setSending(false)
    }
  }

  async function download(message: LocalMessage) {
    const bytes = await messenger.openAttachment(c.id, message.file!)
    // Always saved as a download with a generic type, never rendered inline.
    const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type: 'application/octet-stream' }))
    const link = document.createElement('a')
    link.href = url
    link.download = message.file!.name.replace(/[\\/:*?"<>|]/g, '_')
    link.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  return (
    <>
      <header className="flex items-center gap-3 border-b border-line px-4 py-3 sm:px-6">
        <button type="button" onClick={onBack} aria-label="Back to conversations" className="rounded-lg px-2 py-1 text-lg text-muted hover:bg-sage md:hidden">
          ←
        </button>
        <div className="min-w-0 flex-1">
          <h2 className="truncate font-semibold">{c.title}</h2>
          <p className="truncate text-xs text-muted">{c.kind === 'group' ? `${c.members.length} members` : 'Direct message'} · end-to-end encrypted</p>
        </div>
        {c.problem ? <Badge tone="danger">BLOCKED</Badge> : verified ? <Badge tone="good">✓ VERIFIED</Badge> : <Badge tone="warn">UNVERIFIED</Badge>}
        <Button onClick={() => setInfo(true)}>Details</Button>
      </header>

      {c.problem && (
        <div role="alert" className="border-b border-danger/20 bg-danger-soft px-6 py-3 text-sm text-danger">
          <strong>Sending is blocked.</strong> {c.problem} This can mean the server presented a member list its owner did not sign.
        </div>
      )}

      <div ref={scroller} className="min-h-0 flex-1 space-y-3 overflow-y-auto px-4 py-5 sm:px-6">
        {items.length === 0 && <p className="py-10 text-center text-sm text-muted">Nothing here yet. Say hello — only the people in this conversation can read it.</p>}
        {items.map((item) =>
          item.notice ? (
            <p key={item.notice.id} className={`mx-auto max-w-lg rounded-lg px-3 py-2 text-center text-xs ${item.notice.kind === 'warning' ? 'bg-warn-soft text-warn' : 'bg-paper text-muted'}`}>
              {item.notice.kind === 'warning' ? '⚠ ' : ''}
              {item.notice.text}
            </p>
          ) : (
            <Bubble key={item.message!.id} message={item.message!} group={c.kind === 'group'} onDownload={() => void guard(() => download(item.message!))} />
          ),
        )}
      </div>

      <form
        className="border-t border-line p-3 sm:p-4"
        onSubmit={(event) => {
          event.preventDefault()
          void guard(send)
        }}
      >
        {file && (
          <div className="mb-2 flex items-center justify-between rounded-lg bg-sage px-3 py-2 text-sm">
            <span className="truncate">
              📎 {file.name} · {(file.size / 1024).toFixed(0)} KB · encrypted before upload
            </span>
            <button type="button" onClick={() => setFile(null)} aria-label="Remove attachment" className="ml-2 text-muted hover:text-ink">
              ×
            </button>
          </div>
        )}
        <div className="rounded-xl border border-line bg-paper focus-within:border-moss">
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
                e.preventDefault()
                void guard(send)
              }
            }}
            rows={2}
            maxLength={8000}
            disabled={!!c.problem}
            placeholder={c.problem ? 'Sending is blocked for this conversation' : 'Write a message'}
            aria-label="Message"
            className="block w-full resize-none bg-transparent px-3.5 pt-3 text-[15px] placeholder:text-muted/70 focus:outline-none"
          />
          <div className="flex items-center gap-2 px-2 pb-2">
            <input ref={picker} type="file" hidden onChange={(e) => (setFile(e.target.files?.[0] ?? null), (e.target.value = ''))} />
            <Button variant="ghost" onClick={() => picker.current?.click()} disabled={!!c.problem} aria-label="Attach a file">
              📎
            </Button>
            <label className="flex items-center gap-1.5 text-xs text-muted">
              Disappears after
              <select value={lifetime} onChange={(e) => setLifetime(Number(e.target.value))} className="rounded-md border border-line bg-panel px-1.5 py-1 text-xs text-ink">
                {LIFETIMES.map((l) => (
                  <option key={l.seconds} value={l.seconds}>
                    {l.label}
                  </option>
                ))}
              </select>
            </label>
            <Button type="submit" variant="primary" className="ml-auto" disabled={sending || !!c.problem || (!text.trim() && !file)}>
              {sending ? 'Encrypting…' : 'Send'}
            </Button>
          </div>
        </div>
        <p className="mt-1.5 px-1 text-[11px] text-muted">
          {app.lastSend
            ? `Last message: encrypted for ${app.lastSend.recipients} device${app.lastSend.recipients === 1 ? '' : 's'} in ${app.lastSend.encryptMs.toFixed(1)} ms · confirmed by the server in ${app.lastSend.totalMs.toFixed(0)} ms`
            : 'Encrypted on this device before it is sent.'}
        </p>
      </form>

      <Details open={info} onClose={() => setInfo(false)} conversation={c} />
    </>
  )
}

function Bubble({ message: m, group, onDownload }: { message: LocalMessage; group: boolean; onDownload: () => void }) {
  const messenger = getMessenger()
  return (
    <article className={`flex ${m.mine ? 'justify-end' : 'justify-start'}`}>
      <div className="max-w-[min(34rem,85%)]">
        {group && !m.mine && <p className="mb-1 ml-1 text-xs font-medium text-muted">{messenger.username(m.from)}</p>}
        <div className={`rounded-2xl px-4 py-2.5 text-[15px] ${m.mine ? 'rounded-br-md bg-rail text-white' : 'rounded-bl-md bg-sage'}`}>
          {m.text && <p className="break-words whitespace-pre-wrap">{m.text}</p>}
          {m.file && (
            <button type="button" onClick={onDownload} className={`mt-1 flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-sm ${m.mine ? 'bg-white/10 hover:bg-white/20' : 'bg-panel hover:bg-paper'}`}>
              <span aria-hidden="true">↓</span>
              <span className="min-w-0 flex-1 truncate">{m.file.name}</span>
              <span className="shrink-0 text-xs opacity-70">{(m.file.size / 1024).toFixed(0)} KB</span>
            </button>
          )}
        </div>
        <p className={`mt-1 px-1 text-[11px] text-muted ${m.mine ? 'text-right' : ''}`}>
          {clock(m.created)} · disappears {relative(m.expires)}
        </p>
      </div>
    </article>
  )
}

function NewConversation({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (id: string) => void }) {
  const messenger = getMessenger()
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<Array<{ id: string; username: string }>>([])
  const [picked, setPicked] = useState<Array<{ id: string; username: string }>>([])
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (query.trim().length < 2) return setResults([])
    const timer = setTimeout(() => void guard(async () => setResults(await messenger.searchUsers(query.trim().toLowerCase()))), 250)
    return () => clearTimeout(timer)
  }, [query, messenger])
  useEffect(() => {
    if (!open) {
      setQuery('')
      setPicked([])
      setName('')
    }
  }, [open])

  const group = picked.length > 1
  return (
    <Modal open={open} title="New conversation" onClose={onClose}>
      <form
        className="space-y-4"
        onSubmit={(event) => {
          event.preventDefault()
          setBusy(true)
          void guard(async () => {
            const id = await messenger.createConversation(group ? 'group' : 'direct', picked.map((p) => p.id), group ? name : undefined)
            onClose()
            onCreated(id)
          }).finally(() => setBusy(false))
        }}
      >
        <Field label="Find people" placeholder="Type at least 2 letters of a username" value={query} onChange={(e) => setQuery(e.target.value)} autoComplete="off" />
        {results.length > 0 && (
          <ul className="max-h-40 space-y-1 overflow-y-auto">
            {results
              .filter((r) => !picked.some((p) => p.id === r.id))
              .map((r) => (
                <li key={r.id}>
                  <button type="button" onClick={() => setPicked([...picked, r])} className="w-full rounded-lg px-3 py-2 text-left text-sm hover:bg-sage">
                    @{r.username}
                  </button>
                </li>
              ))}
          </ul>
        )}
        {picked.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {picked.map((p) => (
              <button key={p.id} type="button" onClick={() => setPicked(picked.filter((x) => x.id !== p.id))} className="rounded-full bg-sage px-2.5 py-1 text-xs font-medium hover:bg-sage-strong" aria-label={`Remove ${p.username}`}>
                @{p.username} ×
              </button>
            ))}
          </div>
        )}
        {group && <Field label="Group name" required maxLength={60} value={name} onChange={(e) => setName(e.target.value)} hint="Encrypted like a message. The server never sees it." />}
        <Button type="submit" variant="primary" className="w-full" disabled={busy || picked.length === 0}>
          {group ? 'Create group' : 'Start conversation'}
        </Button>
      </form>
    </Modal>
  )
}

function Details({ open, onClose, conversation: c }: { open: boolean; onClose: () => void; conversation: Conversation }) {
  useApp()
  const messenger = getMessenger()
  const mine = messenger.me.user.id
  const owner = c.owner === mine && c.kind === 'group'
  const [checking, setChecking] = useState<string | null>(null)
  const [pasted, setPasted] = useState('')
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<Array<{ id: string; username: string }>>([])

  useEffect(() => {
    if (!owner || query.trim().length < 2) return setResults([])
    const timer = setTimeout(() => void guard(async () => setResults(await messenger.searchUsers(query.trim().toLowerCase()))), 250)
    return () => clearTimeout(timer)
  }, [query, owner, messenger])

  const setMembers = (members: Array<string>) =>
    guard(async () => {
      await withStepUp(() => messenger.setMembers(c.id, members.filter((m) => m !== mine)))
      toast('Member list updated and signed.')
    })

  return (
    <Modal open={open} title={c.kind === 'group' ? 'Group details' : 'Conversation details'} onClose={onClose} wide>
      <p className="mb-5 text-sm text-muted">
        To be sure nobody is intercepting this conversation, compare security codes with each person in person or over a call. If the codes match, mark them verified. You will be warned if their keys change later.
      </p>
      <ul className="space-y-3">
        {c.members.map((userId) => {
          const self = userId === mine
          const verified = messenger.isVerified(userId)
          return (
            <li key={userId} className="rounded-xl border border-line p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-medium">
                  @{messenger.username(userId)} {self && <span className="text-muted">(you)</span>} {userId === c.owner && c.kind === 'group' && <Badge>OWNER</Badge>}
                </span>
                <span className="flex items-center gap-2">
                  {!self && (verified ? <Badge tone="good">✓ VERIFIED</Badge> : <Badge tone="warn">NOT VERIFIED</Badge>)}
                  {!self && <Button onClick={() => (setChecking(checking === userId ? null : userId), setPasted(''))}>{checking === userId ? 'Hide code' : 'Security code'}</Button>}
                  {owner && !self && (
                    <Button variant="danger" onClick={() => void setMembers(c.members.filter((m) => m !== userId))}>
                      Remove
                    </Button>
                  )}
                </span>
              </div>
              {checking === userId && (
                <div className="mt-4 grid gap-4 sm:grid-cols-[auto_1fr]">
                  <Qr value={messenger.verificationCode(userId)} label={`Security code for ${messenger.username(userId)}`} size={140} />
                  <div className="text-sm">
                    <p className="text-muted">Both of you should see this same number:</p>
                    <code className="mt-2 block rounded-lg bg-sage px-3 py-2 font-mono text-[13px] leading-relaxed">{messenger.safetyNumber(userId)}</code>
                    <form
                      className="mt-3 flex gap-2"
                      onSubmit={(event) => {
                        event.preventDefault()
                        void guard(async () => {
                          await messenger.verify(userId, pasted || undefined)
                          toast(`@${messenger.username(userId)} marked as verified.`)
                          setChecking(null)
                        })
                      }}
                    >
                      <input value={pasted} onChange={(e) => setPasted(e.target.value)} placeholder="Paste the code from their Devices page (optional)" aria-label="Their verification code" className="min-w-0 flex-1 rounded-lg border border-line px-2.5 py-1.5 text-xs" />
                      <Button type="submit" variant="primary">
                        {pasted ? 'Check & verify' : 'Numbers match'}
                      </Button>
                    </form>
                  </div>
                </div>
              )}
            </li>
          )
        })}
      </ul>
      {owner && (
        <div className="mt-6 border-t border-line pt-5">
          <Field label="Add someone" placeholder="Type at least 2 letters of a username" value={query} onChange={(e) => setQuery(e.target.value)} autoComplete="off" hint="Changing members needs your authenticator code. The new list is signed by this device." />
          <ul className="mt-2 space-y-1">
            {results
              .filter((r) => !c.members.includes(r.id))
              .map((r) => (
                <li key={r.id}>
                  <button type="button" className="w-full rounded-lg px-3 py-2 text-left text-sm hover:bg-sage" onClick={() => (setQuery(''), void setMembers([...c.members, r.id]))}>
                    Add @{r.username}
                  </button>
                </li>
              ))}
          </ul>
        </div>
      )}
    </Modal>
  )
}
