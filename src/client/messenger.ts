/**
 * The client engine: owns keys, ratchet sessions, pins and local history, and turns user actions
 * into ciphertext. It has no DOM or network dependencies of its own — the browser and the test
 * suite inject a transport and a persistence callback — so the tests exercise the real client.
 */
import * as P from '../shared/protocol'

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public code?: string,
  ) {
    super(message)
  }
}

export type Transport = {
  api: <T = any>(method: string, path: string, body?: unknown) => Promise<T>
  upload: (path: string, bytes: Uint8Array) => Promise<{ id: string }>
  download: (path: string) => Promise<Uint8Array>
  /** Optional realtime send. Falls back to HTTP when absent or disconnected. */
  send?: (message: unknown) => Promise<unknown> | null
}

export type Me = {
  user: { id: string; username: string; role: 'member' | 'auditor' | 'admin' }
  device: { id: string; trust: 'pending' | 'trusted' }
  csrf: string
  permissions: Array<string>
  stepUpUntil: number
  expires: number
}

export type LocalMessage = {
  id: string
  conv: string
  from: string // user id
  device: string
  created: number
  expires: number
  text: string
  file?: P.FileRef
  mine: boolean
}
export type Notice = { id: string; conv: string; created: number; kind: 'warning' | 'info'; text: string }

type Pin = { userId: string; ik: string; first: number; via: 'first-use' | 'cross-signed' | 'unverified-addition'; revoked?: boolean }
type RosterPin = { epoch: number; owner: string; kind: 'direct' | 'group'; members: Array<string> }

/** Everything that is sealed into the local vault. */
export type VaultState = {
  v: 2
  keys: P.DeviceKeys
  sessions: Record<string, Array<P.Session>>
  pins: Record<string, Pin>
  /** userId -> fingerprint that the person confirmed out of band. */
  verified: Record<string, string>
  rosters: Record<string, RosterPin>
  names: Record<string, string>
  messages: Record<string, Array<LocalMessage>>
  notices: Array<Notice>
  usernames: Record<string, string>
}

export type Conversation = {
  id: string
  kind: 'direct' | 'group'
  owner: string
  epoch: number
  members: Array<string>
  created: number
  title: string
  problem?: string
}

type Directory = { users: Array<{ id: string; username: string }>; devices: Array<P.PublicDevice>; at: number }

const HISTORY_LIMIT = 500
const OPK_TARGET = 40
const SPK_MAX_AGE = 7 * 24 * 3600_000

export function newVault(deviceId?: string): VaultState {
  return { v: 2, keys: P.generateDeviceKeys(deviceId), sessions: {}, pins: {}, verified: {}, rosters: {}, names: {}, messages: {}, notices: [], usernames: {} }
}

export class Messenger {
  me!: Me
  conversations: Array<Conversation> = []
  private directories = new Map<string, Directory>()
  private queue: Promise<unknown> = Promise.resolve()
  private listeners = new Set<() => void>()

  constructor(
    public vault: VaultState,
    private transport: Transport,
    /** Must durably store the vault before resolving; ratchet state is acknowledged only after it does. */
    private persist: (vault: VaultState) => Promise<void>,
  ) {}

  subscribe(listener: () => void) {
    this.listeners.add(listener)
    return () => void this.listeners.delete(listener)
  }
  private emit() {
    for (const listener of this.listeners) listener()
  }
  /** Serialises every state-mutating operation so ratchet steps never interleave. */
  private exclusive<T>(work: () => Promise<T>): Promise<T> {
    const run = this.queue.then(work, work)
    this.queue = run.catch(() => {})
    return run
  }
  private async save() {
    await this.persist(this.vault)
    this.emit()
  }

  get keys() {
    return this.vault.keys
  }
  username(userId: string) {
    return userId === this.me.user.id ? this.me.user.username : (this.vault.usernames[userId] ?? 'unknown')
  }

  // ---------- sign-in ----------

  /** Body for /api/auth/verify. Includes a signature over the challenge by this device's identity key. */
  static enrolment(vault: VaultState, challenge: string, code: string, label: string) {
    const k = vault.keys
    const firstUpload = k.nextOpkId === 1
    return {
      challenge,
      code,
      device: { id: k.deviceId, label, ik: k.ik.pub, dh: k.dh.pub, dhSig: k.dhSig },
      spk: P.publicSpk(k),
      opks: firstUpload ? P.mintOneTimePrekeys(k, OPK_TARGET) : [],
      proof: P.signLogin(k, challenge),
    }
  }

  async start(me: Me) {
    this.me = me
    if (me.device.trust !== 'trusted') return this.emit()
    await this.exclusive(async () => {
      await this.maintainPrekeys()
      await this.refreshConversations()
    })
    await this.sync()
  }

  /** Signed-prekey rotation on a schedule, and one-time prekey replenishment. */
  private async maintainPrekeys(forceRotate = false) {
    const status = await this.transport.api<{ available: number; spkId: number; spkAt: number }>('GET', '/api/prekeys')
    const rotate = forceRotate || Date.now() - status.spkAt > SPK_MAX_AGE || status.spkId !== this.keys.spk.id
    const need = Math.max(0, OPK_TARGET - status.available)
    if (!rotate && need < OPK_TARGET / 2) return
    // A device whose server record is ahead of the vault (restored backup) rotates past it.
    if (rotate) while (this.keys.spk.id <= status.spkId) P.rotateSignedPrekey(this.keys)
    const opks = P.mintOneTimePrekeys(this.keys, need)
    await this.persist(this.vault)
    await this.transport.api('POST', '/api/prekeys', { ...(rotate ? { spk: P.publicSpk(this.keys) } : {}), opks })
  }
  rotateKeys() {
    return this.exclusive(() => this.maintainPrekeys(true))
  }

  // ---------- directory, pinning, key-substitution checks ----------

  private note(conv: string, kind: Notice['kind'], text: string) {
    this.vault.notices.push({ id: P.uuid(), conv, created: Date.now(), kind, text })
    this.vault.notices = this.vault.notices.slice(-200)
  }

  /**
   * Checks a directory response against local pins.
   * - A known device id presenting a different identity key is rejected outright.
   * - A new device for a known person is accepted quietly only if one of their pinned devices
   *   cross-signed it. Otherwise it is accepted but the person's verified status is cleared.
   */
  private checkDirectory(conv: string, directory: Directory) {
    for (const user of directory.users) this.vault.usernames[user.id] = user.username
    for (const d of directory.devices) {
      if (!P.verifyDhCert(d)) throw new P.ProtocolError(`A key for ${this.username(d.userId)} failed its signature check.`, 'key-substitution')
      const pin = this.vault.pins[d.id]
      if (pin && (pin.ik !== d.ik || pin.userId !== d.userId))
        throw new P.ProtocolError(`The identity key of a device belonging to ${this.username(pin.userId)} changed. Messaging is blocked.`, 'key-substitution')
    }
    for (const d of directory.devices) {
      const pinned = this.vault.pins[d.id]
      if (pinned) {
        if (d.trust === 'revoked' && !pinned.revoked) {
          // Losing a device adds no new reader, so an existing verification carries over.
          const wasVerified = this.isVerified(d.userId)
          pinned.revoked = true
          if (wasVerified) this.vault.verified[d.userId] = this.fingerprint(d.userId)
        }
        continue
      }
      if (d.trust !== 'trusted') continue
      const known = Object.values(this.vault.pins).some((p) => p.userId === d.userId)
      const signer = d.xsig ? this.vault.pins[d.xsig.by] : undefined
      const crossSigned = !!signer && signer.userId === d.userId && P.verifyCrossSign(signer.ik, d.userId, d.id, d.ik, d.xsig!.sig)
      const via: Pin['via'] = !known ? 'first-use' : crossSigned ? 'cross-signed' : 'unverified-addition'
      const wasVerified = this.isVerified(d.userId)
      this.vault.pins[d.id] = { userId: d.userId, ik: d.ik, first: Date.now(), via }
      if (d.id === this.keys.deviceId) continue
      const who = d.userId === this.me.user.id ? 'Your account' : this.username(d.userId)
      if (via === 'cross-signed') {
        // Trust carries over: re-anchor the verified fingerprint to the new device set.
        if (wasVerified) this.vault.verified[d.userId] = this.fingerprint(d.userId)
        this.note(conv, 'info', `${who} added a device, vouched for by an existing device.`)
      } else if (via === 'unverified-addition') {
        delete this.vault.verified[d.userId]
        this.note(conv, 'warning', `${who} has a new device that no known device vouched for. Compare security codes before sharing anything sensitive.`)
      }
    }
  }

  private async directory(conv: string, maxAge = 15_000): Promise<Directory> {
    const cached = this.directories.get(conv)
    if (cached && Date.now() - cached.at < maxAge) return cached
    const fresh = { ...(await this.transport.api<Omit<Directory, 'at'>>('GET', `/api/conversations/${conv}/directory`)), at: Date.now() }
    this.checkDirectory(conv, fresh)
    this.directories.set(conv, fresh)
    return fresh
  }

  private fingerprints = new Map<string, string>()
  /** Covers the identity keys of every pinned, unrevoked device of a person. */
  fingerprint(userId: string) {
    const keys = Object.values(this.vault.pins)
      .filter((pin) => pin.userId === userId && !pin.revoked)
      .map((pin) => pin.ik)
    if (userId === this.me.user.id && !keys.includes(this.keys.ik.pub)) keys.push(this.keys.ik.pub)
    const cacheKey = `${userId}|${keys.sort().join()}`
    let value = this.fingerprints.get(cacheKey)
    if (!value) this.fingerprints.set(cacheKey, (value = P.userFingerprint(userId, keys)))
    return value
  }
  safetyNumber(userId: string) {
    return P.safetyNumber(this.fingerprint(this.me.user.id), this.fingerprint(userId))
  }
  /** Payload for the QR code another person scans or pastes to verify this account. */
  verificationCode(userId = this.me.user.id) {
    return `cipherroom:v2:${userId}:${this.fingerprint(userId)}`
  }
  isVerified(userId: string) {
    return !!this.vault.verified[userId] && this.vault.verified[userId] === this.fingerprint(userId)
  }
  /** Marks a contact verified. With `scanned`, the code from their device must match what this device computed. */
  verify(userId: string, scanned?: string) {
    return this.exclusive(async () => {
      if (scanned !== undefined && scanned.trim() !== this.verificationCode(userId))
        throw new P.ProtocolError('That code does not match the keys this device has for them. Do not trust this conversation yet.', 'key-substitution')
      this.vault.verified[userId] = this.fingerprint(userId)
      await this.save()
    })
  }

  // ---------- conversations and signed rosters ----------

  /**
   * The server stores membership, but clients only act on a roster signed by the owner's device.
   * Owner and epoch are pinned locally, so the server cannot swap the owner or roll membership back.
   */
  private async acceptRoster(row: { id: string; created: number; roster: P.Roster; signer: string; sig: string }): Promise<Conversation> {
    const { roster } = row
    const base = { id: row.id, kind: roster.kind, owner: roster.owner, epoch: roster.epoch, members: roster.members, created: row.created }
    const pinned = this.vault.rosters[row.id]
    try {
      if (roster.conv !== row.id || !roster.members.includes(roster.owner) || !roster.members.includes(this.me.user.id))
        throw new P.ProtocolError('Roster does not match this conversation.', 'roster')
      const directory = await this.directory(row.id)
      const signer = directory.devices.find((d) => d.id === row.signer)
      if (!signer || signer.userId !== roster.owner || !P.verifyRoster(row, signer.ik))
        throw new P.ProtocolError('Member list is not signed by the conversation owner.', 'roster')
      if (pinned && (pinned.owner !== roster.owner || pinned.kind !== roster.kind || roster.epoch < pinned.epoch))
        throw new P.ProtocolError('Member list was rolled back or its owner changed.', 'roster')
      if (pinned && roster.epoch === pinned.epoch && pinned.members.join() !== roster.members.join())
        throw new P.ProtocolError('Member list changed without a new signed epoch.', 'roster')
      if (pinned && roster.epoch > pinned.epoch) {
        const added = roster.members.filter((m) => !pinned.members.includes(m)).map((m) => this.username(m))
        const removed = pinned.members.filter((m) => !roster.members.includes(m)).map((m) => this.username(m))
        if (added.length) this.note(row.id, 'info', `${this.username(roster.owner)} added ${added.join(', ')}.`)
        if (removed.length) this.note(row.id, 'info', `${this.username(roster.owner)} removed ${removed.join(', ')}.`)
      }
      this.vault.rosters[row.id] = { epoch: roster.epoch, owner: roster.owner, kind: roster.kind, members: roster.members }
      return { ...base, title: this.title(base) }
    } catch (error) {
      // Fail closed: keep the last roster we verified and refuse to send until this is resolved.
      const safe = pinned ? { ...base, ...pinned } : base
      return { ...safe, title: this.title(safe), problem: (error as Error).message }
    }
  }
  private title(c: { id: string; kind: string; members: Array<string> }) {
    if (c.kind === 'direct') return this.username(c.members.find((m) => m !== this.me.user.id) ?? this.me.user.id)
    return this.vault.names[c.id] ?? `Group of ${c.members.length}`
  }

  private async refreshConversations() {
    const rows = await this.transport.api<Array<{ id: string; created: number; roster: P.Roster; signer: string; sig: string }>>('GET', '/api/conversations')
    const next: Array<Conversation> = []
    for (const row of rows) next.push(await this.acceptRoster(row))
    this.conversations = next
    await this.save()
  }
  refresh() {
    this.directories.clear()
    return this.exclusive(() => this.refreshConversations())
  }

  async searchUsers(q: string) {
    const users = await this.transport.api<Array<{ id: string; username: string }>>('GET', `/api/users?q=${encodeURIComponent(q)}`)
    for (const user of users) this.vault.usernames[user.id] = user.username
    return users
  }

  async createConversation(kind: 'direct' | 'group', memberIds: Array<string>, name?: string) {
    const conv = P.uuid()
    const signed = P.signRoster(this.keys, { v: 1, conv, epoch: 1, kind, owner: this.me.user.id, members: [this.me.user.id, ...memberIds] })
    const result = await this.transport.api<{ id: string; existing: boolean }>('POST', '/api/conversations', signed)
    await this.refresh()
    // The group name never reaches the server in the clear: it travels as an encrypted control message.
    if (kind === 'group' && name && !result.existing) await this.rename(result.id, name)
    return result.id
  }

  async rename(conv: string, name: string) {
    await this.dispatch(conv, { t: 'meta', name: name.trim().slice(0, 60) }, 7 * 24 * 3600)
    await this.exclusive(async () => {
      this.vault.names[conv] = name.trim().slice(0, 60)
      this.conversations = this.conversations.map((c) => (c.id === conv ? { ...c, title: this.title(c) } : c))
      await this.save()
    })
  }

  /** Owner only; the server additionally requires a fresh second factor. */
  async setMembers(conv: string, memberIds: Array<string>) {
    const current = this.conversations.find((c) => c.id === conv)
    if (!current) throw new Error('Unknown conversation.')
    const signed = P.signRoster(this.keys, { v: 1, conv, epoch: current.epoch + 1, kind: 'group', owner: this.me.user.id, members: [this.me.user.id, ...memberIds] })
    await this.transport.api('PUT', `/api/conversations/${conv}/roster`, signed)
    await this.refresh()
    if (this.vault.names[conv]) await this.dispatch(conv, { t: 'meta', name: this.vault.names[conv] }, 7 * 24 * 3600)
  }

  // ---------- sending ----------

  private async sessionFor(device: P.PublicDevice) {
    const existing = this.vault.sessions[device.id]?.[0]
    if (existing?.cks) return existing
    const bundle = await this.transport.api<P.PrekeyBundle>('POST', `/api/devices/${device.id}/bundle`)
    const session = P.initiateSession(this.keys, device, bundle)
    this.vault.sessions[device.id] = [session, ...(this.vault.sessions[device.id] ?? [])].slice(0, 3)
    return session
  }

  private dispatch(conv: string, payload: P.Payload, lifetimeSeconds: number, id = P.uuid()) {
    return this.exclusive(async () => {
      const started = performance.now()
      const attempt = async () => {
        const conversation = this.conversations.find((c) => c.id === conv)
        if (!conversation) throw new Error('Unknown conversation.')
        if (conversation.problem) throw new P.ProtocolError(`Sending is blocked: ${conversation.problem}`, 'roster')
        const directory = await this.directory(conv, 5_000)
        // Recipients come from the owner-signed roster, never from the server's say-so alone.
        const targets = directory.devices.filter((d) => d.trust === 'trusted' && d.id !== this.keys.deviceId && conversation.members.includes(d.userId))
        const created = Date.now()
        const expires = created + lifetimeSeconds * 1000
        const plaintext = P.encodePayload(payload)
        const envelopes = []
        for (const device of targets) {
          const session = await this.sessionFor(device)
          const e = P.ratchetEncrypt(session, { id, conv, from: this.keys.deviceId, to: device.id, created, expires }, plaintext)
          envelopes.push({ to: e.to, header: e.header, pre: e.pre, nonce: e.nonce, ct: e.ct })
        }
        return { message: { id, conv, created, expires, envelopes }, created, expires }
      }
      let built = await attempt()
      const encryptMs = performance.now() - started
      // Ratchet state advances before the network call, so a crash cannot cause key reuse.
      await this.persist(this.vault)
      if (built.message.envelopes.length) {
        const post = async (message: unknown) => (await this.transport.send?.(message)) ?? this.transport.api('POST', '/api/messages', message)
        try {
          await post(built.message)
        } catch (error) {
          if (!(error instanceof ApiError) || error.code !== 'recipients-changed') throw error
          this.directories.delete(conv)
          await this.refreshConversations()
          id = P.uuid()
          built = await attempt()
          await this.persist(this.vault)
          if (built.message.envelopes.length) await post(built.message)
        }
      }
      return { id, created: built.created, expires: built.expires, recipients: built.message.envelopes.length, encryptMs, totalMs: performance.now() - started }
    })
  }

  async send(conv: string, text: string, options: { lifetimeSeconds?: number; file?: { name: string; type: string; bytes: Uint8Array } } = {}) {
    const lifetime = options.lifetimeSeconds ?? 24 * 3600
    let file: P.FileRef | undefined
    if (options.file) {
      const enc = P.encryptAttachment(conv, options.file.bytes)
      const { id } = await this.transport.upload(`/api/conversations/${conv}/attachments?expires=${Date.now() + lifetime * 1000 + 60_000}`, enc.ciphertext)
      file = { id, key: enc.key, nonce: enc.nonce, digest: enc.digest, name: options.file.name.slice(0, 200), type: options.file.type.slice(0, 100), size: options.file.bytes.length }
    }
    const sent = await this.dispatch(conv, { t: 'text', text, ...(file ? { file } : {}) }, lifetime)
    await this.exclusive(async () => {
      this.store({ id: sent.id, conv, from: this.me.user.id, device: this.keys.deviceId, created: sent.created, expires: sent.expires, text, file, mine: true })
      await this.save()
    })
    return sent
  }

  async openAttachment(conv: string, file: P.FileRef) {
    return P.decryptAttachment(conv, file, await this.transport.download(`/api/attachments/${file.id}`))
  }

  // ---------- receiving ----------

  private store(message: LocalMessage) {
    const list = (this.vault.messages[message.conv] ??= [])
    if (list.some((m) => m.id === message.id)) return false
    list.push(message)
    list.sort((a, b) => a.created - b.created)
    if (list.length > HISTORY_LIMIT) list.splice(0, list.length - HISTORY_LIMIT)
    return true
  }

  private decrypt(e: P.Envelope, sender: P.PublicDevice) {
    const sessions = this.vault.sessions[e.from] ?? []
    for (let i = 0; i < sessions.length; i++) {
      try {
        const result = P.ratchetDecrypt(sessions[i], e)
        // The session that worked becomes the one we send on, so both sides converge.
        this.vault.sessions[e.from] = [result.session, ...sessions.filter((_, j) => j !== i)]
        return result.plaintext
      } catch (error) {
        if (error instanceof P.ProtocolError && error.code === 'replay') throw error
      }
    }
    if (!e.pre) throw new P.ProtocolError('No session can decrypt this message.', 'decrypt-failed')
    // Accepting consumes a one-time prekey, so work on a copy until the message authenticates.
    const keys = structuredClone(this.keys)
    const result = P.ratchetDecrypt(P.acceptSession(keys, sender, e.pre), e)
    this.vault.keys = keys
    this.vault.sessions[e.from] = [result.session, ...sessions].slice(0, 3)
    return result.plaintext
  }

  /** Returns true when the envelope is finished with (delivered or permanently rejected) and can be acknowledged. */
  private async receiveOne(e: P.Envelope): Promise<boolean> {
    if (e.to !== this.keys.deviceId) return true
    if (e.expires <= Date.now()) return true
    let conversation = this.conversations.find((c) => c.id === e.conv)
    if (!conversation) {
      await this.refreshConversations()
      conversation = this.conversations.find((c) => c.id === e.conv)
      if (!conversation) return true
    }
    try {
      let directory = await this.directory(e.conv, 60_000)
      let sender = directory.devices.find((d) => d.id === e.from)
      if (!sender) {
        this.directories.delete(e.conv)
        directory = await this.directory(e.conv)
        sender = directory.devices.find((d) => d.id === e.from)
      }
      if (!sender || sender.trust !== 'trusted') throw new P.ProtocolError('Sender device is not trusted.', 'roster')
      if (!conversation.members.includes(sender.userId)) {
        // The signed roster we hold may simply be stale; re-check once before rejecting.
        await this.refreshConversations()
        conversation = this.conversations.find((c) => c.id === e.conv)
        if (!conversation?.members.includes(sender.userId)) throw new P.ProtocolError('Sender is not in the signed member list.', 'roster')
      }
      const payload = P.decodePayload(this.decrypt(e, sender))
      if (payload.t === 'meta') {
        if (sender.userId === conversation.owner && conversation.kind === 'group') {
          this.vault.names[e.conv] = payload.name.slice(0, 60)
          this.conversations = this.conversations.map((c) => (c.id === e.conv ? { ...c, title: this.title(c) } : c))
        }
      } else {
        this.store({ id: e.id, conv: e.conv, from: sender.userId, device: e.from, created: e.created, expires: e.expires, text: payload.text.slice(0, 20_000), file: payload.file, mine: sender.userId === this.me.user.id })
      }
      return true
    } catch (error) {
      if (!(error instanceof P.ProtocolError)) throw error // transient (network): leave queued and retry
      if (error.code !== 'replay') this.note(e.conv, 'warning', `A message could not be verified and was discarded (${error.message})`)
      return true
    }
  }

  /** Handles envelopes pushed over the socket or fetched from the queue; acknowledges after the vault is saved. */
  receive(envelopes: Array<P.Envelope>) {
    return this.exclusive(async () => {
      const done: Array<string> = []
      for (const e of envelopes) if (await this.receiveOne(e)) done.push(e.id)
      if (!done.length) return
      await this.save()
      const ack = { t: 'ack', ids: done }
      if ((await this.transport.send?.(ack)) == null) await this.transport.api('POST', '/api/messages/ack', { ids: done })
      const prekeyHandshakes = envelopes.filter((e) => e.pre).length
      if (prekeyHandshakes && Object.keys(this.keys.opks).length < OPK_TARGET / 2) await this.maintainPrekeys()
    })
  }

  async sync() {
    if (this.me.device.trust !== 'trusted') return
    const queued = await this.transport.api<Array<P.Envelope>>('GET', '/api/messages')
    if (queued.length) await this.receive(queued)
  }

  /** Ephemeral messages: remove expired plaintext from the vault. */
  expire(now = Date.now()) {
    return this.exclusive(async () => {
      let changed = false
      for (const [conv, list] of Object.entries(this.vault.messages)) {
        const kept = list.filter((m) => m.expires > now)
        if (kept.length !== list.length) {
          this.vault.messages[conv] = kept
          changed = true
        }
      }
      if (changed) await this.save()
    })
  }

  messages(conv: string) {
    const now = Date.now()
    return (this.vault.messages[conv] ?? []).filter((m) => m.expires > now)
  }
  notices(conv: string) {
    return this.vault.notices.filter((n) => n.conv === conv)
  }

  // ---------- device management ----------

  /** Cross-signs a pending device of this account so that contacts' clients accept it without a warning. */
  approveDevice(device: { id: string; ik: string }) {
    return this.transport.api('POST', `/api/devices/${device.id}/approve`, { sig: P.crossSign(this.keys, this.me.user.id, device.id, device.ik) })
  }
}
