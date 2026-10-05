/**
 * Browser glue around the Messenger: vault storage in IndexedDB, fetch + WebSocket transport,
 * sign-in flow and a small observable store for React.
 */
import { useSyncExternalStore } from 'react'
import * as P from '../shared/protocol'
import { ApiError, Messenger, newVault } from './messenger'
import type { Me, Transport, VaultState } from './messenger'

export type AppState = {
  phase: 'locked' | 'mfa' | 'ready'
  busy: boolean
  username: string
  me: Me | null
  enrol: { secret: string; uri: string } | null
  /** True when this browser has never completed sign-in for the account, so the device needs a name. */
  newDevice: boolean
  connection: 'offline' | 'connecting' | 'live'
  /** Bumped when the messenger's state changes, so components re-read it. */
  version: number
  /** Bumped when the server says devices / security / account data changed. */
  remote: number
  toast: { text: string; error: boolean; id: number } | null
  stepUp: { resolve: () => void; reject: (error: Error) => void } | null
  lastSend: { encryptMs: number; totalMs: number; recipients: number } | null
}

let state: AppState = { phase: 'locked', busy: false, username: '', me: null, enrol: null, newDevice: true, connection: 'offline', version: 0, remote: 0, toast: null, stepUp: null, lastSend: null }
const listeners = new Set<() => void>()
function set(patch: Partial<AppState>) {
  state = { ...state, ...patch }
  for (const listener of listeners) listener()
}
const subscribe = (listener: () => void) => (listeners.add(listener), () => void listeners.delete(listener))
export const useApp = () => useSyncExternalStore(subscribe, () => state, () => state)
export const getState = () => state

let messenger: Messenger | null = null
let vault: VaultState | null = null
let vaultKey: Uint8Array | null = null
let challenge = ''
let socket: WebSocket | null = null
let reconnect: ReturnType<typeof setTimeout> | undefined
let timers: Array<ReturnType<typeof setInterval>> = []
const pending = new Map<string, { resolve: (value: unknown) => void; reject: (error: Error) => void }>()

export const getMessenger = () => messenger!

export function toast(text: string, error = false) {
  set({ toast: { text, error, id: Date.now() } })
}
export const dismissToast = () => set({ toast: null })

// ---------- vault storage ----------

function idb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('cipherroom', 1)
    open.onupgradeneeded = () => open.result.createObjectStore('vaults')
    open.onsuccess = () => resolve(open.result)
    open.onerror = () => reject(open.error)
  })
}
async function idbGet(key: string) {
  const db = await idb()
  return new Promise<any>((resolve, reject) => {
    const request = db.transaction('vaults').objectStore('vaults').get(key)
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
  })
}
async function idbPut(key: string, value: unknown) {
  const db = await idb()
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction('vaults', 'readwrite')
    tx.objectStore('vaults').put(value, key)
    tx.oncomplete = () => resolve()
    tx.onerror = () => reject(tx.error)
  })
}
const label = (username: string) => `cr/vault/v2|${username}`
/** The vault (keys, ratchet sessions, pins, history) is only ever written to disk encrypted. */
async function persist(next: VaultState) {
  if (!vaultKey) return
  await idbPut(state.username, P.seal(vaultKey, label(state.username), new TextEncoder().encode(JSON.stringify(next))))
}

// ---------- transport ----------

async function http(method: string, path: string, body?: BodyInit, json = true) {
  const headers: Record<string, string> = {}
  if (json && body !== undefined) headers['Content-Type'] = 'application/json'
  if (state.me && method !== 'GET') headers['X-CSRF-Token'] = state.me.csrf
  const response = await fetch(path, { method, headers, body, credentials: 'same-origin' })
  if (!response.ok) {
    const data = await response.json().catch(() => ({ error: 'Request failed.' }))
    if (response.status === 401 && data.code === 'unauthenticated' && state.phase === 'ready') lock('Your session ended. Sign in again.')
    throw new ApiError(response.status, data.error, data.code)
  }
  return response
}
export async function api<T = any>(method: string, path: string, body?: unknown): Promise<T> {
  return (await http(method, path, body === undefined ? undefined : JSON.stringify(body))).json()
}

const transport: Transport = {
  api,
  upload: async (path, bytes) => (await http('POST', path, bytes as BodyInit, false)).json(),
  download: async (path) => new Uint8Array(await (await http('GET', path)).arrayBuffer()),
  send(message: any) {
    if (socket?.readyState !== WebSocket.OPEN) return null
    if (message.t === 'ack') {
      socket.send(JSON.stringify(message))
      return Promise.resolve(true)
    }
    const ref = P.uuid()
    return new Promise((resolve, reject) => {
      pending.set(ref, { resolve, reject })
      socket!.send(JSON.stringify({ t: 'send', ref, message }))
      setTimeout(() => pending.delete(ref) && reject(new Error('The server did not confirm delivery in time.')), 15_000)
    })
  },
}

function connect() {
  if (!state.me || socket) return
  set({ connection: 'connecting' })
  const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`)
  socket = ws
  ws.onmessage = (event) => {
    const frame = JSON.parse(event.data)
    if (frame.t === 'ready') {
      set({ connection: 'live' })
      void messenger?.sync().catch(report)
    } else if (frame.t === 'envelope') void messenger?.receive([frame.e]).catch(report)
    else if (frame.t === 'sent') {
      const waiter = pending.get(frame.ref)
      pending.delete(frame.ref)
      if (frame.ok) waiter?.resolve(frame)
      else waiter?.reject(new ApiError(frame.status, frame.error, frame.code))
    } else if (frame.t === 'sync') {
      if (frame.what === 'conversations') void messenger?.refresh().catch(report)
      else if (frame.what === 'me') void refreshMe()
      else {
        if (frame.what === 'devices') void refreshMe()
        set({ remote: state.remote + 1 })
      }
    }
  }
  ws.onclose = (event) => {
    if (socket === ws) socket = null
    for (const waiter of pending.values()) waiter.reject(new Error('Connection lost before the server confirmed delivery.'))
    pending.clear()
    if (state.phase !== 'ready') return
    set({ connection: 'offline' })
    if (event.code === 4001) return lock('Your session was revoked or expired.')
    clearTimeout(reconnect)
    reconnect = setTimeout(async () => {
      // Confirms the session is still valid (and locks if not) before reconnecting.
      if (await refreshMe()) connect()
    }, 2500)
  }
  ws.onerror = () => ws.close()
}

const report = (error: unknown) => toast((error as Error)?.message ?? 'Something went wrong.', true)

async function refreshMe() {
  try {
    const me = await api<Me>('GET', '/api/me')
    const becameTrusted = state.me?.device.trust === 'pending' && me.device.trust === 'trusted'
    set({ me })
    if (messenger) messenger.me = me
    if (becameTrusted) await messenger?.start(me)
    return true
  } catch {
    return false
  }
}

// ---------- sign-in ----------

export async function signIn(mode: 'login' | 'register', usernameInput: string, password: string, email = '') {
  const username = usernameInput.trim().toLowerCase()
  set({ busy: true })
  try {
    const keys = await P.deriveKeys(username, password)
    const sealed = await idbGet(username)
    let opened: VaultState
    if (sealed) {
      try {
        opened = JSON.parse(new TextDecoder().decode(P.unseal(keys.vaultKey, label(username), sealed)))
      } catch {
        throw new Error('That password does not unlock the key vault stored in this browser.')
      }
    } else opened = newVault()
    vault = opened
    vaultKey = keys.vaultKey
    set({ username, newDevice: !opened.enrolled })

    // Reloading the page drops the vault key from memory; if the server session is still valid
    // for this exact device, unlocking the vault is enough.
    if (mode === 'login' && sealed) {
      const existing = await fetch('/api/me', { credentials: 'same-origin' })
      if (existing.ok) {
        const me: Me = await existing.json()
        if (me.user.username === username && me.device.id === opened.keys.deviceId) return await enter(me)
      }
    }
    const result =
      mode === 'login'
        ? await api('POST', '/api/auth/login', { username, authKey: keys.authKey })
        : await api('POST', '/api/auth/register', { username, email: email.trim(), authKey: keys.authKey })
    challenge = result.challenge
    set({ phase: 'mfa', enrol: result.secret ? { secret: result.secret, uri: result.uri } : null })
  } finally {
    set({ busy: false })
  }
}

export async function completeSignIn(code: string, deviceLabel: string) {
  if (!vault) return
  set({ busy: true })
  try {
    const body = Messenger.enrolment(vault, challenge, code.trim(), deviceLabel.trim() || 'Browser')
    // One-time prekeys were minted for the request; store their private halves before the server learns the public ones.
    await persist(vault)
    const me = await api<Me>('POST', '/api/auth/verify', body)
    await enter(me)
  } finally {
    set({ busy: false })
  }
}

async function enter(me: Me) {
  messenger = new Messenger(vault!, transport, persist)
  messenger.me = me
  messenger.subscribe(() => set({ version: state.version + 1 }))
  vault!.enrolled = true
  set({ phase: 'ready', me, enrol: null })
  await persist(vault!)
  await messenger.start(me)
  connect()
  timers = [
    setInterval(() => void messenger?.expire().catch(() => {}), 5_000),
    // Keeps the idle timer honest while the tab is open, and notices approval of a pending device.
    setInterval(() => void (socket?.readyState === WebSocket.OPEN ? socket.send('{"t":"ping"}') : refreshMe()), 60_000),
    setInterval(() => state.me?.device.trust === 'pending' && void refreshMe(), 5_000),
  ]
}

export function cancelSignIn() {
  vault = null
  vaultKey?.fill(0)
  vaultKey = null
  challenge = ''
  set({ phase: 'locked', enrol: null })
}

/** Drops keys and plaintext from memory. The encrypted vault stays in IndexedDB for the next unlock. */
export function lock(reason?: string) {
  for (const timer of timers) clearInterval(timer)
  timers = []
  clearTimeout(reconnect)
  const ws = socket
  socket = null
  ws?.close()
  messenger = null
  vault = null
  vaultKey?.fill(0)
  vaultKey = null
  state.stepUp?.reject(new Error('Signed out.'))
  set({ phase: 'locked', me: null, enrol: null, connection: 'offline', stepUp: null, lastSend: null, version: state.version + 1 })
  if (reason) toast(reason, true)
}

export async function logout() {
  await api('POST', '/api/auth/logout', {}).catch(() => {})
  lock()
  toast('Signed out. Keys were cleared from memory.')
}

// ---------- step-up authentication ----------

/** Runs a sensitive action; if the server asks for a fresh second factor, prompts for it and retries once. */
export async function withStepUp<T>(action: () => Promise<T>): Promise<T> {
  try {
    return await action()
  } catch (error) {
    if (!(error instanceof ApiError) || error.code !== 'step-up-required') throw error
    await new Promise<void>((resolve, reject) => set({ stepUp: { resolve, reject } }))
    return action()
  }
}
export async function submitStepUp(code: string) {
  await api('POST', '/api/auth/stepup', { code: code.trim() })
  const waiting = state.stepUp
  set({ stepUp: null })
  await refreshMe()
  waiting?.resolve()
}
export function cancelStepUp() {
  const waiting = state.stepUp
  set({ stepUp: null })
  waiting?.reject(new Error('Verification cancelled.'))
}

export const noteSend = (lastSend: AppState['lastSend']) => set({ lastSend })

/** Wraps a UI action so failures surface as a toast instead of an unhandled rejection. */
export async function guard(action: () => Promise<unknown>) {
  try {
    await action()
  } catch (error) {
    report(error)
  }
}
