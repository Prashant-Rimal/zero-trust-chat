import { createFileRoute } from '@tanstack/react-router'
import { Page } from '~/components/Shell'
import { PageHeader, Panel } from '~/components/ui'

export const Route = createFileRoute('/privacy')({ component: Privacy })

const CANNOT = [
  ['Message text', 'Encrypted on your device with a key used once and then deleted.'],
  ['Attachments and their filenames', 'Files are encrypted before upload. The name and type travel inside the encrypted message.'],
  ['Group names', 'Sent to members as an encrypted message. The database has no column for them.'],
  ['Your password', 'Your browser sends a derived login key. The key that unlocks your vault is derived separately and never leaves this device.'],
  ['Your private keys', 'Generated here and stored only in this browser, encrypted with your password.'],
  ['Past messages after a key theft', 'Keys ratchet forward with every message, so today’s keys cannot open yesterday’s ciphertext.'],
  ['Exact message length', 'Messages are padded to 256-byte steps before encryption.'],
]
const CAN = [
  ['Who is in each conversation', 'Needed to route ciphertext and enforce access. Member lists are signed by the owner so the server cannot quietly change them.'],
  ['Which device sent to which device, and when', 'Visible while a message waits for delivery. The row is deleted when the recipient device confirms receipt.'],
  ['Approximate size', 'The 256-byte size class of messages and the size of encrypted attachments.'],
  ['Your email address', 'Collected at sign-up for the workspace’s records. Stored as you typed it, not verified, and shown only to administrators and auditors.'],
  ['Usernames, roles and public keys', 'Public keys are meant to be public. Compare security codes to be sure they are the right ones.'],
  ['Security events', 'Event type, time and device id, kept 30 days. No content, no IP addresses.'],
  ['Your network, coarsely and briefly', 'A keyed hash of your network prefix and browser string is kept per session to spot hijacking. The raw values are not stored.'],
]
const LIMITS = [
  'The server delivers this app’s code. A malicious operator could ship altered JavaScript. Native apps or signed web bundles are the real fix; this prototype does not have one.',
  'Anyone with access to an unlocked device, or malware on it, can read what you can read.',
  'Disappearing messages are deleted from the server and from honest apps. A recipient can still copy or photograph them first.',
  'When two people have never verified each other, the first exchange of keys trusts the server. Comparing security codes closes that gap.',
  'Timing and volume of traffic are visible to the server and the network. There is no cover traffic or sender anonymity.',
  'This is coursework, built on reviewed primitives but not itself independently audited.',
]

function Row({ title, body }: { title: string; body: string }) {
  return (
    <li className="py-3">
      <p className="text-sm font-medium">{title}</p>
      <p className="mt-0.5 text-sm text-muted">{body}</p>
    </li>
  )
}

function Privacy() {
  return (
    <Page>
      <PageHeader eyebrow="Metadata minimisation" title="What the server can and cannot see" description="Privacy claims are only useful when they are specific. This is exactly where your trust goes — and where it doesn’t need to." />

      <div className="mb-6 grid items-stretch gap-3 text-center text-sm sm:grid-cols-[1fr_auto_1fr_auto_1fr]">
        <div className="rounded-2xl border border-sage-strong bg-sage p-4">
          <p className="font-semibold">Your device</p>
          <p className="mt-1 text-xs text-muted">Holds keys · encrypts · keeps history</p>
        </div>
        <div className="hidden items-center text-muted sm:flex">ciphertext →</div>
        <div className="rounded-2xl border border-line bg-panel p-4">
          <p className="font-semibold">Relay server + database</p>
          <p className="mt-1 text-xs text-muted">Checks access · queues ciphertext · deletes on delivery</p>
        </div>
        <div className="hidden items-center text-muted sm:flex">ciphertext →</div>
        <div className="rounded-2xl border border-sage-strong bg-sage p-4">
          <p className="font-semibold">Their devices</p>
          <p className="mt-1 text-xs text-muted">Verify · decrypt · keep history</p>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="The server cannot see">
          <ul className="divide-y divide-line">
            {CANNOT.map(([title, body]) => (
              <Row key={title} title={title} body={body} />
            ))}
          </ul>
        </Panel>
        <Panel title="The server can see">
          <ul className="divide-y divide-line">
            {CAN.map(([title, body]) => (
              <Row key={title} title={title} body={body} />
            ))}
          </ul>
        </Panel>
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <Panel title="How usage statistics stay private" description="Administrators see workspace trends, never individuals.">
          <ul className="list-disc space-y-2 pl-5 text-sm text-muted">
            <li>Counts are capped per person before they are stored, so one very active person cannot dominate a total.</li>
            <li>Each period is published once, with calibrated random noise added (differential privacy), and the per-person rows are then deleted.</li>
            <li>The noise is large enough that the published numbers look the same whether or not any one person took part.</li>
          </ul>
        </Panel>
        <Panel title="Limits you should know about">
          <ul className="list-disc space-y-2 pl-5 text-sm text-muted">
            {LIMITS.map((limit) => (
              <li key={limit}>{limit}</li>
            ))}
          </ul>
        </Panel>
      </div>
    </Page>
  )
}
