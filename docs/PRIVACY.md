# Privacy: metadata minimisation and differential privacy

## What the server cannot observe

| Data | Why not |
|---|---|
| Message text | Encrypted on the sender's device; keys are per message and never sent |
| Attachment bytes, filename, MIME type | File encrypted before upload; name and type are inside the encrypted message |
| Group names | Delivered as an encrypted control message; `conversations` has no name column |
| Password | Only a derived login key is sent; the server stores its scrypt hash |
| Vault key and private keys | Derived and generated in the browser; never transmitted |
| Earlier messages after a compromise | Message keys are deleted after use |
| Exact message length | Padded to 256-byte buckets |
| Whether a message was read | No read receipts, typing indicators or presence |
| Raw IP address or user agent | Stored only as a 16-character keyed hash of the /24 (or /48) and of the user-agent string |

## What the server can observe

| Data | Why it is needed | Retention |
|---|---|---|
| Usernames, roles, account status | Authentication, RBAC | Life of the account |
| Email address, as entered at sign-up (unverified) | Record-keeping only. Not used for sign-in, recovery or search. Returned only by the admin overview (`audit:read`) | Life of the account |
| Device public keys, labels, trust state | Key directory | Life of the device record |
| Conversation id, kind, owner, member list (signed roster) | Routing and access control | Life of the conversation |
| Sender device, recipient device, timestamps, size class of each queued message | Delivery | **Until the recipient device acknowledges**, or expiry, whichever is first |
| Replay tombstone: a hash of (message id, recipient) | Replay rejection | Until one hour after the message's expiry |
| Encrypted attachment and its size | Storage | Until the message expires |
| Session records: device, start, last activity, network/browser pseudonyms | Zero Trust checks | Until 24 h after expiry |
| Audit events: kind, severity, time, user id, device id | Security dashboard | 30 days |
| Per-user usage counters (capped) | Analytics | Until the reporting period closes, then deleted |

The network path additionally sees IP addresses and traffic timing, as with any web service.

## Design decisions that reduce metadata

- **Delete on delivery.** The `envelopes` table is a queue, not an archive. Tested: *deletes queued ciphertext once the recipient device acknowledges it*.
- **No names server-side.** Direct chats are titled from the other person's username on the client; groups from the encrypted name.
- **Route patterns in logs.** `/api/conversations/:id/roster`, not the actual id. Tested: *writes nothing sensitive to server logs*.
- **Audit detail allow-list.** A test fails if an audit record gains a field outside a fixed set or a value longer than 40 characters.
- **Pseudonymised context.** Session hijack detection only needs "same as before?", so only keyed hashes are stored.
- **Bounded directory search.** Prefix match, minimum two characters, ten results.
- **Schema pinned by a test.** Adding a column to `conversations`, `envelopes` or `audit` requires changing the test that documents what is stored.

## What is not hidden

The social graph (who shares a conversation), activity timing and volume. Hiding those needs sealed sender, private group membership, cover traffic or mixing, none of which are implemented.

---

## Differential privacy for usage analytics

Administrators and auditors see workspace trends: messages, attachments, sign-ins, security signals and active users per period. The design goal is that these numbers look essentially the same whether or not any one person was active.

### Mechanism

1. **Bound each person's influence.** Each event increments a per-user counter for the current period, but the counter stops at a cap (messages 20, attachments 5, sign-ins 3, signals 3). Active users counts each person at most once.
2. **Add calibrated noise.** When a period has closed, each metric total gets `Laplace(cap / ε)` noise drawn from the OS CSPRNG.
3. **Release once.** The noisy value is stored and returned for every later query. Asking a thousand times returns the same number, so the noise cannot be averaged away.
4. **Delete the inputs.** The per-user rows for that period are deleted in the same transaction.
5. **Release empty periods too**, so the absence of a data point is not itself a signal.

The open period is never shown.

### Guarantee

Adding or removing one user changes a metric's true total by at most its cap, so each released value is ε-differentially private at user level for that period. With five metrics, one user's total privacy loss for a period is at most 5ε (sequential composition). Defaults: ε = 1 per metric, daily periods. Both are configurable (`DP_EPSILON`, `DP_WINDOW_MINUTES`).

Rounding and clamping at zero happen after the noise is added and do not weaken the guarantee.

### Reading the chart honestly

With ε = 1 the noise on the messages metric has scale 20. In a workspace of three people most bars *are* noise. The admin chart draws a dashed line at three times the noise scale and renders bars below it in a lighter colour, labelled "within noise". The mechanism is doing its job: small groups cannot be measured precisely without exposing individuals.

### Limits

- The guarantee is per period. Someone active across many periods accumulates loss across them.
- Floating-point Laplace sampling has known precision side channels (Mironov, 2012). Released values are rounded to integers, which narrows but does not eliminate this. A production system should use a discrete mechanism.
- The security dashboard's audit trail is **not** differentially private. It is exact, per-user, role-restricted, and intended for incident response. Only the aggregate analytics are covered.

### Tests

`tests/dp.test.ts`: noise has zero mean and the right spread; the ε bound holds empirically on neighbouring inputs; contributions are clipped at write time; a period is released exactly once; raw rows are deleted; empty periods are released; released totals are unbiased across periods.
