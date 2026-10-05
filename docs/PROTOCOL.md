# Protocol and key lifecycle

All of this is implemented in `src/shared/protocol.ts` (primitives and state machines) and `src/client/messenger.ts` (policy: who to trust, who to encrypt to).

## Primitives

| Purpose | Primitive | Library |
|---|---|---|
| Device identity, signatures | Ed25519 | `@noble/curves` |
| Key agreement | X25519 | `@noble/curves` |
| Key derivation | HKDF-SHA-256, HMAC-SHA-256 | `@noble/hashes` |
| Message and file encryption | XChaCha20-Poly1305 (24-byte random nonce) | `@noble/ciphers` |
| Password stretching | PBKDF2-SHA-256, 600,000 iterations | WebCrypto |
| Server-side login secret | scrypt N=2^15, r=8, p=1 | Node |
| Second factor | TOTP (RFC 6238), single-use steps | Node |

Every signature and KDF input carries a domain-separation label (`cr/…/v2`).

## Keys held by a device

| Key | Type | Lifetime | Purpose |
|---|---|---|---|
| `ik` | Ed25519 | Life of the device | Identity. Signs the keys below, login challenges, rosters, device approvals. Its hash is the fingerprint. |
| `dh` | X25519 | Life of the device | Identity DH key for X3DH. Signed by `ik`. |
| `spk` | X25519 | 7 days (previous two kept for in-flight handshakes) | Signed prekey. Signed by `ik`. |
| `opk` | X25519 | Single use | One-time prekeys. 40 uploaded, replenished when half are used. |
| ratchet state | per peer device | Changes every message | Root key, chain keys, current DH pair. |

Private halves exist only in the vault, which is sealed with XChaCha20-Poly1305 under the password-derived vault key before being written to IndexedDB.

## Session setup (X3DH)

Alice's device A wants to message Bob's device B.

1. A fetches B's directory entry (`ik`, `dh`, `dhSig`) and checks it against its local pins.
2. A requests a prekey bundle (`spk`, `spkSig`, one `opk`). The server deletes that `opk`.
3. A verifies `dhSig` and `spkSig` with B's pinned `ik`, generates an ephemeral key `ek`, and computes
   `SK = HKDF(0xFF×32 ‖ DH(A.dh, B.spk) ‖ DH(ek, B.dh) ‖ DH(ek, B.spk) ‖ DH(ek, B.opk))`.
4. Associated data binds both identities: `AD = H(A.ik ‖ A.id ‖ B.ik ‖ B.id)`.
5. A's first messages carry `{ek, spkId, opkId}` until B replies. B recomputes `SK`, deleting the one-time prekey.

If the server hands B a different `ik` for A than the one A used, B derives a different `SK` and `AD`, and decryption fails closed.

## Messages (Double Ratchet)

- **Symmetric ratchet:** each message key is `HMAC(chainKey, 1)`; the chain advances with `HMAC(chainKey, 2)`. The message key is used once and wiped.
- **DH ratchet:** when a message arrives with a new ratchet public key, the receiver mixes a fresh DH output into the root key and generates a new key pair for its reply.
- **Result:** stealing a device's current state does not reveal earlier messages (forward secrecy), and stops revealing later ones once the conversation has gone back and forth (post-compromise security). Both are tested in `tests/protocol.test.ts`.
- **Out-of-order delivery:** up to 500 skipped message keys per chain are kept.
- **Failed decryption never changes state.** `ratchetDecrypt` works on a copy and returns the new state only on success, so forged or replayed envelopes cannot desynchronise a session.

### What is authenticated

The AEAD associated data is

```
["cr/msg/v2", AD, id, conversation, fromDevice, toDevice, created, expires, ratchetKey, pn, n]
```

so the server cannot change the conversation, sender, recipient, timestamp, expiry or ordering counters without the recipient noticing. Plaintext is padded to a multiple of 256 bytes before encryption.

### Simultaneous initiation

If both sides start a session at once, each device keeps up to three sessions per peer, tries each on receipt, and promotes whichever decrypts. Both sides converge on the same session after one exchange.

## Groups

A group message is one payload encrypted separately to every recipient device. There is no shared group key.

**Who counts as a member** is decided by a roster `{conv, epoch, kind, owner, members}` signed by the owner's device. Clients:

- verify the signature against the owner's pinned identity key;
- pin the owner and the highest epoch seen, and refuse a different owner or a lower epoch;
- encrypt only to devices of users in the verified roster, whatever the server's member table says;
- reject incoming messages from senders outside it.

So a server that adds a row to `members` gains nothing: no client will encrypt to the newcomer (tested).

The **group name** is sent as an encrypted control message by the owner; the server never stores it.

## Attachments

The file is encrypted in the browser with a random key (XChaCha20-Poly1305, conversation id as associated data) and uploaded as ciphertext. The key, nonce, SHA-256 of the ciphertext, filename, type and size travel inside the encrypted message. Attachments expire with the message.

## Identity verification

- **Device fingerprint:** first 8 bytes of `SHA-256("cr/devfp/v2" ‖ ik)`, shown when approving a new device.
- **User fingerprint:** 30 decimal digits from an iterated SHA-256 over the user id and the sorted identity keys of all their trusted devices.
- **Security code:** the two users' fingerprints, sorted and concatenated (60 digits). Both people see the same number. Also available as a QR code / pasteable string.

Pinning rules when a directory response arrives:

| Situation | Client behaviour |
|---|---|
| Known device id, different identity key | **Hard failure.** Sending is blocked. |
| New device, cross-signed by a device already pinned for that user | Accepted silently; verified status carries over. |
| New device, not cross-signed by a known device | Accepted, but the user's verified status is cleared and a warning appears in the conversation. |
| First time seeing a user | Trust on first use, shown as "unverified" until codes are compared. |

## Device approval (cross-signing)

A new device enrols with password + TOTP + its own identity key, and starts **pending**: it is not listed in the directory and cannot call anything except its own status. An existing trusted device approves it by signing `("cr/xsign/v2", userId, newDeviceId, newIk)` after a step-up. The server verifies that signature; contacts verify it too, which is what lets them tell an approved device from one the server invented.

## Replay protection

| Layer | Mechanism |
|---|---|
| Relay | `SHA-256(messageId ‖ recipientDevice)` tombstone kept until an hour after expiry; duplicates get HTTP 409 and an audit event |
| Relay | Messages older or newer than two minutes are refused |
| Client | A message key is deleted after use; the same counter cannot be decrypted twice |
| Client | Message id is in the associated data and history is de-duplicated by id |

## Ephemeral messages

`expires` is chosen by the sender (1 minute to 7 days), authenticated in the AEAD, and enforced in three places: the relay refuses to store or serve expired ciphertext and sweeps it; clients drop expired envelopes unread; clients delete expired plaintext from the vault. A recipient who copies the text first is outside what any protocol can prevent.

## Not provided

Header encryption, sealed sender, deniability analysis, post-quantum key agreement, multi-device history sync, key transparency log. See the threat model for the consequences.
