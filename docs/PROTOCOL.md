# Cryptographic protocol and key lifecycle

## Primitives and wire format

WebCrypto supplies P-256 ECDSA identities, P-256 ECDH exchange keys, HKDF-SHA-256, AES-256-GCM with 96-bit random IVs and 128-bit tags, SHA-256 fingerprints and PBKDF2-SHA-256 vault encryption. The vault uses a random 128-bit salt and 600,000 iterations. Password login uses Node scrypt with N=32768, r=8, p=1 and a random salt. TOTP is RFC 6238 SHA-1, 6 digits / 30 seconds, ±1 counter tolerance, with strictly increasing successful counters. TOTP's SHA-1 is the interoperable HMAC construction, not a message signature algorithm.

## Enrollment

1. Browser generates a device ID, ECDSA identity key and ECDH exchange key.
2. Identity key signs a certificate binding **device ID, epoch and exchange public key**. The server verifies this and recipients independently verify it.
3. Private material and locally pinned identities are encrypted in a browser vault under a password-derived key. Neither the vault nor private key material is uploaded.
4. Password + authenticator verification creates a random 256-bit session. Only its SHA-256 hash is stored server-side; the token travels in an HttpOnly cookie. The API returns a separate CSRF token.

## Message send

1. Fetch current trusted devices for every active room member. Verify signed exchange certificates, compare identity pins and reject decreasing epochs or altered certificates within the same epoch.
2. Generate a fresh random 256-bit content key and ephemeral P-256 ECDH sender key pair.
3. Encrypt JSON containing text and optional file bytes/name with AES-GCM. Additional authenticated data binds protocol version, message ID, room, sender, creation and expiration.
4. For each recipient device (including sender's device), perform ephemeral-static ECDH. HKDF uses a protocol domain separator and message/room/sender/recipient/epoch context. Wrap the content key with AES-GCM using that context as AAD.
5. ECDSA-sign the canonical envelope, including ephemeral key, all metadata, ciphertext and all recipient wraps. ECDSA uses SHA-256 and IEEE P1363 signature encoding on both sides.
6. The relay enforces session/device/room authorization, sender match, allowable time bounds, exact current recipient set and epochs, sender signature, and replay ID uniqueness. Only the canonical envelope is retained.

## Receive

1. Session and membership checked again before WebSocket delivery.
2. Browser checks sender device identity and envelope signature before decryption. Expired messages are rejected.
3. Locate the wrap for this device and epoch. Derive its wrapping key, decrypt the content key, then authenticate/decrypt the payload.
4. Display with DOM `textContent`. Decrypted attachments are downloaded as an octet-stream blob and never rendered as active HTML.
5. Browser deduplicates IDs, removes expired content from the DOM, and clears app references on sign-out. Plaintext is never intentionally persisted; JS garbage collection does not promise secure memory erasure.

## Identity verification and key substitution

Fingerprints hash the canonical ECDSA public JWK. They are pinned at first use and stored inside the encrypted local vault. Users compare the full hex fingerprint over a separate authenticated channel before marking it verified. A signed exchange certificate stops the server from replacing an existing pinned identity's ECDH key without its signing key. A full identity swap is blocked after pinning.

**Residual risk:** first contact, deliberately enrolled new device identities, and a malicious server injecting a new apparently valid device still require participant verification. There is no global key-transparency log or signed room roster. New-device warnings are advisory; the prototype permits messaging before manual fingerprint verification. Do not describe this as protection from every active malicious relay attack.

## Forward-secrecy design: bounded epochs, not a Double Ratchet

Each message has a unique content key and sender ephemeral ECDH key. However, wrapping is ephemeral-static against recipient exchange keys: compromise of a recipient's current private exchange key can decrypt recorded envelopes addressed to that key. **Per-message sender ephemerality alone is not full forward secrecy.**

The implemented rotation action signs a new recipient exchange key/epoch and overwrites the previous key in the active vault. Older envelopes become inaccessible on that device. Rotation is staged in the encrypted vault before the server update; a subsequent sign-in reconciles a crash between remote and local commit. Do not restore an old browser vault backup expecting forward secrecy to hold.

Limits: rotation is manual, old browser/OS snapshots may contain old keys, other recipient devices have their own key lifecycles, and there is no automatic ratchet, one-time prekey protocol or post-compromise recovery. A production successor should replace the custom wire protocol with a vetted Signal-style or MLS implementation and get independent review.

## Expiration and replay

Expiration is signed and authenticated. Reads immediately filter expired rows; a five-second cleanup deletes payloads. Replay IDs remain for eight days, exceeding the seven-day maximum message lifetime, and the creation-time acceptance window is two minutes. This blocks re-inserting an expired identifier while it could otherwise be accepted. Recipient screenshots, downloads, malicious clients, SQLite WAL files and backups prevent guaranteed deletion claims.

## Sources

- [WebCrypto encryption / AES-GCM](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt)
- [WebCrypto primitives](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto)
- [Node crypto / scrypt](https://nodejs.org/api/crypto.html)
- [RFC 6238 TOTP](https://www.rfc-editor.org/rfc/rfc6238)

These describe primitives and APIs; they do not constitute an audit or endorsement of this composed protocol.
