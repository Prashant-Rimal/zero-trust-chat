# Safe incident simulation

Scenario: an enrolled device is suspected compromised after an anomalous login/device event. Contain its future access without reading conversations.

## Automated demonstration

Run `npm test` and `npm run test:browser`. The integration test also submits a replay and a signed-field tampering attempt to create detectable events. Browser tests enroll two synthetic users, exchange messages, and have the administrator revoke the second account.

Expected evidence:

- Detection: `device.enrolled`, `message.replay_blocked` and `message.integrity_failed` events with warning/high severity and no message text.
- Response: device owner uses My devices → Revoke, or administrator uses Security center → Account containment.
- Containment: connected WebSocket receives close code 4001; browser locks; subsequent API request returns 401; next device list excludes revoked devices.
- Least privilege: an ordinary member trying the administrator endpoint receives 403; a stale step-up window receives 403 until MFA is refreshed.
- Recovery: retain minimal audit evidence, inspect and clean the suspected endpoint, then enroll a fresh browser identity for a still-active account or a new synthetic account in a new lab channel. Previous device history is not transferred. Browser test validates new-epoch messaging after key rotation before demonstrating full account containment.

Account restoration and automatic device remediation are not implemented. The incident demonstration proves detection and containment plus a valid rekeyed communication path; a production organization must define human account recovery and identity re-verification procedures.

## Manual exercise

1. Create Alice (administrator) and Bob (member) in separate browsers using synthetic credentials.
2. Chat and note Bob's device and Alice's security events.
3. On Alice, use Verify identity if the last successful MFA is older than five minutes.
4. Revoke Bob under Account containment. Observe Bob's UI return to sign-in immediately.
5. Attempt Bob's old session access: it is denied. Alice can see the account revocation event without knowing Bob's private message keys.
6. Save only redacted event/evidence information. Do not copy session cookies, MFA seeds, real names or private keys into a report.

Tests are safe to repeat: disposable identities/databases are cleaned up. Real account revocation is a persistent action, so use the test harness or dedicated lab accounts.
