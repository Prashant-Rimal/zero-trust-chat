import { performance } from 'node:perf_hooks';
import { mkdirSync, writeFileSync } from 'node:fs';
import { generateIdentity, publicIdentity, encryptMessage, decryptMessage } from '../public/crypto.js';
const a = await generateIdentity(), b = await generateIdentity();
const devices = [a, b].map(i => ({ id: i.device, ...publicIdentity(i), revision: 1 }));
const samples = [];
for (let n = 0; n < 40; n++) {
  const start = performance.now(), e = await encryptMessage(a, 'benchmark', devices, { text: 'x'.repeat(1024) });
  const encrypted = performance.now(), result = await decryptMessage(b, e, devices[0]);
  if (result.text.length !== 1024) throw new Error('Benchmark integrity failure');
  samples.push({ encryptMs: encrypted - start, decryptMs: performance.now() - encrypted, envelopeBytes: Buffer.byteLength(JSON.stringify(e)) });
}
const percentile = (field, p) => Number(samples.map(s => s[field]).sort((a, b) => a - b)[Math.ceil(samples.length * p) - 1].toFixed(3));
const report = { generatedAt: new Date().toISOString(), runtime: process.version, platform: process.platform, iterations: samples.length, payloadBytes: 1024, recipients: 2,
  encrypt: { medianMs: percentile('encryptMs', .5), p95Ms: percentile('encryptMs', .95) }, decrypt: { medianMs: percentile('decryptMs', .5), p95Ms: percentile('decryptMs', .95) },
  envelopeBytes: samples[0].envelopeBytes, notes: 'Local WebCrypto measurement; network round-trip timings are reported by integration tests and the browser composer. No production throughput claim.' };
mkdirSync('evidence', { recursive: true }); writeFileSync('evidence/benchmark.json', JSON.stringify(report, null, 2)); console.log(JSON.stringify(report, null, 2));
