import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
const result = spawnSync(process.execPath, ['--test', '--test-reporter=tap', '--test-concurrency=1', 'tests/crypto.test.js', 'tests/server.test.js'], { encoding: 'utf8', timeout: 120000 });
mkdirSync('evidence', { recursive: true });
writeFileSync('evidence/tests.tap', result.stdout || String(result.error || 'Test process did not return output'));
process.stdout.write(result.stdout || ''); process.stderr.write(result.stderr || ''); process.exitCode = result.status ?? 1;
