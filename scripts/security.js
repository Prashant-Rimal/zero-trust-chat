import { readdirSync, readFileSync, mkdirSync, writeFileSync } from 'node:fs';
const findings = [], checks = [
  ['dynamic-eval', /\beval\s*\(|new\s+Function\s*\(/],
  ['shell-execution', /\bexecSync\s*\(|\bexec\s*\([^'"`]/],
  ['private-key-material', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ['cloud-access-key', /AKIA[0-9A-Z]{16}/],
  ['request-body-logging', /console\.(?:log|error|info)\([^\n]*(?:req\.body|password|secret|ciphertext)/],
  ['dynamic-inner-html', /\.innerHTML\s*=\s*(?![\s'"])[^;\n]+/]
];
let scanned = 0;
for (const directory of ['server', 'public', 'shared']) for (const file of readdirSync(directory).filter(f => /\.(js|html)$/.test(f))) {
  const source = readFileSync(`${directory}/${file}`, 'utf8'); scanned++;
  for (const [rule, pattern] of checks) if (pattern.test(source)) findings.push({ file: `${directory}/${file}`, rule });
}
mkdirSync('evidence', { recursive: true });
const report = { generatedAt: new Date().toISOString(), tool: 'Cipherroom focused static policy scan', scope: ['server', 'public', 'shared'], files: scanned, rules: checks.map(c => c[0]), findings, limitation: 'Focused policy checks, not a general-purpose SAST engine. CI additionally runs Semgrep and Gitleaks.' };
writeFileSync('evidence/static-scan.json', JSON.stringify(report, null, 2));
console.log(JSON.stringify(report, null, 2)); if (findings.length) process.exitCode = 1;
