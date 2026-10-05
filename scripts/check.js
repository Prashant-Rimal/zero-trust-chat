import { readdirSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const folders = ['server', 'public', 'shared', 'scripts', 'tests'];
let count = 0;
for (const folder of folders) for (const file of readdirSync(folder).filter(f => f.endsWith('.js'))) {
  const path = `${folder}/${file}`, result = spawnSync(process.execPath, ['--check', path], { encoding: 'utf8' });
  if (result.status) { process.stderr.write(result.stderr); process.exit(1); } count++;
}
JSON.parse(readFileSync('package.json', 'utf8'));
console.log(`Build validation passed: ${count} JavaScript modules; static browser assets served directly, no bundler needed.`);
