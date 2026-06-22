const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const tests = fs.readdirSync(__dirname)
  .filter(name => name.endsWith('.test.js'))
  .sort();
const failed = [];

for (const test of tests) {
  process.stdout.write(`\n=== ${test} ===\n`);
  const result = spawnSync(process.execPath, [path.join(__dirname, test)], {
    cwd: path.join(__dirname, '..'),
    stdio: 'inherit',
    env: process.env
  });
  if (result.status !== 0) failed.push(test);
}

if (failed.length) {
  console.error(`\nTests fallidos: ${failed.join(', ')}`);
  process.exit(1);
}

console.log(`\n${tests.length} archivos de test superados.`);
