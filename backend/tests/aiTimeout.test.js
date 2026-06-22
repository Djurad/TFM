const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');

process.env.AI_DISABLE_TIMEOUTS = 'true';
process.env.AI_SINGLE_FINDING_TIMEOUT_MS = '60000';
process.env.OLLAMA_REQUEST_TIMEOUT_MS = '60000';

const {
  buildCompactAIPromptForFinding,
  getAiRuntimeConfig,
  postJsonSinTimeout,
  resolveAiTimeoutMs
} = require('../modules/ia/ia');

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server.address()));
  });
}

function close(server) {
  return new Promise(resolve => server.close(resolve));
}

async function testDelayedResponsesAreNotCancelled() {
  const delays = [90, 180];
  let call = 0;
  const server = http.createServer((req, res) => {
    const delayMs = delays[call++] || delays[delays.length - 1];
    setTimeout(() => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ response: '{"ok":true}' }));
    }, delayMs);
  });
  const address = await listen(server);
  const url = `http://127.0.0.1:${address.port}/api/generate`;

  try {
    for (const delayMs of delays) {
      const startedAt = Date.now();
      const response = await postJsonSinTimeout(url, {
        model: 'test',
        prompt: 'finding individual',
        stream: false,
        format: 'json'
      }, 0, { findingId: `delay-${delayMs}` });
      assert.ok(Date.now() - startedAt >= delayMs - 10);
      assert.strictEqual(response.response, '{"ok":true}');
    }
  } finally {
    await close(server);
  }
}

function testTimeoutConfigurationIsDisabled() {
  const config = getAiRuntimeConfig();
  assert.strictEqual(config.disableTimeouts, true);
  assert.strictEqual(config.timeoutMs, 0);
  assert.strictEqual(config.singleFindingTimeoutMs, 0);
  assert.strictEqual(resolveAiTimeoutMs(60000), 0);

  const source = fs.readFileSync(path.join(__dirname, '..', 'modules', 'ia', 'ia.js'), 'utf8');
  assert.ok(!source.includes('AI_SINGLE_FINDING_TIMEOUT_MS || 60000'));
  assert.ok(source.includes('req.setTimeout(0)'));
}

function testCompactPromptStaysIndividual() {
  const prompt = buildCompactAIPromptForFinding({
    id: 'xss-1',
    tool: 'dalfox',
    title: 'XSS confirmado',
    finalStatus: 'confirmed',
    finalSeverity: 'high',
    parameter: 'q',
    affected_url: 'https://example.test/search?q=x',
    evidence: 'Triggered XSS Payload',
    payload: '<svg onload=alert(1)>'
  }, { target: 'https://example.test', tool: 'dalfox' });

  assert.match(prompt, /Analiza este hallazgo/i);
  assert.match(prompt, /"probability"/);
  assert.doesNotMatch(prompt, /cvssVectorApprox|validationSteps|remediationSteps/);
  assert.ok(Math.ceil(prompt.length / 4) < 1500);
}

async function main() {
  await testDelayedResponsesAreNotCancelled();
  testTimeoutConfigurationIsDisabled();
  testCompactPromptStaysIndividual();
  console.log('ai timeout tests passed');
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
