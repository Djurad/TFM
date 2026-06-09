const assert = require('assert');
const { parsearDalfox } = require('../modules/herramientas/dalfox');
const { extraerFindingsDeterministas } = require('../modules/procesamiento/extractores');
const { clasificarFindings } = require('../modules/procesamiento/clasificadorFindings');
const { buildFindingGroups } = require('../modules/procesamiento/findingGroups');
const { calcularRiskScore } = require('../modules/procesamiento/scoring');

const fixture = `[
{"type":"V","inject_type":"inHTML-URL","poc_type":"plain","method":"GET","data":"https://demo.testfire.net/util/serverStatusCheckService.jsp?HostName=%22%3E%3Csvg+onload%3D%22setInterval%28%27alert%281%29%27%2C1000%29%22+class%3Ddalfox%3E","param":"HostName","payload":"\\"><svg onload=\\"setInterval('alert(1)',1000)\\" class=dalfox>","evidence":"4 line:  \\t\\"HostName\\": \\"\\"><svg onload=\\"setInterval('alert(1)',1000)\\" class=dalfox>\\",\\r","cwe":"CWE-79","severity":"High","message_id":527,"message_str":"Triggered XSS Payload (found DOM Object): HostName=\\"\\"><svg onload=\\"setInterval('alert(1)',1000)\\" class=dalfox>"},
{}]`;

function testParserFormats() {
  assert.deepStrictEqual(parsearDalfox(''), []);
  assert.deepStrictEqual(parsearDalfox('[{}]'), []);
  assert.strictEqual(parsearDalfox('{"type":"V","data":"https://example.test/?q=x"}').length, 1);
  assert.strictEqual(parsearDalfox('{"type":"V","data":"https://example.test/?q=x"}\n{}').length, 1);
}

function testConfirmedDalfoxFinding() {
  const parsed = parsearDalfox(fixture);
  assert.strictEqual(parsed.length, 1);

  const rawFindings = extraerFindingsDeterministas('dalfox', {
    status: 'success',
    raw: fixture,
    parsed,
    findings: []
  }, 'demo.testfire.net');
  const classified = clasificarFindings(rawFindings);
  const groups = buildFindingGroups(classified);
  const risk = calcularRiskScore(classified);

  assert.strictEqual(groups.confirmed.length, 1);
  assert.strictEqual(groups.possible.length, 0);
  assert.strictEqual(groups.confirmed[0].title, 'XSS confirmado por Dalfox');
  assert.strictEqual(groups.confirmed[0].severity, 'high');
  assert.strictEqual(groups.confirmed[0].confidence, 'high');
  assert.strictEqual(groups.confirmed[0].cwe, 'CWE-79');
  assert.strictEqual(groups.confirmed[0].param, 'HostName');
  assert.ok(groups.confirmed[0].payload.includes('<svg'));
  assert.ok(groups.confirmed[0].affected_url.includes('serverStatusCheckService.jsp'));
  assert.ok((risk.risk_score || 0) >= 35);
}

testParserFormats();
testConfirmedDalfoxFinding();

console.log('dalfox tests passed');
