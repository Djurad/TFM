const assert = require('assert');
const { extraerFindingsDeterministas } = require('../modules/procesamiento/extractores');
const { clasificarFindings } = require('../modules/procesamiento/clasificadorFindings');
const {
  getFinalSeverity,
  getFinalStatus,
  normalizeFindingsForReporting
} = require('../modules/priorizacion/findingGroups');

function findings(tool, result) {
  return normalizeFindingsForReporting(
    clasificarFindings(extraerFindingsDeterministas(tool, result, 'example.test'))
  );
}

function testHeadersFindings() {
  const result = findings('headers', {
    status: 'success',
    parsed: [{
      url: 'https://example.test',
      statusCode: 200,
      missing: ['content-security-policy', 'strict-transport-security', 'x-frame-options'],
      banners: []
    }]
  });

  assert.ok(result.length >= 3);
  assert.ok(result.every(f => getFinalStatus(f) === 'hardening'));
  const csp = result.find(f => f.title.includes('Content-Security-Policy'));
  assert.strictEqual(getFinalSeverity(csp), 'medium');
  assert.strictEqual(csp.evidenceStrength, 'medium');
}

function testCookiesFindings() {
  const result = findings('cookies', {
    status: 'success',
    parsed: [{
      url: 'https://example.test',
      statusCode: 200,
      isHttps: true,
      cookies: [{
        name: 'JSESSIONID',
        isSessionCookie: true,
        secure: true,
        httpOnly: true,
        sameSite: null,
        path: '/'
      }]
    }]
  });

  assert.strictEqual(result.length, 1);
  assert.strictEqual(getFinalStatus(result[0]), 'hardening');
  assert.strictEqual(getFinalSeverity(result[0]), 'medium');
  assert.ok(/SameSite/.test(result[0].evidence));
}

function testHttpsRedirectFinding() {
  const result = findings('httpsRedirect', {
    status: 'success',
    parsed: [{
      url: 'http://example.test',
      statusCode: 200,
      location: null,
      redirectsToHttps: false,
      httpAccessibleWithoutRedirect: true
    }]
  });

  assert.strictEqual(result.length, 1);
  assert.strictEqual(getFinalStatus(result[0]), 'hardening');
  assert.strictEqual(getFinalSeverity(result[0]), 'medium');
}

function testTlsFinding() {
  const result = findings('tls', {
    status: 'success',
    parsed: [{
      host: 'example.test',
      validTo: '2026-07-01',
      daysRemaining: 2,
      expired: false,
      nearExpiry: true,
      authorizationError: null,
      issuer: { CN: 'Example CA' }
    }]
  });

  assert.strictEqual(result.length, 1);
  assert.strictEqual(getFinalStatus(result[0]), 'hardening');
  assert.strictEqual(getFinalSeverity(result[0]), 'medium');
}

function testPortsFindings() {
  const result = findings('ports', {
    status: 'success',
    parsed: [
      { host: 'example.test', port: 80, service: 'http', source: 'nmap', category: 'web' },
      { host: 'example.test', port: 443, service: 'https', source: 'nmap', category: 'web' },
      { host: 'example.test', port: 8080, service: 'http-proxy', source: 'nmap', category: 'web-alt' }
    ]
  });

  const alt = result.find(f => f.affected_url.includes(':8080'));
  assert.ok(alt);
  assert.strictEqual(getFinalStatus(alt), 'surface');
  assert.strictEqual(getFinalSeverity(alt), 'low');
}

function testSqlmapPossibleFinding() {
  const result = findings('sqlmap', {
    status: 'success',
    parsed: [{
      status: 'possible_sqli',
      url: 'https://example.test/item?id=1',
      evidencia: 'possible_sqli sin payload, DBMS ni extraccion'
    }]
  });

  assert.strictEqual(result.length, 1);
  assert.strictEqual(getFinalStatus(result[0]), 'possible');
  assert.strictEqual(getFinalSeverity(result[0]), 'high');
  assert.strictEqual(result[0].requiresManualValidation, true);
}

function testGfFinding() {
  const result = findings('gf', {
    status: 'success',
    parsed: {
      xssCandidates: ['https://example.test/search?q=test']
    }
  });

  assert.strictEqual(result.length, 1);
  assert.strictEqual(getFinalStatus(result[0]), 'candidate');
  assert.notStrictEqual(getFinalStatus(result[0]), 'confirmed');
}

testHeadersFindings();
testCookiesFindings();
testHttpsRedirectFinding();
testTlsFinding();
testPortsFindings();
testSqlmapPossibleFinding();
testGfFinding();

console.log('toolFindings tests passed');
