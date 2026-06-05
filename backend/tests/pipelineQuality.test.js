const assert = require('assert');
const {
  construirInputHttpx,
  deduplicarHttpxResultados,
  parsearNucleiJsonl
} = require('../modules/reconocimiento');
const { filtrarYPriorizarUrlsGau } = require('../modules/gau');
const {
  procesarFeroxRaw,
  esRutaInteresante,
  esPosibleVulnerabilidad
} = require('../modules/feroxbuster');
const { extraerFindingsDeterministas } = require('../modules/extractores');
const { clasificarFindings } = require('../modules/clasificadorFindings');
const { buildFindingGroups } = require('../modules/findingGroups');

function testHttpxDedup() {
  const inputDemo = construirInputHttpx(
    { original: 'demo.testfire.net', inputUrl: 'https://demo.testfire.net', baseUrl: 'https://demo.testfire.net' },
    ['demo.testfire.net']
  );
  assert.deepStrictEqual(inputDemo, ['demo.testfire.net']);

  const inputHttps = construirInputHttpx(
    { original: 'https://demo.testfire.net', inputUrl: 'https://demo.testfire.net', baseUrl: 'https://demo.testfire.net' },
    ['demo.testfire.net']
  );
  assert.deepStrictEqual(inputHttps, ['https://demo.testfire.net']);

  const inputPort = construirInputHttpx(
    { original: 'http://example.com:8080', inputUrl: 'http://example.com:8080', baseUrl: 'http://example.com:8080' },
    ['example.com']
  );
  assert.ok(inputPort.includes('http://example.com:8080'));

  const inputLocal = construirInputHttpx(
    { original: 'localhost:3000', inputUrl: 'https://localhost:3000', baseUrl: 'https://localhost:3000' },
    ['localhost']
  );
  assert.ok(inputLocal.includes('localhost:3000'));

  const dedup = deduplicarHttpxResultados([
    { input: 'https://demo.testfire.net', url: 'https://demo.testfire.net', finalUrl: 'https://demo.testfire.net', statusCode: 200 },
    { input: 'demo.testfire.net', url: 'https://demo.testfire.net', finalUrl: 'https://demo.testfire.net', statusCode: 200 }
  ]);
  assert.strictEqual(dedup.metrics.respuestas_httpx, 2);
  assert.strictEqual(dedup.metrics.activos_vivos, 1);
  assert.strictEqual(dedup.metrics.duplicados_httpx, 1);
}

function testGauFiltroInteligente() {
  const assets = Array.from({ length: 1000 }, (_, index) => `https://demo.testfire.net/static/file${index}.css`);
  const raw = [
    ...assets,
    'https://github.com/org/project',
    'https://hcl-software.com/',
    'https://demo.testfire.net/search?q=one',
    'https://demo.testfire.net/search?q=two',
    'https://demo.testfire.net/search?q=three',
    'https://demo.testfire.net/search?q=four',
    'https://demo.testfire.net/admin',
    'https://demo.testfire.net/api/user?id=1',
    'https://demo.testfire.net/download.php?file=a'
  ];

  const result = filtrarYPriorizarUrlsGau(raw, 'demo.testfire.net', {
    maxParamUrls: 100,
    maxSurfaceUrls: 100,
    maxTotal: 300,
    maxPerPattern: 3
  });

  assert.strictEqual(result.discardedStats.assets_descartados, 1000);
  assert.strictEqual(result.discardedStats.urls_externas_descartadas, 2);
  assert.strictEqual(result.discardedStats.patrones_deduplicados, 1);
  assert.ok(result.selected.some(endpoint => endpoint.url.includes('/api/user?id=1')));
  assert.ok(result.selected.some(endpoint => endpoint.url.includes('/admin')));
  assert.ok(result.selected.every(endpoint => endpoint.url.includes('demo.testfire.net')));

  const empty = filtrarYPriorizarUrlsGau([], 'demo.testfire.net');
  assert.strictEqual(empty.selected.length, 0);
}

function testFeroxFixtures() {
  const empty = procesarFeroxRaw('');
  assert.strictEqual(empty.endpoints.length, 0);
  assert.strictEqual(empty.stats.raw_lineas, 0);

  const adminRaw = JSON.stringify({ url: 'https://example.test/admin', status: 200 }) + '\n';
  const admin = procesarFeroxRaw(adminRaw);
  assert.strictEqual(admin.endpoints.length, 1);
  assert.ok(esRutaInteresante(admin.endpoints[0].url));
  assert.strictEqual(esPosibleVulnerabilidad(admin.endpoints[0].url, admin.endpoints[0].status), false);

  const envRaw = JSON.stringify({ url: 'https://example.test/.env', status: 200 }) + '\n';
  const env = procesarFeroxRaw(envRaw);
  assert.strictEqual(env.endpoints.length, 1);
  assert.strictEqual(esPosibleVulnerabilidad(env.endpoints[0].url, env.endpoints[0].status), true);

  const cssRaw = JSON.stringify({ url: 'https://example.test/style.css', status: 200 }) + '\n';
  const css = procesarFeroxRaw(cssRaw);
  assert.strictEqual(css.endpoints.length, 0);
  assert.strictEqual(css.stats.descartados_assets, 1);
}

function testNucleiFixtures() {
  assert.deepStrictEqual(parsearNucleiJsonl(''), []);

  const infoLine = JSON.stringify({
    'template-id': 'tech-detect',
    info: { name: 'Technology Detection', severity: 'info', tags: ['tech'] },
    host: 'https://example.test',
    'matched-at': 'https://example.test'
  });
  const highLine = JSON.stringify({
    'template-id': 'exposed-env',
    info: { name: 'Env exposed', severity: 'high', tags: ['exposure'] },
    host: 'https://example.test',
    'matched-at': 'https://example.test/.env'
  });
  const mediumLine = JSON.stringify({
    'template-id': 'cors-misconfig',
    info: { name: 'CORS misconfig', severity: 'medium', tags: ['misconfig'] },
    host: 'https://example.test',
    'matched-at': 'https://example.test'
  });

  const findings = extraerFindingsDeterministas('nuclei', {
    parsed: [infoLine, highLine, mediumLine]
  }, 'https://example.test');
  const groups = buildFindingGroups(clasificarFindings(findings));

  assert.strictEqual(groups.informational.some(f => f.templateID === 'tech-detect'), true);
  assert.strictEqual([...groups.confirmed, ...groups.possible].some(f => f.templateID === 'exposed-env'), true);
  assert.strictEqual(groups.possible.some(f => f.templateID === 'cors-misconfig'), true);
}

testHttpxDedup();
testGauFiltroInteligente();
testFeroxFixtures();
testNucleiFixtures();

console.log('pipelineQuality tests ok');
