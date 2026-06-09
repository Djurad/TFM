const assert = require('assert');
const {
  construirInputHttpx,
  deduplicarHttpxResultados
} = require('../modules/reconocimiento');
const { parsearNucleiJsonl } = require('../modules/herramientas/nuclei');
const { ejecutarGau, filtrarYPriorizarUrlsGau } = require('../modules/herramientas/gau');
const {
  procesarFeroxRaw,
  esRutaInteresante,
  esPosibleVulnerabilidad
} = require('../modules/herramientas/feroxbuster');
const { extraerFindingsDeterministas } = require('../modules/procesamiento/extractores');
const { clasificarFindings } = require('../modules/procesamiento/clasificadorFindings');
const { buildFindingGroups } = require('../modules/procesamiento/findingGroups');

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
    'https://demo.testfire.net/download.php?file=a',
    'https://demo.testfire.net/search?q=%3Cscript%3Ealert(1)%3C/script%3E',
    'https://demo.testfire.net/1234567890*~1*/cgi.exe',
    'https://demo.testfire.net/api/user?id=FUZZ'
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
  assert.strictEqual(result.discardedStats.ruido_historico_descartado, 3);
  assert.ok(result.selected.some(endpoint => endpoint.url.includes('/api/user?id=1')));
  assert.ok(result.selected.some(endpoint => endpoint.url.includes('/admin')));
  assert.ok(result.selected.every(endpoint => endpoint.url.includes('demo.testfire.net')));

  const empty = filtrarYPriorizarUrlsGau([], 'demo.testfire.net');
  assert.strictEqual(empty.selected.length, 0);
}

async function testGauProvidersYFallbacks() {
  const llamadasOtx = [];
  const soloOtx = await ejecutarGau('demo.testfire.net', {
    enabled: true,
    timeoutSeconds: 10,
    ejecutarProceso: async (binario, args, timeoutMs, input) => {
      llamadasOtx.push({ binario, args, timeoutMs, input });
      return {
        stdout: 'https://demo.testfire.net/login.jsp\nhttps://demo.testfire.net/search?q=test\n',
        stderr: '',
        exitCode: 0,
        timedOut: false,
        notInstalled: false,
        error: null
      };
    }
  });

  assert.strictEqual(soloOtx.status, 'success');
  assert.strictEqual(soloOtx.metrics.source, 'gau:otx');
  assert.strictEqual(soloOtx.metrics.provider_usado, 'otx');
  assert.deepStrictEqual(soloOtx.metrics.providers_probados, ['otx']);
  assert.strictEqual(llamadasOtx.length, 1);
  assert.deepStrictEqual(llamadasOtx[0].args, ['demo.testfire.net', '--providers', 'otx', '--timeout', '10']);

  const llamadasFallback = [];
  const fallbackProvider = await ejecutarGau('demo.testfire.net', {
    enabled: true,
    timeoutSeconds: 10,
    ejecutarProceso: async (binario, args) => {
      const provider = args[2];
      llamadasFallback.push(provider || binario);
      if (provider === 'wayback') {
        return {
          stdout: '',
          stderr: 'timeout',
          exitCode: null,
          timedOut: true,
          notInstalled: false,
          error: 'timeout'
        };
      }
      if (provider === 'commoncrawl') {
        return {
          stdout: 'https://demo.testfire.net/bank/queryxpath.jsp?id=1\n',
          stderr: '',
          exitCode: 0,
          timedOut: false,
          notInstalled: false,
          error: null
        };
      }
      return {
        stdout: '',
        stderr: '',
        exitCode: 0,
        timedOut: false,
        notInstalled: false,
        error: null
      };
    }
  });

  assert.strictEqual(fallbackProvider.status, 'partial');
  assert.strictEqual(fallbackProvider.metrics.source, 'gau:commoncrawl');
  assert.deepStrictEqual(llamadasFallback, ['otx', 'wayback', 'commoncrawl']);
  assert.ok(fallbackProvider.warning.includes('timeout'));

  const fallbackWaybackurls = await ejecutarGau('demo.testfire.net', {
    enabled: true,
    timeoutSeconds: 10,
    ejecutarProceso: async binario => {
      if (binario === 'gau') {
        return {
          stdout: '',
          stderr: '',
          exitCode: null,
          timedOut: false,
          notInstalled: true,
          error: 'spawn gau ENOENT'
        };
      }
      return {
        stdout: 'https://demo.testfire.net/default.htm\n',
        stderr: '',
        exitCode: 0,
        timedOut: false,
        notInstalled: false,
        error: null
      };
    }
  });

  assert.strictEqual(fallbackWaybackurls.status, 'partial');
  assert.strictEqual(fallbackWaybackurls.metrics.source, 'waybackurls');
  assert.strictEqual(fallbackWaybackurls.metrics.fallback_waybackurls_usado, true);
  assert.strictEqual(fallbackWaybackurls.parsed.length, 1);
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

async function main() {
  testHttpxDedup();
  testGauFiltroInteligente();
  await testGauProvidersYFallbacks();
  testFeroxFixtures();
  testNucleiFixtures();
  console.log('pipelineQuality tests ok');
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
