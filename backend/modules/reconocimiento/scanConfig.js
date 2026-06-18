function parseBool(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  return ['1', 'true', 'yes', 'si', 'on'].includes(String(value).toLowerCase());
}

function parseNumber(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parseTimeoutMs(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  const raw = String(value).trim().toLowerCase();
  if (['0', 'none', 'null', 'false', 'off', 'disabled', 'sin-timeout'].includes(raw)) return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function parseSecondsToMs(value, fallback) {
  const timeout = parseTimeoutMs(value, fallback === null ? null : Number(fallback) / 1000);
  return timeout === null ? null : timeout * 1000;
}

function parseLimit(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  const raw = String(value).trim().toLowerCase();
  if (['0', 'none', 'null', 'false', 'off', 'all', 'unlimited'].includes(raw)) return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function modeDefaults(mode) {
  if (mode === 'quick') {
    return {
      activeTimeoutMs: 120000,
      nucleiTimeoutMs: 90000,
      dalfoxTimeoutMs: 120000,
      sqlmapTimeoutMs: 120000,
      trufflehogTimeoutMs: 120000,
      feroxbusterTimeoutMs: 120000,
      katanaTimeoutMs: 120000,
      gauTimeoutSeconds: 10,
      passiveTimeoutMs: 12000,
      idleTimeoutMs: null,
      killOnIdle: false,
      maxNucleiUrls: 30,
      maxDalfoxUrls: 50,
      maxSqlmapUrls: 10,
      maxFeroxUrls: 100,
      maxJsSecretScan: 20
    };
  }

  if (mode === 'balanced') {
    return {
      activeTimeoutMs: 300000,
      nucleiTimeoutMs: 300000,
      dalfoxTimeoutMs: 300000,
      sqlmapTimeoutMs: 300000,
      trufflehogTimeoutMs: 300000,
      feroxbusterTimeoutMs: 300000,
      katanaTimeoutMs: 300000,
      gauTimeoutSeconds: 45,
      passiveTimeoutMs: 15000,
      idleTimeoutMs: null,
      killOnIdle: false,
      maxNucleiUrls: 80,
      maxDalfoxUrls: 120,
      maxSqlmapUrls: 30,
      maxFeroxUrls: 250,
      maxJsSecretScan: 60
    };
  }

  return {
    activeTimeoutMs: null,
    nucleiTimeoutMs: null,
    dalfoxTimeoutMs: null,
    sqlmapTimeoutMs: null,
    trufflehogTimeoutMs: null,
    feroxbusterTimeoutMs: null,
    katanaTimeoutMs: null,
    gauTimeoutSeconds: null,
    passiveTimeoutMs: 15000,
    idleTimeoutMs: null,
    killOnIdle: false,
    maxNucleiUrls: null,
    maxDalfoxUrls: null,
    maxSqlmapUrls: null,
    maxFeroxUrls: null,
    maxJsSecretScan: null
  };
}

function buildScanConfig(env = process.env) {
  const mode = String(env.SCAN_MODE || 'complete').trim().toLowerCase();
  const normalizedMode = ['quick', 'balanced', 'complete', 'custom'].includes(mode) ? mode : 'complete';
  const base = modeDefaults(normalizedMode === 'custom' ? 'complete' : normalizedMode);

  return {
    mode: normalizedMode,
    activeTimeoutMs: parseSecondsToMs(env.TOOL_TIMEOUT_SECONDS, base.activeTimeoutMs),
    nucleiTimeoutMs: parseSecondsToMs(env.NUCLEI_PROCESS_TIMEOUT_SECONDS, base.nucleiTimeoutMs),
    dalfoxTimeoutMs: parseSecondsToMs(env.DALFOX_TIMEOUT_SECONDS, base.dalfoxTimeoutMs),
    sqlmapTimeoutMs: parseSecondsToMs(env.SQLMAP_TIMEOUT_SECONDS, base.sqlmapTimeoutMs),
    trufflehogTimeoutMs: parseSecondsToMs(env.TRUFFLEHOG_TIMEOUT_SECONDS, base.trufflehogTimeoutMs),
    feroxbusterTimeoutMs: parseSecondsToMs(env.FEROXBUSTER_TIMEOUT_SECONDS, base.feroxbusterTimeoutMs),
    katanaTimeoutMs: parseSecondsToMs(env.KATANA_TIMEOUT_SECONDS, base.katanaTimeoutMs),
    gauTimeoutSeconds: parseTimeoutMs(env.GAU_TIMEOUT_SECONDS, base.gauTimeoutSeconds),
    passiveTimeoutMs: parseSecondsToMs(env.PASSIVE_TIMEOUT_SECONDS, base.passiveTimeoutMs),
    idleTimeoutMs: parseSecondsToMs(env.IDLE_TIMEOUT_SECONDS, base.idleTimeoutMs),
    killOnIdle: parseBool(env.KILL_ON_IDLE, base.killOnIdle),
    maxNucleiUrls: parseLimit(env.MAX_NUCLEI_URLS, base.maxNucleiUrls),
    maxDalfoxUrls: parseLimit(env.MAX_DALFOX_URLS, base.maxDalfoxUrls),
    maxSqlmapUrls: parseLimit(env.MAX_SQLMAP_URLS, base.maxSqlmapUrls),
    maxFeroxUrls: parseLimit(env.MAX_FEROX_URLS, base.maxFeroxUrls),
    maxJsSecretScan: parseLimit(env.MAX_JS_SECRET_SCAN, base.maxJsSecretScan)
  };
}

module.exports = {
  buildScanConfig,
  parseLimit,
  parseTimeoutMs
};
