const { requestUrl } = require('./passiveHttp');

function httpUrlDesdeDominio(dominio) {
  const host = String(dominio || '').replace(/^https?:\/\//i, '').split('/')[0];
  return host ? `http://${host}` : null;
}

async function ejecutarHttpsRedirect(dominio, opciones = {}) {
  const timeoutMs = Number(opciones.timeoutMs || 8000);
  const url = httpUrlDesdeDominio(dominio);

  if (!url) {
    return {
      status: 'skipped',
      raw: '',
      parsed: [],
      findings: [],
      error: 'httpsRedirect no se ejecuto porque no hay dominio valido',
      metrics: { comprobaciones: 0, redirecciona_https: 0, http_sin_redirect: 0 }
    };
  }

  try {
    const response = await requestUrl(url, { method: 'GET', timeoutMs, rejectUnauthorized: false, maxBytes: 32 * 1024 });
    const location = response.headers.location || null;
    const redirect = [301, 302, 303, 307, 308].includes(response.statusCode);
    const redirectsToHttps = redirect && /^https:\/\//i.test(String(location || ''));
    const item = {
      url,
      statusCode: response.statusCode,
      location,
      redirect,
      redirectsToHttps,
      httpAccessibleWithoutRedirect: !redirectsToHttps && response.statusCode >= 200 && response.statusCode < 400
    };

    return {
      status: 'success',
      raw: JSON.stringify(item, null, 2),
      parsed: [item],
      findings: [],
      metrics: {
        comprobaciones: 1,
        redirecciona_https: redirectsToHttps ? 1 : 0,
        http_sin_redirect: item.httpAccessibleWithoutRedirect ? 1 : 0
      }
    };
  } catch (error) {
    return {
      status: 'skipped',
      raw: '',
      parsed: [],
      findings: [],
      error: `HTTP no disponible o no comprobable: ${error.message}`,
      metrics: { comprobaciones: 1, redirecciona_https: 0, http_sin_redirect: 0 }
    };
  }
}

module.exports = {
  ejecutarHttpsRedirect
};
