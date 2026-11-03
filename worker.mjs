// The check as a small Cloudflare Worker: GET /?url=firma.ee&lang=et answers
// with the report as JSON. wrangler.example.jsonc has the settings, the
// README the steps.
//
// The limits keep the Worker from being used against anyone's site or from
// spending your daily requests: a few checks a minute per visitor IP
// (IP_LIMIT), a few a minute per checked site (SITE_LIMIT), and the same
// address checked again within ten minutes is answered from the cache.
// The Worker has nothing else: no database, no keys and no secrets.
import { checkSiteSecurity, CheckError, parseTarget } from './site-security-check.mjs';

const CACHE_SECONDS = 600;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method !== 'GET') return json({ error: { code: 'method', message: 'GET only' } }, 405);
    const lang = url.searchParams.get('lang') === 'en' ? 'en' : 'et';
    let target;
    try {
      target = parseTarget(url.searchParams.get('url') ?? '', lang);
    } catch (error) {
      if (error instanceof CheckError) return json({ error: { code: error.code, message: error.message } }, 422);
      throw error;
    }
    // The Worker never checks itself.
    if (target.hostname === url.hostname) return json({ error: { code: 'self', message: 'This address is the checker itself.' } }, 422);

    const cache = globalThis.caches?.default;
    const key = new Request(new URL(`/__cache/${lang}/${encodeURIComponent(target.href)}`, url).href);
    const cached = await cache?.match(key);
    if (cached) return cached;

    const ip = request.headers.get('cf-connecting-ip') ?? 'unknown';
    if (env.IP_LIMIT && !(await env.IP_LIMIT.limit({ key: ip })).success) {
      return json({ error: { code: 'rate-limit', message: 'Too many checks. Try again in a minute.' } }, 429);
    }
    if (env.SITE_LIMIT && !(await env.SITE_LIMIT.limit({ key: target.hostname })).success) {
      return json({ error: { code: 'site-limit', message: 'This site was checked many times just now. Try again in a minute.' } }, 429);
    }

    try {
      const report = await checkSiteSecurity(target.href, { lang });
      const response = json(report, 200, CACHE_SECONDS);
      if (cache) ctx.waitUntil(cache.put(key, response.clone()));
      return response;
    } catch (error) {
      if (error instanceof CheckError) return json({ error: { code: error.code, message: error.message } }, 422);
      return json({ error: { code: 'internal', message: 'The check failed.' } }, 500);
    }
  },
};

function json(body, status = 200, maxAge = 0) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': maxAge ? `public, max-age=${maxAge}` : 'no-store',
      'x-robots-tag': 'noindex',
      'x-content-type-options': 'nosniff',
    },
  });
}
