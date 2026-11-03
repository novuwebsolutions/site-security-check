import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { allowed, CheckError, checkSiteSecurity, isPublicIp, parseRobots, parseTarget, rulesFor } from '../site-security-check.mjs';

const cli = fileURLToPath(new URL('../cli.mjs', import.meta.url));
const NOW = Date.parse('2026-11-03T12:00:00Z');

/**
 * A small internet: `hosts` maps names to addresses (DNS), `pages` maps URLs
 * to responses or functions that make one. Unknown URLs answer 404.
 */
function internet({ hosts = {}, pages = {}, signed = [], certificates = [] }) {
  const requests = [];
  const fetch = async (url, init = {}) => {
    const u = new URL(url);
    if (u.hostname === 'cloudflare-dns.com') {
      const name = u.searchParams.get('name');
      const type = u.searchParams.get('type');
      const ips = (hosts[name] ?? []).filter((ip) => (type === 'AAAA') === ip.includes(':'));
      const body = {
        Status: name in hosts ? 0 : 3,
        AD: signed.includes(name),
        Answer: ips.map((data) => ({ name, type: type === 'AAAA' ? 28 : 1, TTL: 60, data })),
      };
      return new Response(JSON.stringify(body));
    }
    if (u.hostname === 'api.certspotter.com') return new Response(JSON.stringify(certificates));
    requests.push({ url, headers: init.headers ?? {}, redirect: init.redirect });
    const page = pages[url];
    if (typeof page === 'function') return page();
    if (page) return page.clone();
    return new Response('not found', { status: 404 });
  };
  return { fetch, requests };
}

const html = (body, headers = {}) => new Response(`<!doctype html><html><head><title>x</title></head><body>${body}</body></html>`, { headers: { 'content-type': 'text/html; charset=utf-8', ...headers } });
const moved = (location, status = 301) => new Response(null, { status, headers: { location } });
const byId = (report) => Object.fromEntries(report.findings.map((f) => [f.id, f]));

const SAFE_HEADERS = {
  'strict-transport-security': 'max-age=31536000',
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=()',
  server: 'cloudflare',
};

test('isPublicIp keeps private, local and special addresses out', () => {
  for (const ip of ['8.8.8.8', '217.146.69.10', '2606:4700:3034::ac43:bafc', '2a00:1450:4001::200e']) assert.equal(isPublicIp(ip), true, ip);
  for (const ip of [
    '127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0',
    '224.0.0.1', '255.255.255.255', '198.18.0.1', '::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', '::ffff:127.0.0.1',
    '::ffff:10.0.0.1', '64:ff9b::a00:1', '2001:db8::1', '2002:7f00:1::1', '2001::1', 'ff02::1', 'not-an-ip',
  ]) {
    assert.equal(isPublicIp(ip), false, ip);
  }
});

test('parseTarget accepts web addresses and refuses the rest', () => {
  assert.equal(parseTarget('Firma.ee').href, 'https://firma.ee/');
  assert.equal(parseTarget('http://www.firma.ee/kontakt#x').href, 'http://www.firma.ee/kontakt');
  for (const [input, code] of [
    ['', 'empty'],
    ['ftp://firma.ee', 'scheme'],
    ['https://user:pw@firma.ee', 'credentials'],
    ['https://firma.ee:8080', 'port'],
    ['http://127.0.0.1', 'ip'],
    ['http://2130706433', 'ip'],
    ['http://0x7f.1', 'ip'],
    ['http://[::1]/', 'ip'],
    ['localhost', 'invalid'],
    ['router.local', 'reserved'],
    ['metadata.google.internal', 'reserved'],
  ]) {
    assert.throws(() => parseTarget(input), (e) => e instanceof CheckError && e.code === code, input);
  }
});

test('robots rules: named groups, longest match, wildcards', () => {
  const robots = parseRobots('User-agent: *\nDisallow: /admin\n\nUser-agent: site-security-check\nUser-agent: other\nDisallow: /\nAllow: /avalik$\n\nSitemap: https://firma.ee/sitemap.xml');
  assert.deepEqual(robots.sitemaps, ['https://firma.ee/sitemap.xml']);
  const mine = rulesFor(robots, 'Site-Security-Check');
  assert.equal(mine.named, true);
  assert.equal(allowed(mine.rules, '/'), false);
  assert.equal(allowed(mine.rules, '/avalik'), true);
  assert.equal(allowed(mine.rules, '/avalik/x'), false);
  const others = rulesFor(robots, 'googlebot');
  assert.equal(others.named, false);
  assert.equal(allowed(others.rules, '/admin/x'), false);
  assert.equal(allowed(others.rules, '/'), true);
  assert.equal(allowed(parseRobots('User-agent: *\nDisallow: /*.pdf$').groups[0].rules, '/a/b.pdf'), false);
});

test('a well protected site', async () => {
  const { fetch, requests } = internet({
    hosts: { 'firma.ee': ['93.184.216.34'] },
    signed: ['firma.ee'],
    pages: {
      'https://firma.ee/robots.txt': new Response('User-agent: *\nAllow: /\n'),
      'https://firma.ee/': html('<img src="/a.png">', SAFE_HEADERS),
      'http://firma.ee/': moved('https://firma.ee/'),
      'https://firma.ee/.well-known/security.txt': new Response('Contact: mailto:info@firma.ee\n', { headers: { 'content-type': 'text/plain' } }),
    },
    certificates: [
      { dns_names: ['firma.ee', 'www.firma.ee'], not_before: '2026-10-01T00:00:00Z', not_after: '2026-12-30T00:00:00Z', revoked: false, issuer: { friendly_name: "Let's Encrypt" } },
      { dns_names: ['*.firma.ee'], not_before: '2026-09-01T00:00:00Z', not_after: '2026-11-30T00:00:00Z', revoked: false },
    ],
  });
  const report = await checkSiteSecurity('firma.ee', { fetch, now: NOW });
  assert.equal(report.summary.status, 'ok', JSON.stringify(report.findings.filter((f) => f.status !== 'ok')));
  const f = byId(report);
  assert.match(f['certificate-ok'].text, /30\.12\.2026 \(veel 56 päeva\), väljastaja Let's Encrypt/);
  assert.ok(f['dnssec-ok'] && f['securitytxt-ok'] && f['http-redirect'] && f['cookies-none']);
  // Requests are plain reads that never follow a redirect on their own.
  assert.ok(requests.every((r) => r.redirect === 'manual' && /site-security-check/.test(r.headers['user-agent'])));
  assert.ok(requests.length <= 8);
});

test('an unprotected site gets its fixes', async () => {
  const { fetch } = internet({
    hosts: { 'vana.ee': ['93.184.216.34'] },
    pages: {
      'https://vana.ee/': html('<script src="http://cdn.vana.ee/x.js"></script><meta name="generator" content="WordPress 5.8.1">', {
        server: 'Apache/2.4.41 (Ubuntu)',
        'x-powered-by': 'PHP/7.4.3',
        'set-cookie': 'PHPSESSID=abc; path=/',
        'referrer-policy': 'unsafe-url',
      }),
      'http://vana.ee/': html('vana'),
    },
    certificates: [{ dns_names: ['vana.ee'], not_before: '2026-08-10T00:00:00Z', not_after: '2026-11-08T00:00:00Z', revoked: false }],
  });
  const f = byId(await checkSiteSecurity('https://vana.ee/', { fetch, now: NOW }));
  assert.equal(f['http-no-redirect'].status, 'warn');
  assert.equal(f['certificate-expiring'].status, 'warn');
  assert.equal(f['hsts-missing'].status, 'warn');
  assert.match(f['hsts-missing'].fix.code, /Strict-Transport-Security/);
  assert.equal(f['xcto-missing'].status, 'warn');
  assert.equal(f['frame-missing'].status, 'warn');
  assert.equal(f['referrer-unsafe'].status, 'warn');
  assert.match(f['server-version'].text, /Apache\/2\.4\.41.*PHP\/7\.4\.3/);
  assert.equal(f['cookies-insecure'].status, 'warn');
  assert.match(f['cookies-insecure'].text, /PHPSESSID/);
  assert.equal(f['mixed-content'].status, 'warn');
  assert.match(f['generator-version'].text, /WordPress 5\.8\.1/);
  assert.equal(f['dnssec-off'].status, 'info');
});

test('a static site generator version is no warning', async () => {
  const { fetch } = internet({
    hosts: { 'firma.ee': ['93.184.216.34'] },
    pages: { 'https://firma.ee/': html('<meta name="generator" content="Astro v7.2.9">', SAFE_HEADERS) },
  });
  const f = byId(await checkSiteSecurity('firma.ee', { fetch, now: NOW, certificateLog: false }));
  assert.equal(f['generator-version'], undefined);
});

test('a broken certificate is a finding, read over http', async () => {
  const { fetch } = internet({
    hosts: { 'katki.ee': ['93.184.216.34'] },
    pages: {
      'https://katki.ee/robots.txt': () => Promise.reject(new TypeError('fetch failed', { cause: { code: 'CERT_HAS_EXPIRED' } })),
      'http://katki.ee/': html('tere', { server: 'nginx' }),
    },
  });
  const report = await checkSiteSecurity('katki.ee', { fetch, now: NOW });
  const f = byId(report);
  assert.equal(f['https-broken'].status, 'error');
  assert.equal(f['hsts-missing'], undefined);
  assert.equal(report.summary.status, 'error');
});

test('names and redirects into private networks are refused', async () => {
  const { fetch, requests } = internet({
    hosts: { 'sisemine.ee': ['10.0.0.5'], 'segane.ee': ['93.184.216.34', '127.0.0.1'], 'suunab.ee': ['93.184.216.34'], 'ruuter.ee': ['192.168.1.1'] },
    pages: {
      'https://suunab.ee/robots.txt': new Response('', { status: 404 }),
      'https://suunab.ee/': moved('https://ruuter.ee/admin'),
      'https://suunab.ee/ip': moved('http://169.254.169.254/latest/meta-data/'),
    },
  });
  for (const [input, code] of [
    ['sisemine.ee', 'private'],
    ['segane.ee', 'private'],
    ['suunab.ee', 'private'],
    ['https://suunab.ee/ip', 'redirect-bad'],
    ['puudub.ee', 'nxdomain'],
  ]) {
    await assert.rejects(checkSiteSecurity(input, { fetch, now: NOW }), (e) => e instanceof CheckError && e.code === code, input);
  }
  assert.ok(requests.every((r) => new URL(r.url).hostname === 'suunab.ee'), 'nothing was sent to a private address');
});

test('robots.txt naming the checker turns it away', async () => {
  const { fetch, requests } = internet({
    hosts: { 'firma.ee': ['93.184.216.34'] },
    pages: { 'https://firma.ee/robots.txt': new Response('User-agent: NovuTooriistad\nDisallow: /\n') },
  });
  await assert.rejects(checkSiteSecurity('firma.ee', { fetch, robotsToken: 'NovuTooriistad' }), (e) => e.code === 'blocked');
  assert.equal(requests.length, 1);
});

test('a site behind a bot challenge is reported as such', async () => {
  const blocked = internet({
    hosts: { 'kaitstud.ee': ['93.184.216.34'] },
    pages: { 'https://kaitstud.ee/': () => new Response('Just a moment...', { status: 403, headers: { 'cf-mitigated': 'challenge' } }) },
  });
  await assert.rejects(checkSiteSecurity('kaitstud.ee', { fetch: blocked.fetch }), (e) => e.code === 'bot-protection');
});

test('the request budget holds', async () => {
  const pages = { 'https://ring.ee/robots.txt': new Response('', { status: 404 }) };
  for (let i = 0; i < 20; i++) pages[`https://ring.ee/${i}`] = moved(`https://ring.ee/${i + 1}`);
  const { fetch, requests } = internet({ hosts: { 'ring.ee': ['93.184.216.34'] }, pages });
  await assert.rejects(checkSiteSecurity('https://ring.ee/0', { fetch }), (e) => e.code === 'redirects');
  assert.ok(requests.length <= 8, `${requests.length} requests`);
});

test('the command line prints help', () => {
  const help = spawnSync(process.execPath, [cli, '--help'], { encoding: 'utf8' });
  assert.equal(help.status, 0);
  assert.match(help.stdout, /site-security-check https:\/\/firma\.ee/);
});
