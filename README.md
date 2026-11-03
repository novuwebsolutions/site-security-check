# site-security-check

Loeb veebilehelt seda, mida näeb iga brauser, ja ütleb lihtsas keeles, kui hästi leht on kaitstud: HTTPS ja ümbersuunamine sinna, sertifikaadi kehtivus, turvapäised, küpsised, kas server või CMS ütleb välja oma versiooni, segasisu, security.txt ja DNSSEC. Iga leiu juures on parandus, sageli rida koodi, mille saab kopeerida.

Ainult passiivne: porte ei skaneeri, peidetud faile ega haavatavusi ei otsi, sisse logida ei proovi ja vorme ei saada. Vajab ainult `fetch`-i, nii et töötab Node 18+, Cloudflare Workersi, Deno ja Buniga. Sõltuvusi pole.

Proovi brauseris: [novu.ee/tooriistad/turvakontroll](https://novu.ee/tooriistad/turvakontroll/)

*English below.*

## Mida see kontrollib

- **HTTPS.** Kas leht avaneb krüpteeritult. Vigane või aegunud sertifikaat on viga ja ülejäänu loetakse siis üle http.
- **HTTP → HTTPS.** Kas `http://` suunab püsivalt (301 või 308) `https://`-le.
- **Sertifikaat.** Uusima sertifikaadi kehtivus avalikust sertifikaatide logist ([Cert Spotter](https://sslmate.com/certspotter/)); alla 14 päeva on hoiatus.
- **Turvapäised.** `Strict-Transport-Security` (vähemalt pool aastat), `Content-Security-Policy`, `X-Content-Type-Options`, raamikaitse (`frame-ancestors` või `X-Frame-Options`), `Referrer-Policy`, `Permissions-Policy`. Parandusena Apache'i `.htaccess` rida, mida kasutab enamik majutusi.
- **Versioonid.** `Server`, `X-Powered-By` ja `X-AspNet-Version` versiooniga; serveris jooksva CMS-i (WordPress, Joomla, Drupal jt) `generator`-silt versiooniga. Staatilise saidi generaatori versioon (Astro, Hugo) ei ole hoiatus, sest serveris sellest midagi ei jookse.
- **Küpsised** esimesel külastusel: `Secure` ja `HttpOnly`.
- **Segasisu.** Skriptid, stiilid, pildid ja raamid, mis tulevad HTTPS-lehel `http://` aadressilt.
- **security.txt** aadressil `/.well-known/security.txt`.
- **DNSSEC** DNS-vastuse allkirja järgi.

## Turvalisus

Tööriista ei saa kasutada kellegi teise vastu:

- **Ainult avalikud aadressid.** Iga nimi lahendatakse enne päringut DNS-iga ja kui mõni selle aadress on privaatne või sisemine (localhost, 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, IPv6 kohalikud, IPv4-sisaldavad ja muud erivahemikud), siis päringut ei tehta. IP-aadressi, kasutajanime ega parooli aadressis ei võeta vastu, pordid ainult 80 ja 443.
- **Ümbersuunamisi järgib tööriist ise** (`redirect: 'manual'`) ja kontrollib iga uut aadressi samamoodi, kuni 5 korda.
- **Piirid.** Ühe kontrolli jooksul kuni 8 päringut saidile, igaüks kuni 8 sekundit ja 1,5 MB. Küpsiseid ei saadeta.
- **robots.txt.** Kui sait keelab tööriista nime (`User-agent: site-security-check` ja `Disallow: /`, nimi on valikuga muudetav), kontrolli ei tehta.

Cloudflare Workersis lahendab `fetch` nime uuesti ise, nii et nimi, mis muudab vastust meie kontrolli ja päringu vahel (DNS rebinding), võiks teoreetiliselt läbi lipsata. Workersil pole sisevõrku, kuhu see viiks. Kui jooksutad tööriista serveris, mille kõrval on sisevõrk, anna sellele oma võrk ilma sisevõrgu ligipääsuta.

## Kasutamine

Käsurealt, ilma midagi paigaldamata:

```bash
npx github:novuwebsolutions/site-security-check https://firma.ee
npx github:novuwebsolutions/site-security-check firma.ee --lang en --json
```

Valikud: `--lang en`, `--json`, `--user-agent "…"`, `--robots-token nimi`, `--no-certificate-log`. Väljumiskood 1 tähendab, et leiti viga või kontroll ei õnnestunud.

Oma koodis:

```bash
npm install github:novuwebsolutions/site-security-check
```

```js
import { checkSiteSecurity, CheckError } from 'site-security-check';

try {
  const report = await checkSiteSecurity('https://firma.ee', { lang: 'et' });
  console.log(report.summary, report.finalUrl);
} catch (error) {
  if (error instanceof CheckError) console.log(error.code, error.message); // 'private', 'timeout', 'blocked', …
  else throw error;
}
```

Valikud: `lang`, `userAgent`, `robotsToken`, `maxRequests` (8), `timeoutMs` (8000), `maxBytes`, `certificateLog` (`false` jätab sertifikaatide logi vahele), `fetch`, `doh`. Tulemus on kujul `{ tool, version, lang, url, finalUrl, host, checkedAt, summary, findings }`; iga leid on `{ id, status, title, text, fix, value }` ja `status` on `ok`, `info`, `warn` või `error`.

Samast failist saab ka abifunktsioonid: `parseTarget` (aadressi kontroll), `isPublicIp`, `parseRobots`, `rulesFor`, `allowed`, `dnsQuery` ja `session` (piiratud ja kontrollitud `get`).

## Oma Cloudflare Workerina

`worker.mjs` vastab päringule `GET /?url=firma.ee&lang=et` JSON-iga:

```bash
git clone https://github.com/novuwebsolutions/site-security-check.git
cd site-security-check
cp wrangler.example.jsonc wrangler.jsonc
npx wrangler deploy
```

Seadetes on `global_fetch_strictly_public`, nii et ka sinu enda Cloudflare'i tsoonide kontroll läheb läbi avaliku interneti, mitte otse origin-serverisse. Piirangud: 10 kontrolli minutis külastaja IP kohta (`IP_LIMIT`), 6 minutis kontrollitava saidi kohta (`SITE_LIMIT`) ja sama aadressi tulemus tuleb 10 minutit vahemälust. Saladusi pole vaja.

## Testid

```bash
npm test
```

Testid ei kasuta võrku: DNS ja saidid on testis kirjas, sealhulgas privaatsetele aadressidele suunavad nimed ja ümbersuunamised.

## English

Reads what any browser sees of a website and says in plain words how well it is protected: HTTPS and the redirect to it, the certificate's expiry (from the public certificate logs), the security headers (HSTS, CSP, nosniff, frame protection, Referrer-Policy, Permissions-Policy), cookies, software versions given away by the server or a server-side CMS, mixed content, security.txt and DNSSEC. Every finding comes with a fix, usually an Apache `.htaccess` line.

It is passive only: no port scans, no guessing of hidden files, no vulnerability probing, no logins, no forms. Every host is resolved first and refused if any of its addresses is private, internal or special (also after each redirect, which it follows itself, up to 5); IP addresses, credentials and ports other than 80 and 443 are refused; a check makes at most 8 requests to the site, each capped at 8 seconds and 1.5 MB; and a robots.txt group naming the checker (`site-security-check` by default) with `Disallow: /` turns it away. On Cloudflare Workers `fetch` resolves names again itself, so DNS rebinding is theoretically possible there, but Workers have no private network to reach; elsewhere, give it a network without internal access.

```bash
npx github:novuwebsolutions/site-security-check https://firma.ee --lang en
```

```js
import { checkSiteSecurity } from 'site-security-check';
const report = await checkSiteSecurity('firma.ee', { lang: 'en' });
```

Options: `lang`, `userAgent`, `robotsToken`, `maxRequests`, `timeoutMs`, `maxBytes`, `certificateLog`, `fetch`, `doh`. Failures throw a `CheckError` with a stable `code`. `worker.mjs` with `wrangler.example.jsonc` is a ready Cloudflare Worker (`GET /?url=firma.ee`) with `global_fetch_strictly_public`, per-IP and per-site rate limits and a ten-minute cache. Tests run offline: `npm test`.

Made by [Novu Web Solutions](https://novu.ee), a web studio in Viljandi, Estonia. Try it in the browser at [novu.ee/tooriistad](https://novu.ee/tooriistad/). MIT licence.
