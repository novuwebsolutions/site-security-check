// Reads what any browser sees of a website and says, in plain words, how well
// it is protected: HTTPS and the move to it, the certificate, the security
// headers, cookies, whether the server names its software version, mixed
// content, security.txt and DNSSEC.
//
//   import { checkSiteSecurity } from './site-security-check.mjs';
//   const report = await checkSiteSecurity('https://firma.ee');
//
// It only reads public things, as a browser would: the page you give it, the
// same site over plain http, robots.txt, /.well-known/security.txt, public DNS
// and the public certificate logs. No port scans, no guessing of hidden files,
// no logins, no forms. At most 8 requests to the site, each capped in time and
// size, and an address that leads to a private or internal network is refused,
// also after a redirect. It needs nothing but fetch, so it runs in Node 18+,
// Cloudflare Workers, Deno and Bun.

export const VERSION = '1.0.0';

const DEFAULTS = {
  userAgent: `site-security-check/${VERSION} (+https://github.com/novuwebsolutions/site-security-check)`,
  // A site owner turns the check away with "User-agent: site-security-check"
  // and "Disallow: /" in robots.txt.
  robotsToken: 'site-security-check',
  maxRequests: 8,
  timeoutMs: 8000,
  maxBytes: 1_500_000,
};

// HSTS shorter than half a year protects little between visits.
const HSTS_MIN = 15_552_000;
// A certificate whose newest copy runs out within two weeks is not renewing.
const CERT_WARN_DAYS = 14;

// ---------------------------------------------------------------------------
// Words

const ERRORS = {
  et: {
    empty: 'Sisesta kodulehe aadress.',
    invalid: 'See ei ole veebiaadress. Sisesta näiteks firma.ee.',
    ip: 'Sisesta domeeni nimi, mitte IP-aadress.',
    reserved: 'Seda nime ei saa internetist kontrollida.',
    scheme: 'Kontrollida saab ainult http- ja https-aadresse.',
    credentials: 'Aadressis ei tohi olla kasutajanime ega parooli.',
    port: 'Kontrollida saab ainult tavalisi veebiporte (80 ja 443).',
    nxdomain: (host) => `Aadressi ${host} pole olemas. Kontrolli kirjapilti.`,
    dns: (host) => `DNS ei vastanud aadressi ${host} kohta. Proovi mõne aja pärast uuesti.`,
    private: (host) => `${host} viib sisevõrku. Selliseid aadresse me ei kontrolli.`,
    timeout: (host) => `${host} ei vastanud 8 sekundi jooksul.`,
    unreachable: (host) => `${host} ei vasta.`,
    tls: (host) => `${host} HTTPS-ühendus ei õnnestunud: sertifikaat on vigane või aegunud.`,
    redirects: 'Leht suunab edasi liiga mitu korda.',
    'redirect-bad': 'Leht suunab aadressile, mida me ei kontrolli.',
    limit: 'Kontroll jõudis päringute piirini.',
    blocked: (host) => `${host} omanik on robots.txt-is selle kontrolli keelanud.`,
    'bot-protection': (host) => `${host} robotikaitse ei lase automaatset kontrolli läbi. Külastajad näevad lehte, meie mitte.`,
  },
  en: {
    empty: 'Enter a website address.',
    invalid: 'That is not a web address. Try firma.ee.',
    ip: 'Enter a domain name, not an IP address.',
    reserved: 'This name cannot be checked from the internet.',
    scheme: 'Only http and https addresses can be checked.',
    credentials: 'The address must not contain a user name or password.',
    port: 'Only the usual web ports (80 and 443) can be checked.',
    nxdomain: (host) => `${host} does not exist. Check the spelling.`,
    dns: (host) => `DNS did not answer for ${host}. Try again in a while.`,
    private: (host) => `${host} leads to a private network. Such addresses are not checked.`,
    timeout: (host) => `${host} did not answer within 8 seconds.`,
    unreachable: (host) => `${host} does not answer.`,
    tls: (host) => `The HTTPS connection to ${host} failed: the certificate is invalid or has expired.`,
    redirects: 'The page redirects too many times.',
    'redirect-bad': 'The page redirects to an address that is not checked.',
    limit: 'The check reached its request limit.',
    blocked: (host) => `The owner of ${host} has turned this check away in robots.txt.`,
    'bot-protection': (host) => `The bot protection of ${host} does not let automated checks through. Visitors see the page; we do not.`,
  },
};

/** An input or network problem; `code` is stable, `message` is for people. */
export class CheckError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = 'CheckError';
    this.code = code;
  }
}

const fail = (lang, code, arg, cause) => {
  const text = (ERRORS[lang] ?? ERRORS.en)[code];
  return new CheckError(code, typeof text === 'function' ? text(arg) : text, cause ? { cause } : undefined);
};

const HTACCESS = (header) => `Header always set ${header}`;

const TEXT = {
  et: {
    'https-ok': (f) => ({
      title: 'HTTPS töötab',
      text: `Ühendus lehega ${f.host} on krüpteeritud ja brauser ei näita hoiatust.`,
    }),
    'https-broken': (f) => ({
      title: 'HTTPS ei tööta',
      text: `Brauser näitab lehe ${f.host} avamisel turvahoiatust: sertifikaat on vigane, aegunud või vale nimega. Paljud külastajad lahkuvad kohe.`,
      fix: { text: 'Uuenda sertifikaat oma majutuse halduses. Let\'s Encrypt annab tasuta sertifikaadi, mis uueneb ise.' },
    }),
    'https-missing': (f) => ({
      title: 'Lehel pole HTTPS-i',
      text: `${f.host} avaneb ainult ilma krüpteeringuta. Brauser märgib lehe „Pole turvaline“ ja vormidesse sisestatud andmed liiguvad lahtiselt.`,
      fix: { text: 'Lülita oma majutuse halduses sisse tasuta Let\'s Encrypti sertifikaat.' },
    }),
    'http-redirect': () => ({
      title: 'HTTP suunab HTTPS-ile',
      text: 'Kes kirjutab aadressi ilma https-ita, jõuab ikkagi turvalisele lehele.',
    }),
    'http-redirect-temporary': (f) => ({
      title: 'HTTP suunab HTTPS-ile ajutiselt',
      text: `Ümbersuunamine on olemas, aga ajutine (${f.status}). Püsiv ümbersuunamine (301) ütleb ka Google'ile, et õige aadress on https.`,
    }),
    'http-no-redirect': () => ({
      title: 'Leht avaneb ka ilma HTTPS-ita',
      text: 'Aadress http:// näitab lehte krüpteerimata. Kes sinna satub, ei ole kaitstud.',
      fix: { text: 'Lisa püsiv ümbersuunamine http-lt https-ile. Apache\'i serveris (.htaccess):', code: 'RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]' },
    }),
    'certificate-ok': (f) => ({
      title: 'Sertifikaat kehtib',
      text: f.until ? `Uusim sertifikaat kehtib ${f.until} (veel ${f.days} päeva)${f.issuer ? `, väljastaja ${f.issuer}` : ''}.` : 'Brauser usaldab lehe sertifikaati.',
    }),
    'certificate-expiring': (f) => ({
      title: 'Sertifikaat aegub varsti',
      text: `Uusim sertifikaat kehtib ainult ${f.until} (veel ${f.days} päeva). Kui see ei uuene, näevad külastajad turvahoiatust.`,
      fix: { text: 'Kontrolli, kas sertifikaadi automaatne uuendamine on majutuses sees.' },
    }),
    'hsts-ok': () => ({
      title: 'Brauser kasutab alati HTTPS-i (HSTS)',
      text: 'Kord lehel käinud brauser ei ava seda enam kunagi krüpteerimata.',
    }),
    'hsts-short': (f) => ({
      title: 'HSTS kehtib lühikest aega',
      text: `Brauser mäletab HTTPS-i nõuet ainult ${f.days} päeva. Soovitus on vähemalt pool aastat.`,
      fix: { text: 'Pikenda max-age väärtust:', code: HTACCESS('Strict-Transport-Security "max-age=31536000"') },
    }),
    'hsts-missing': () => ({
      title: 'HSTS puudub',
      text: 'Server ei ütle brauserile, et lehte tohib avada ainult HTTPS-iga. Avalikus WiFis saab külastaja siis ümber suunata võltslehele.',
      fix: { text: 'Lisa serveri vastusesse päis. Cloudflare\'is: SSL/TLS → Edge Certificates → HSTS. Apache\'i serveris (.htaccess):', code: HTACCESS('Strict-Transport-Security "max-age=31536000"') },
    }),
    'csp-ok': () => ({
      title: 'Sisu turvapoliitika on olemas (CSP)',
      text: 'Leht ütleb brauserile, kust tohib skripte ja muid faile laadida. See peatab suure osa võõrastest skriptidest.',
    }),
    'csp-report-only': () => ({
      title: 'CSP ainult jälgib',
      text: 'Content-Security-Policy-Report-Only annab teada, aga ei keela midagi.',
    }),
    'csp-missing': () => ({
      title: 'Sisu turvapoliitikat pole (CSP)',
      text: 'Brauser laadib skripte igalt poolt. CSP on suurem töö, sest see tuleb lehe järgi seadistada. Tasub teha, kui lehel on vormid või sisselogimine.',
    }),
    'xcto-ok': () => ({
      title: 'Failitüübid on lukus (nosniff)',
      text: 'Brauser ei arva failitüüpi ise ja võõras fail ei saa end skriptiks teeselda.',
    }),
    'xcto-missing': () => ({
      title: 'Failitüübid pole lukus',
      text: 'Päis X-Content-Type-Options puudub. Brauser võib arvata failitüüpi ise ja käivitada näiteks pildina üles laaditud skripti.',
      fix: { text: 'Lisa päis. Apache\'i serveris (.htaccess):', code: HTACCESS('X-Content-Type-Options "nosniff"') },
    }),
    'frame-ok': () => ({
      title: 'Lehte ei saa võõrale lehele peita',
      text: 'Teine sait ei saa sinu lehte oma lehe sisse panna ja külastajat petta, et ta klõpsaks valel nupul.',
    }),
    'frame-missing': () => ({
      title: 'Lehte saab võõrale lehele peita',
      text: 'Teine sait võib sinu lehe nähtamatult oma lehe sisse panna ja panna külastaja klõpsama valel nupul (clickjacking).',
      fix: { text: 'Lisa päis. Apache\'i serveris (.htaccess):', code: HTACCESS('X-Frame-Options "SAMEORIGIN"') },
    }),
    'referrer-ok': () => ({
      title: 'Lingid ei reeda liiga palju (Referrer-Policy)',
      text: 'Kui külastaja lahkub lingi kaudu, saab teine sait teada ainult sinu domeeni, mitte täit aadressi.',
    }),
    'referrer-unsafe': (f) => ({
      title: 'Lingid reedavad täisaadressi',
      text: `Referrer-Policy on ${f.value}. Teine sait näeb täit aadressi, ka seal olevaid andmeid.`,
      fix: { text: 'Muuda päis:', code: HTACCESS('Referrer-Policy "strict-origin-when-cross-origin"') },
    }),
    'referrer-missing': () => ({
      title: 'Referrer-Policy puudub',
      text: 'Tänapäeva brauserid kasutavad ise mõistlikku vaikimisi reeglit, nii et see on väike asi.',
      fix: { text: 'Kui tahad selgust, lisa päis:', code: HTACCESS('Referrer-Policy "strict-origin-when-cross-origin"') },
    }),
    'permissions-ok': () => ({
      title: 'Kaamera ja mikrofon on lukus (Permissions-Policy)',
      text: 'Leht ütleb, milliseid seadme võimalusi (kaamera, mikrofon, asukoht) ta ei kasuta.',
    }),
    'permissions-missing': () => ({
      title: 'Permissions-Policy puudub',
      text: 'Leht ei keela kaamerat, mikrofoni ega asukohta. Kui leht neid ei kasuta, tasub need kinni panna, et võõras skript neid küsida ei saaks.',
      fix: { text: 'Lisa päis:', code: HTACCESS('Permissions-Policy "camera=(), microphone=(), geolocation=()"') },
    }),
    'server-quiet': () => ({
      title: 'Server ei reeda oma tarkvara versiooni',
      text: 'Ründajal on raskem teada, milliseid vanu vigu proovida.',
    }),
    'server-version': (f) => ({
      title: 'Server reedab oma tarkvara versiooni',
      text: `Vastuses on ${f.values}. Ründaja näeb kohe, kas tarkvara on vana ja milliseid vigu proovida.`,
      fix: { text: 'Peida versioon serveri seadetest (Apache: ServerTokens Prod, PHP: expose_php = Off) või küsi seda majutajalt.' },
    }),
    'cookies-none': () => ({
      title: 'Esimesel külastusel küpsiseid ei panda',
      text: 'Server ei pane külastajale küpsiseid enne, kui ta midagi teeb.',
    }),
    'cookies-ok': (f) => ({
      title: 'Küpsised on kaitstud',
      text: `Server paneb ${f.count === 1 ? 'ühe küpsise' : `${f.count} küpsist`} ja ${f.count === 1 ? 'see liigub' : 'need liiguvad'} ainult HTTPS-iga.`,
    }),
    'cookies-insecure': (f) => ({
      title: 'Küpsised liiguvad ka krüpteerimata',
      text: `${f.names} pole märgitud Secure, nii et brauser võib ${f.count === 1 ? 'selle' : 'need'} saata ka ilma HTTPS-ita.`,
      fix: { text: 'Pane küpsistele Secure, HttpOnly ja SameSite. PHP-s: session.cookie_secure = 1, session.cookie_httponly = 1, session.cookie_samesite = "Lax".' },
    }),
    'cookies-script': (f) => ({
      title: 'Skriptid näevad küpsiseid',
      text: `${f.names} pole märgitud HttpOnly. Kui need hoiavad sisselogimist, saab võõras skript need kaasa võtta.`,
    }),
    'mixed-content': (f) => ({
      title: 'Leht laadib faile ilma HTTPS-ita',
      text: `${f.count === 1 ? 'Üks fail' : `${f.count} faili`} tuleb aadressilt http://, näiteks ${f.example}. Brauser blokeerib sellised skriptid ja stiilid ning leht võib katki minna.`,
      fix: { text: 'Muuda need lingid https:// kujule. WordPressis aitab otsi-ja-asenda kogu andmebaasis.' },
    }),
    'generator-version': (f) => ({
      title: 'Leht ütleb oma tarkvara versiooni',
      text: `Lehe koodis on kirjas ${f.value}. Kui see versioon on vana, teab ründaja kohe, milliseid vigu proovida.`,
      fix: { text: 'Hoia tarkvara ajakohasena ja eemalda generator-silt (WordPressis teeb seda iga turvaplugin).' },
    }),
    'securitytxt-ok': () => ({
      title: 'security.txt on olemas',
      text: 'Kes leiab lehelt turvavea, teab, kuhu sellest teatada.',
    }),
    'securitytxt-missing': (f) => ({
      title: 'security.txt puudub',
      text: 'Pole kirjas, kuhu turvaveast teatada. See on väike fail, mida otsivad turvauurijad ja RIA.',
      fix: { text: `Lisa fail aadressile https://${f.host}/.well-known/security.txt, näiteks:`, code: `Contact: mailto:info@${f.domain}\nExpires: ${f.expires}\nPreferred-Languages: et, en` },
    }),
    'dnssec-ok': () => ({
      title: 'DNS on allkirjastatud (DNSSEC)',
      text: 'Keegi ei saa võltsida vastust küsimusele, kus sinu leht asub.',
    }),
    'dnssec-off': () => ({
      title: 'DNSSEC pole sees',
      text: 'DNS-i vastused pole allkirjastatud. Rünnak selle kaudu on harv, aga kaitse on tasuta.',
      fix: { text: 'Lülita DNSSEC sisse oma DNS-i halduses (Cloudflare\'is DNS → Settings → DNSSEC). Kui registripidaja ei lisa DS-kirjet ise, lisa see seal.' },
    }),
  },
  en: {
    'https-ok': (f) => ({
      title: 'HTTPS works',
      text: `The connection to ${f.host} is encrypted and the browser shows no warning.`,
    }),
    'https-broken': (f) => ({
      title: 'HTTPS is broken',
      text: `Browsers show a security warning when opening ${f.host}: the certificate is invalid, expired or for another name. Many visitors leave at once.`,
      fix: { text: 'Renew the certificate in your hosting panel. Let\'s Encrypt gives a free one that renews itself.' },
    }),
    'https-missing': (f) => ({
      title: 'No HTTPS',
      text: `${f.host} only opens unencrypted. Browsers mark it "Not secure", and what visitors type into forms travels in the clear.`,
      fix: { text: 'Turn on a free Let\'s Encrypt certificate in your hosting panel.' },
    }),
    'http-redirect': () => ({
      title: 'HTTP redirects to HTTPS',
      text: 'Whoever types the address without https still lands on the secure page.',
    }),
    'http-redirect-temporary': (f) => ({
      title: 'HTTP redirects to HTTPS temporarily',
      text: `The redirect is there but temporary (${f.status}). A permanent one (301) also tells Google that https is the right address.`,
    }),
    'http-no-redirect': () => ({
      title: 'The page also opens without HTTPS',
      text: 'The http:// address shows the page unencrypted. Whoever lands there is not protected.',
      fix: { text: 'Add a permanent redirect from http to https. On an Apache server (.htaccess):', code: 'RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]' },
    }),
    'certificate-ok': (f) => ({
      title: 'The certificate is valid',
      text: f.until ? `The newest certificate is valid until ${f.until} (${f.days} more days)${f.issuer ? `, issued by ${f.issuer}` : ''}.` : 'Browsers trust the certificate.',
    }),
    'certificate-expiring': (f) => ({
      title: 'The certificate expires soon',
      text: `The newest certificate is valid only until ${f.until} (${f.days} more days). If it does not renew, visitors will see a security warning.`,
      fix: { text: 'Check that automatic renewal is on in your hosting.' },
    }),
    'hsts-ok': () => ({
      title: 'Browsers always use HTTPS (HSTS)',
      text: 'A browser that has visited once never opens the site unencrypted again.',
    }),
    'hsts-short': (f) => ({
      title: 'HSTS is short',
      text: `Browsers remember the HTTPS rule for only ${f.days} days. At least half a year is recommended.`,
      fix: { text: 'Raise max-age:', code: HTACCESS('Strict-Transport-Security "max-age=31536000"') },
    }),
    'hsts-missing': () => ({
      title: 'No HSTS',
      text: 'The server does not tell browsers to use only HTTPS, so on public Wi-Fi a visitor can be diverted to a fake page.',
      fix: { text: 'Add the header. On Cloudflare: SSL/TLS → Edge Certificates → HSTS. On an Apache server (.htaccess):', code: HTACCESS('Strict-Transport-Security "max-age=31536000"') },
    }),
    'csp-ok': () => ({
      title: 'There is a Content Security Policy',
      text: 'The page tells the browser where scripts and other files may come from, which stops most foreign scripts.',
    }),
    'csp-report-only': () => ({
      title: 'CSP only reports',
      text: 'Content-Security-Policy-Report-Only reports problems but blocks nothing.',
    }),
    'csp-missing': () => ({
      title: 'No Content Security Policy',
      text: 'The browser loads scripts from anywhere. A CSP takes some work, as it must fit the page. It is worth it where the site has forms or logins.',
    }),
    'xcto-ok': () => ({
      title: 'File types are locked (nosniff)',
      text: 'The browser does not guess file types, so a foreign file cannot pass itself off as a script.',
    }),
    'xcto-missing': () => ({
      title: 'File types are not locked',
      text: 'X-Content-Type-Options is missing. The browser may guess a file\'s type and run, say, a script uploaded as a picture.',
      fix: { text: 'Add the header. On an Apache server (.htaccess):', code: HTACCESS('X-Content-Type-Options "nosniff"') },
    }),
    'frame-ok': () => ({
      title: 'The page cannot be hidden in another site',
      text: 'Another site cannot put your page inside its own and trick visitors into clicking the wrong button.',
    }),
    'frame-missing': () => ({
      title: 'The page can be hidden in another site',
      text: 'Another site can put your page invisibly inside its own and make visitors click the wrong button (clickjacking).',
      fix: { text: 'Add the header. On an Apache server (.htaccess):', code: HTACCESS('X-Frame-Options "SAMEORIGIN"') },
    }),
    'referrer-ok': () => ({
      title: 'Links do not give away too much (Referrer-Policy)',
      text: 'When a visitor follows a link away, the other site learns only your domain, not the full address.',
    }),
    'referrer-unsafe': (f) => ({
      title: 'Links give away the full address',
      text: `Referrer-Policy is ${f.value}. Other sites see the full address, including any data in it.`,
      fix: { text: 'Change the header:', code: HTACCESS('Referrer-Policy "strict-origin-when-cross-origin"') },
    }),
    'referrer-missing': () => ({
      title: 'No Referrer-Policy',
      text: 'Current browsers apply a sensible default themselves, so this is a small thing.',
      fix: { text: 'To make it explicit, add:', code: HTACCESS('Referrer-Policy "strict-origin-when-cross-origin"') },
    }),
    'permissions-ok': () => ({
      title: 'Camera and microphone are locked (Permissions-Policy)',
      text: 'The page says which device features (camera, microphone, location) it does not use.',
    }),
    'permissions-missing': () => ({
      title: 'No Permissions-Policy',
      text: 'The page does not turn off the camera, microphone or location. If it does not use them, locking them keeps a foreign script from asking.',
      fix: { text: 'Add the header:', code: HTACCESS('Permissions-Policy "camera=(), microphone=(), geolocation=()"') },
    }),
    'server-quiet': () => ({
      title: 'The server does not give away its software version',
      text: 'An attacker has a harder time knowing which old flaws to try.',
    }),
    'server-version': (f) => ({
      title: 'The server gives away its software version',
      text: `The response says ${f.values}. An attacker sees at once whether the software is old and which flaws to try.`,
      fix: { text: 'Hide the version in the server settings (Apache: ServerTokens Prod, PHP: expose_php = Off) or ask your host.' },
    }),
    'cookies-none': () => ({
      title: 'No cookies on the first visit',
      text: 'The server sets no cookies before the visitor does anything.',
    }),
    'cookies-ok': (f) => ({
      title: 'Cookies are protected',
      text: `The server sets ${f.count === 1 ? 'one cookie' : `${f.count} cookies`}, sent over HTTPS only.`,
    }),
    'cookies-insecure': (f) => ({
      title: 'Cookies also travel unencrypted',
      text: `${f.names} ${f.count === 1 ? 'is' : 'are'} not marked Secure, so browsers may send ${f.count === 1 ? 'it' : 'them'} without HTTPS too.`,
      fix: { text: 'Mark cookies Secure, HttpOnly and SameSite. In PHP: session.cookie_secure = 1, session.cookie_httponly = 1, session.cookie_samesite = "Lax".' },
    }),
    'cookies-script': (f) => ({
      title: 'Scripts can read cookies',
      text: `${f.names} ${f.count === 1 ? 'is' : 'are'} not marked HttpOnly. If they hold a login, a foreign script can take them.`,
    }),
    'mixed-content': (f) => ({
      title: 'The page loads files without HTTPS',
      text: `${f.count === 1 ? 'One file comes' : `${f.count} files come`} from http://, for example ${f.example}. Browsers block such scripts and styles, and the page may break.`,
      fix: { text: 'Change those links to https://. In WordPress a search-and-replace over the database does it.' },
    }),
    'generator-version': (f) => ({
      title: 'The page names its software version',
      text: `The page's code says ${f.value}. If that version is old, an attacker knows at once which flaws to try.`,
      fix: { text: 'Keep the software up to date and remove the generator tag (any WordPress security plugin does it).' },
    }),
    'securitytxt-ok': () => ({
      title: 'There is a security.txt',
      text: 'Whoever finds a security flaw knows where to report it.',
    }),
    'securitytxt-missing': (f) => ({
      title: 'No security.txt',
      text: 'Nothing says where to report a security flaw. It is a small file that security researchers look for.',
      fix: { text: `Add a file at https://${f.host}/.well-known/security.txt, for example:`, code: `Contact: mailto:info@${f.domain}\nExpires: ${f.expires}\nPreferred-Languages: et, en` },
    }),
    'dnssec-ok': () => ({
      title: 'DNS is signed (DNSSEC)',
      text: 'Nobody can forge the answer to where your site lives.',
    }),
    'dnssec-off': () => ({
      title: 'DNSSEC is off',
      text: 'DNS answers are not signed. Attacks through it are rare, but the protection is free.',
      fix: { text: 'Turn on DNSSEC in your DNS provider (on Cloudflare: DNS → Settings → DNSSEC). If your registrar does not add the DS record itself, add it there.' },
    }),
  },
};

// ---------------------------------------------------------------------------
// Network
//
// Every request to the checked site goes through a session's get(). It
// refuses addresses that are not public (localhost, private and internal
// networks, and names that resolve to them), follows redirects itself so each
// new address is checked the same way, sends no cookies, and stops after a
// time and size limit.
//
// On Cloudflare Workers fetch() resolves the name again on its own, so a name
// that changes its answer between our check and the request could still slip
// through. Workers have no private network to reach, so there it is harmless;
// on a server next to an internal network, give the check a network of its own.

const DOH = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];
const MAX_REDIRECTS = 5;

// Names that never reach the public internet.
const RESERVED = ['localhost', 'local', 'localdomain', 'internal', 'intranet', 'lan', 'home', 'corp', 'private', 'test', 'example', 'invalid', 'onion', 'arpa'];

/**
 * One DNS query over HTTPS (the JSON form both Cloudflare and Google answer):
 * { status, ad, answers: [{ name, type, ttl, data }] }. Status 0 is an answer,
 * 3 a name that does not exist. `ad` is true when the answer is DNSSEC-signed.
 */
export async function dnsQuery(name, type, { fetch = globalThis.fetch.bind(globalThis), doh = DOH, timeoutMs = 5000 } = {}) {
  let lastError;
  for (const endpoint of doh) {
    try {
      const response = await fetch(`${endpoint}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`, {
        headers: { accept: 'application/dns-json' },
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const json = await response.json();
      if (typeof json.Status !== 'number') throw new Error('not a DNS answer');
      if (json.Status === 2 && endpoint !== doh.at(-1)) throw new Error('SERVFAIL');
      return {
        status: json.Status,
        ad: json.AD === true,
        answers: (json.Answer ?? []).map((a) => ({ name: a.name, type: a.type, ttl: a.TTL, data: String(a.data ?? '') })),
      };
    } catch (error) {
      lastError = error;
    }
  }
  throw new Error(`DNS query ${name} ${type} failed: ${lastError?.message}`, { cause: lastError });
}

const ipv4Number = (ip) => {
  const parts = ip.split('.');
  if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return null;
  return parts.reduce((n, p) => n * 256 + Number(p), 0);
};

// IPv4 ranges that are not the public internet: "this network", private,
// carrier NAT, loopback, link-local (cloud metadata lives there), protocol
// assignments, documentation, 6to4 relays, benchmarking, multicast, reserved.
const IPV4_BLOCKED = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
].map(([base, bits]) => [ipv4Number(base), bits]);

/** The eight 16-bit groups of an IPv6 address, or null. */
function ipv6Groups(ip) {
  let text = ip.toLowerCase().replace(/^\[|\]$/g, '').replace(/%.*$/, '');
  let tail = [];
  const v4 = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(text);
  if (v4) {
    const n = ipv4Number(v4[1]);
    if (n === null) return null;
    tail = [Math.floor(n / 65536), n % 65536];
    text = text.slice(0, -v4[1].length);
    if (text.endsWith(':') && !text.endsWith('::')) text = text.slice(0, -1);
  }
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const need = 8 - tail.length;
  const fill = need - head.length - rest.length;
  if (halves.length === 2 ? fill < 0 : fill !== 0) return null;
  const groups = [...head, ...Array(halves.length === 2 ? fill : 0).fill('0'), ...rest];
  if (groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  return [...groups.map((g) => parseInt(g, 16)), ...tail];
}

/** Whether an address is on the public internet. Anything unreadable is not. */
export function isPublicIp(ip) {
  if (!ip.includes(':')) {
    const n = ipv4Number(ip);
    return n !== null && !IPV4_BLOCKED.some(([base, bits]) => Math.floor(n / 2 ** (32 - bits)) === Math.floor(base / 2 ** (32 - bits)));
  }
  const g = ipv6Groups(ip);
  if (!g) return false;
  // Only global unicast (2000::/3), without the IETF special ranges in
  // 2001::/23, documentation (2001:db8::/32, 3fff::/20) and 6to4 (2002::/16).
  // That also leaves out IPv4-mapped (::ffff:), NAT64, local and multicast.
  if (g[0] < 0x2000 || g[0] > 0x3fff) return false;
  if (g[0] === 0x2001 && (g[1] < 0x0200 || g[1] === 0x0db8)) return false;
  if (g[0] === 0x2002) return false;
  if (g[0] === 0x3fff && g[1] < 0x1000) return false;
  return true;
}

/**
 * The URL to check from what someone typed: firma.ee, www.firma.ee/kontakt,
 * https://firma.ee. No scheme means https. Throws a CheckError for anything
 * that is not a public web address on port 80 or 443.
 */
export function parseTarget(input, lang = 'et') {
  let text = String(input ?? '').trim();
  if (!text) throw fail(lang, 'empty');
  if (text.length > 2048) throw fail(lang, 'invalid');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) text = `https://${text}`;
  let url;
  try {
    url = new URL(text);
  } catch {
    throw fail(lang, 'invalid');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw fail(lang, 'scheme');
  if (url.username || url.password) throw fail(lang, 'credentials');
  if (url.port && url.port !== '80' && url.port !== '443') throw fail(lang, 'port');
  // The URL parser has already turned 0x7f.1 and 2130706433 into 127.0.0.1.
  const host = url.hostname.replace(/\.$/, '');
  if (host.startsWith('[') || /^\d+(\.\d+){3}$/.test(host)) throw fail(lang, 'ip');
  const labels = host.split('.');
  if (labels.length < 2 || host.length > 253) throw fail(lang, 'invalid');
  if (labels.some((l) => !/^(?!-)[a-z0-9-]{1,63}(?<!-)$/.test(l))) throw fail(lang, 'invalid');
  if (!/^(?:[a-z]{2,63}|xn--[a-z0-9-]+)$/.test(labels.at(-1))) throw fail(lang, 'invalid');
  if (RESERVED.some((r) => host === r || host.endsWith(`.${r}`))) throw fail(lang, 'reserved');
  url.hostname = host;
  url.hash = '';
  return url;
}

// Node's fetch fails with these when a certificate is not valid.
const TLS_CODES = /CERT|SSL|TLS|SELF_SIGNED|UNABLE_TO_VERIFY|ALTNAME|ERR_TLS/i;

/** Reads at most `max` bytes of a body as text. */
async function readText(response, max) {
  if (!response.body) return { text: '', truncated: false };
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (size + value.byteLength > max) {
      chunks.push(value.subarray(0, max - size));
      size = max;
      truncated = true;
      await reader.cancel().catch(() => {});
      break;
    }
    chunks.push(value);
    size += value.byteLength;
  }
  const bytes = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, at);
    at += chunk.byteLength;
  }
  const charset = /charset=["']?([\w-]+)/i.exec(response.headers.get('content-type') ?? '')?.[1] ?? 'utf-8';
  let decoder;
  try {
    decoder = new TextDecoder(charset);
  } catch {
    decoder = new TextDecoder('utf-8');
  }
  return { text: decoder.decode(bytes), truncated };
}

/**
 * The requests of one check: a request budget, the public-address check for
 * every host it meets (once per host), and get().
 */
export function session(options = {}, lang = 'et') {
  const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
  const dnsOptions = { fetch: fetchImpl, doh: options.doh };
  const settings = { ...DEFAULTS, ...Object.fromEntries(Object.entries(options).filter(([, v]) => v !== undefined)) };
  const hosts = new Map();

  const addresses = async (host) => {
    let answers;
    try {
      answers = await Promise.all([dnsQuery(host, 'A', dnsOptions), dnsQuery(host, 'AAAA', dnsOptions)]);
    } catch (error) {
      throw fail(lang, 'dns', host, error);
    }
    if (answers[0].status === 3) throw fail(lang, 'nxdomain', host);
    const ips = [
      ...answers[0].answers.filter((a) => a.type === 1).map((a) => a.data),
      ...answers[1].answers.filter((a) => a.type === 28).map((a) => a.data),
    ];
    if (!ips.length) throw fail(lang, 'nxdomain', host);
    if (ips.some((ip) => !isPublicIp(ip))) throw fail(lang, 'private', host);
    return { ips, dnssec: answers[0].ad };
  };

  const s = {
    lang,
    settings,
    requests: 0,
    dns: (name, type) => dnsQuery(name, type, dnsOptions),
    fetch: fetchImpl,
    /** The public addresses of a host; throws if any is not public. */
    host(name) {
      if (!hosts.has(name)) hosts.set(name, addresses(name));
      return hosts.get(name);
    },
    left: () => settings.maxRequests - s.requests,
    /**
     * GET a public URL: { url, status, headers, text, truncated, redirects }.
     * With follow: false a redirect is returned as it is.
     */
    async get(target, { accept = 'text/html,application/xhtml+xml,*/*;q=0.8', maxBytes = settings.maxBytes, follow = true } = {}) {
      let url = typeof target === 'string' ? parseTarget(target, lang) : target;
      const redirects = [];
      for (;;) {
        if (s.requests >= settings.maxRequests) throw fail(lang, 'limit');
        await s.host(url.hostname);
        s.requests++;
        let response;
        try {
          response = await fetchImpl(url.href, {
            redirect: 'manual',
            headers: { 'user-agent': settings.userAgent, accept, 'accept-language': lang === 'et' ? 'et,en;q=0.8' : 'en,et;q=0.8' },
            signal: AbortSignal.timeout(settings.timeoutMs),
          });
        } catch (error) {
          const detail = `${error?.cause?.code ?? ''} ${error?.cause?.message ?? ''} ${error?.message ?? ''}`;
          if (error?.name === 'TimeoutError') throw fail(lang, 'timeout', url.hostname, error);
          if (url.protocol === 'https:' && TLS_CODES.test(detail)) throw fail(lang, 'tls', url.hostname, error);
          throw fail(lang, 'unreachable', url.hostname, error);
        }
        // Cloudflare answers 525 and 526 when the site's own certificate fails.
        if (response.status === 525 || response.status === 526) {
          await response.body?.cancel().catch(() => {});
          throw fail(lang, 'tls', url.hostname);
        }
        const location = response.headers.get('location');
        if (follow && response.status >= 300 && response.status < 400 && location) {
          await response.body?.cancel().catch(() => {});
          redirects.push({ url: url.href, status: response.status });
          if (redirects.length > MAX_REDIRECTS) throw fail(lang, 'redirects');
          try {
            url = parseTarget(new URL(location, url).href, lang);
          } catch (error) {
            throw fail(lang, 'redirect-bad', undefined, error);
          }
          continue;
        }
        const body = await readText(response, maxBytes);
        return { url, status: response.status, headers: response.headers, text: body.text, truncated: body.truncated, redirects };
      }
    },
  };
  return s;
}

// ---------------------------------------------------------------------------
// robots.txt

/** The groups and sitemap lines of a robots.txt: { groups: [{ agents, rules }], sitemaps }. */
export function parseRobots(text) {
  const sitemaps = [];
  const groups = [];
  let group = null;
  let inRules = false;
  for (const raw of text.split(/\r\n|\r|\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    const colon = line.indexOf(':');
    if (colon < 0) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (key === 'sitemap') {
      if (value) sitemaps.push(value);
    } else if (key === 'user-agent') {
      // User-agent lines in a row share the rules that follow them.
      if (!group || inRules) {
        group = { agents: [], rules: [] };
        groups.push(group);
        inRules = false;
      }
      group.agents.push(value.toLowerCase());
    } else if (group) {
      inRules = true;
      // An empty Disallow allows everything and is no rule.
      if ((key === 'allow' || key === 'disallow') && value) group.rules.push({ allow: key === 'allow', path: value });
    }
  }
  return { groups, sitemaps };
}

/**
 * The rules for one crawler: those of the groups that name it, else those for
 * everyone (*). `named` says whether a group names it.
 */
export function rulesFor(robots, token) {
  const name = token.toLowerCase();
  const named = robots.groups.filter((g) => g.agents.includes(name));
  const groups = named.length ? named : robots.groups.filter((g) => g.agents.includes('*'));
  return { named: named.length > 0, rules: groups.flatMap((g) => g.rules) };
}

const escapeRegExp = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Whether rules allow a path: the longest matching rule wins, Allow on a tie. */
export function allowed(rules, path) {
  let best = null;
  for (const rule of rules) {
    const anchored = rule.path.endsWith('$');
    const body = (anchored ? rule.path.slice(0, -1) : rule.path).split('*').map(escapeRegExp).join('.*');
    if (!new RegExp(`^${body}${anchored ? '$' : ''}`).test(path)) continue;
    if (!best || rule.path.length > best.path.length || (rule.path.length === best.path.length && rule.allow)) best = rule;
  }
  return !best || best.allow;
}

/**
 * Reads robots.txt and refuses the check when it names this checker and
 * disallows the path. A check runs at a person's request, like a browser, so
 * the rules for every crawler (*) do not stop it; only the ones naming it do.
 */
async function respectRobots(s, url) {
  let robots = null;
  let status = null;
  let error = null;
  try {
    const response = await s.get(new URL('/robots.txt', url), { accept: 'text/plain,*/*;q=0.5', maxBytes: 500_000 });
    status = response.status;
    if (response.status === 200 && !/<html/i.test(response.text.slice(0, 500))) robots = parseRobots(response.text);
  } catch (caught) {
    if (!(caught instanceof CheckError) || ['limit', 'nxdomain', 'private', 'dns'].includes(caught.code)) throw caught;
    // The site itself does not answer; the caller decides what that means.
    error = caught;
  }
  if (robots) {
    const { named, rules } = rulesFor(robots, s.settings.robotsToken);
    if (named && !allowed(rules, url.pathname + url.search)) throw fail(s.lang, 'blocked', url.hostname);
  }
  return { robots, status, error };
}

// ---------------------------------------------------------------------------
// The check

const DAY = 86_400_000;
const date = (time, lang) => {
  const d = new Date(time);
  return lang === 'et' ? `${d.getUTCDate()}.${String(d.getUTCMonth() + 1).padStart(2, '0')}.${d.getUTCFullYear()}` : d.toISOString().slice(0, 10);
};

// Server and X-Powered-By values that name a version: Apache/2.4.41, PHP/7.4.3.
const VERSIONED = /\d+\.\d+/;
// Systems that run code on the server, where a known old version is a known
// way in. A static site generator's version (Astro, Hugo) tells an attacker
// nothing, since nothing of it runs on the server.
const SERVER_CMS = /\b(wordpress|woocommerce|joomla|drupal|typo3|prestashop|magento|opencart|concrete|modx|craft cms|bitrix|umbraco|ghost)\b/i;

/** The newest unexpired certificate for a host in the public certificate logs. */
async function newestCertificate(host, s, now) {
  try {
    const response = await s.fetch(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(host)}&match_wildcards=true&expand=dns_names&expand=issuer`, {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(6000),
    });
    if (!response.ok) return null;
    const body = await readText(response, 1_000_000);
    if (body.truncated) return null;
    const certs = JSON.parse(body.text);
    const covers = (names) => names.some((n) => n === host || (n.startsWith('*.') && host.endsWith(n.slice(1)) && host.split('.').length === n.split('.').length));
    let best = null;
    for (const cert of certs) {
      if (cert.revoked || !Array.isArray(cert.dns_names) || !covers(cert.dns_names.map((n) => n.toLowerCase()))) continue;
      const until = Date.parse(cert.not_after);
      if (!(until > now) || Date.parse(cert.not_before) > now) continue;
      if (!best || until > best.until) best = { until, issuer: cert.issuer?.friendly_name ?? null };
    }
    return best;
  } catch {
    return null;
  }
}

/** The Set-Cookie headers of a response, one per cookie. */
function setCookies(headers) {
  if (typeof headers.getSetCookie === 'function') return headers.getSetCookie();
  const joined = headers.get('set-cookie');
  return joined ? joined.split(/,(?=\s*[^;,=\s]+=)/) : [];
}

/** http:// files a page loads (scripts, styles, pictures, frames, media). */
function insecureResources(html) {
  const text = html.replace(/<!--[\s\S]*?-->/g, '');
  const found = new Set();
  for (const m of text.matchAll(/<(script|img|iframe|source|audio|video|embed|track)\b[^>]*?\ssrc\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi)) found.add(m[2]);
  for (const m of text.matchAll(/<link\b[^>]*>/gi)) {
    if (!/\brel\s*=\s*["']?[^"'>]*\b(stylesheet|preload|modulepreload|icon)\b/i.test(m[0])) continue;
    const href = /\shref\s*=\s*["']?(http:\/\/[^"'\s>]+)/i.exec(m[0]);
    if (href) found.add(href[1]);
  }
  return [...found];
}

/**
 * Checks how a website is protected. Options:
 *   lang         'et' (default) or 'en', the language of the texts
 *   userAgent    how the requests introduce themselves
 *   robotsToken  the robots.txt name that turns the check away
 *   maxRequests  requests to the site per check (8)
 *   timeoutMs    time per request (8000)
 *   certificateLog  false skips the certificate log lookup
 *   fetch, doh   the fetch and DNS-over-HTTPS endpoints to use
 * Returns { tool, version, url, host, checkedAt, summary, findings }. Throws a
 * CheckError when the address is not a public site or the site cannot be read.
 */
export async function checkSiteSecurity(input, options = {}) {
  const lang = options.lang === 'en' ? 'en' : 'et';
  const now = options.now ?? Date.now();
  const target = parseTarget(input, lang);
  const s = session(options, lang);
  const findings = [];
  const add = (status, id, facts = {}) => {
    const text = TEXT[lang][id](facts);
    findings.push({ id, status, title: text.title, text: text.text, fix: text.fix ?? null, value: text.value ?? null });
  };

  const httpsUrl = new URL(target);
  httpsUrl.protocol = 'https:';
  httpsUrl.port = '';
  await s.host(httpsUrl.hostname);
  const robots = await respectRobots(s, httpsUrl);

  // The page over HTTPS. A broken certificate is a finding, not the end:
  // the rest is then read over plain http. A site without HTTPS refuses the
  // connection or lets it time out, which robots.txt has already shown.
  let page = null;
  let httpsError = robots.error;
  if (!httpsError) {
    try {
      page = await s.get(httpsUrl);
    } catch (error) {
      if (!(error instanceof CheckError)) throw error;
      httpsError = error;
    }
  }
  if (httpsError && !['tls', 'unreachable', 'timeout'].includes(httpsError.code)) throw httpsError;
  const httpsProblem = httpsError ? (httpsError.code === 'tls' ? 'https-broken' : 'https-missing') : null;
  if (page && page.status === 403 && /challenge/i.test(page.headers.get('cf-mitigated') ?? '')) throw fail(lang, 'bot-protection', httpsUrl.hostname);

  // The same site over plain http: does it move to https?
  const httpUrl = new URL(httpsUrl);
  httpUrl.protocol = 'http:';
  let http = null;
  try {
    let url = httpUrl;
    for (let hop = 0; hop < 3 && s.left() > 0; hop++) {
      const response = await s.get(url, { follow: false, maxBytes: 200_000 });
      const location = response.headers.get('location');
      if (response.status >= 300 && response.status < 400 && location) {
        const next = new URL(location, url);
        if (next.protocol === 'https:') {
          http = { status: response.status, toHttps: true, permanent: response.status === 301 || response.status === 308 };
          break;
        }
        url = parseTarget(next.href, lang);
        continue;
      }
      http = { status: response.status, toHttps: false, response };
      break;
    }
  } catch (error) {
    // Plain http closed is fine.
    if (!(error instanceof CheckError)) throw error;
  }

  if (httpsProblem) {
    // Neither answers: the site is down or slow, not missing HTTPS.
    if (httpsProblem === 'https-missing' && !http?.response) throw httpsError;
    add('error', httpsProblem, { host: httpsUrl.hostname });
    page = http?.response ?? null;
  } else {
    add('ok', 'https-ok', { host: page.url.hostname });
    if (http?.toHttps && http.permanent) add('ok', 'http-redirect');
    else if (http?.toHttps) add('info', 'http-redirect-temporary', { status: http.status });
    else if (http?.response && http.response.status < 400) add('warn', 'http-no-redirect');
  }
  if (!page) return report(target, null, findings, lang, now);
  const finalHost = page.url.hostname;
  const headers = page.headers;

  // The certificate, from the public logs.
  if (!httpsProblem) {
    const cert = options.certificateLog === false ? null : await newestCertificate(finalHost, s, now);
    if (cert) {
      const days = Math.floor((cert.until - now) / DAY);
      add(days < CERT_WARN_DAYS ? 'warn' : 'ok', days < CERT_WARN_DAYS ? 'certificate-expiring' : 'certificate-ok', { until: date(cert.until, lang), days, issuer: cert.issuer });
    } else {
      add('ok', 'certificate-ok', {});
    }
  }

  // Headers. HSTS only counts over HTTPS.
  const csp = headers.get('content-security-policy') ?? '';
  if (!httpsProblem) {
    const hsts = headers.get('strict-transport-security');
    const maxAge = Number(/max-age\s*=\s*"?(\d+)/i.exec(hsts ?? '')?.[1] ?? NaN);
    if (!hsts || !(maxAge > 0)) add('warn', 'hsts-missing');
    else if (maxAge < HSTS_MIN) add('info', 'hsts-short', { days: Math.floor(maxAge / 86_400) });
    else add('ok', 'hsts-ok');
  }
  if (csp) add('ok', 'csp-ok');
  else if (headers.get('content-security-policy-report-only')) add('info', 'csp-report-only');
  else add('info', 'csp-missing');
  if (/nosniff/i.test(headers.get('x-content-type-options') ?? '')) add('ok', 'xcto-ok');
  else add('warn', 'xcto-missing');
  if (/frame-ancestors/i.test(csp) || /^(deny|sameorigin)$/i.test((headers.get('x-frame-options') ?? '').trim())) add('ok', 'frame-ok');
  else add('warn', 'frame-missing');
  const referrer = (headers.get('referrer-policy') ?? '').split(',').map((v) => v.trim().toLowerCase()).filter(Boolean).at(-1);
  if (!referrer) add('info', 'referrer-missing');
  else if (referrer === 'unsafe-url' || referrer === 'no-referrer-when-downgrade') add('warn', 'referrer-unsafe', { value: referrer });
  else add('ok', 'referrer-ok');
  if (headers.get('permissions-policy') || headers.get('feature-policy')) add('ok', 'permissions-ok');
  else add('info', 'permissions-missing');

  const versions = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']
    .map((name) => [name, headers.get(name)])
    .filter(([, value]) => value && VERSIONED.test(value))
    .map(([name, value]) => `${name}: ${value}`);
  if (versions.length) add('warn', 'server-version', { values: versions.join(', ') });
  else add('ok', 'server-quiet');

  const cookies = setCookies(headers).map((line) => {
    const [pair, ...attributes] = line.split(';');
    const flags = attributes.map((a) => a.trim().toLowerCase());
    return { name: pair.split('=')[0].trim(), secure: flags.includes('secure'), httpOnly: flags.includes('httponly') };
  });
  const names = (list) => list.map((c) => c.name).join(', ');
  if (!cookies.length) add('ok', 'cookies-none');
  else {
    const insecure = cookies.filter((c) => !c.secure);
    if (insecure.length) add('warn', 'cookies-insecure', { names: names(insecure), count: insecure.length });
    else add('ok', 'cookies-ok', { count: cookies.length });
    const readable = cookies.filter((c) => !c.httpOnly);
    if (readable.length) add('info', 'cookies-script', { names: names(readable), count: readable.length });
  }

  if (!httpsProblem && /html/i.test(headers.get('content-type') ?? 'text/html')) {
    const insecure = insecureResources(page.text);
    if (insecure.length && !/upgrade-insecure-requests/i.test(csp)) add('warn', 'mixed-content', { count: insecure.length, example: insecure[0] });
  }
  const generator = /<meta\b[^>]*\bname\s*=\s*["']?generator["']?[^>]*>/i.exec(page.text)?.[0];
  const generatorValue = generator && /\scontent\s*=\s*["']([^"']+)["']/i.exec(generator)?.[1];
  if (generatorValue && VERSIONED.test(generatorValue) && SERVER_CMS.test(generatorValue)) add('warn', 'generator-version', { value: generatorValue.trim() });

  // security.txt
  if (s.left() > 0 && !httpsProblem) {
    let found = false;
    try {
      const response = await s.get(new URL('/.well-known/security.txt', page.url), { accept: 'text/plain', maxBytes: 32_000 });
      found = response.status === 200 && /text\/plain/i.test(response.headers.get('content-type') ?? '') && /^\s*contact\s*:/im.test(response.text);
    } catch (error) {
      if (!(error instanceof CheckError)) throw error;
    }
    const domain = finalHost.replace(/^www\./, '');
    if (found) add('ok', 'securitytxt-ok');
    else add('info', 'securitytxt-missing', { host: finalHost, domain, expires: new Date(now + 365 * DAY).toISOString().slice(0, 10) + 'T00:00:00Z' });
  }

  // DNSSEC, from the signed-answer flag of the address lookup.
  const { dnssec } = await s.host(finalHost);
  add(dnssec ? 'ok' : 'info', dnssec ? 'dnssec-ok' : 'dnssec-off');

  return report(target, page.url, findings, lang, now);
}

const RANK = { error: 3, warn: 2, info: 1, ok: 0 };

function report(target, finalUrl, findings, lang, now) {
  const summary = { ok: 0, info: 0, warn: 0, error: 0, status: 'ok' };
  for (const f of findings) {
    summary[f.status]++;
    if (RANK[f.status] > RANK[summary.status]) summary.status = f.status;
  }
  return {
    tool: 'site-security-check',
    version: VERSION,
    lang,
    url: target.href,
    finalUrl: finalUrl?.href ?? null,
    host: (finalUrl ?? target).hostname,
    checkedAt: new Date(now).toISOString(),
    summary,
    findings,
  };
}
