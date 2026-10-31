// D2UGuard free cyber checkup — live, passive checks against public records only.
// GET /api/domain-check?domain=example.com
// Looks up public DNS records, the website's TLS certificate and its HTTP security headers.
// It never scans ports, never sends email and never follows links off the domain.

import dns from 'node:dns/promises';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';

export const config = {
  path: '/api/domain-check',
  rateLimit: { windowLimit: 10, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};

const DOMAIN_RE = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const DKIM_SELECTORS = ['selector1', 'selector2', 'google', 'default', 'k1', 'k2', 's1', 's2', 'dkim', 'mail', 'smtp', 'everlytickey1', 'mxvault', 'zoho'];
const STEP_MS = 3500;

const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
});

const timeout = (p, ms = STEP_MS) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), ms))]);
const txt = async (name) => { try { return (await timeout(dns.resolveTxt(name))).map((r) => r.join('')); } catch { return []; } };

// Refuse anything that is not a normal public address (stops the checker being pointed at private networks).
function isPublicIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    return true;
  }
  if (net.isIPv6(ip)) {
    const x = ip.toLowerCase();
    return !(x === '::' || x === '::1' || x.startsWith('fc') || x.startsWith('fd') || x.startsWith('fe80') || x.startsWith('::ffff:'));
  }
  return false;
}

async function publicAddress(host) {
  try {
    const ips = await timeout(dns.resolve4(host));
    const ok = ips.find(isPublicIp);
    return ok ? { ip: ok } : { blocked: true };
  } catch { return null; }
}

function tlsInfo(ip, host) {
  return new Promise((resolve) => {
    const s = tls.connect({ host: ip, port: 443, servername: host, rejectUnauthorized: false, timeout: STEP_MS }, () => {
      const c = s.getPeerCertificate();
      resolve({
        authorised: s.authorized,
        error: s.authorizationError ? String(s.authorizationError) : null,
        protocol: s.getProtocol(),
        validTo: c && c.valid_to ? new Date(c.valid_to).toISOString() : null,
        issuer: c && c.issuer ? (c.issuer.O || c.issuer.CN || null) : null,
      });
      s.end();
    });
    s.on('error', () => resolve(null));
    s.on('timeout', () => { s.destroy(); resolve(null); });
  });
}

function head(mod, ip, host, path = '/') {
  return new Promise((resolve) => {
    const opts = { host: ip, port: mod === https ? 443 : 80, path, method: 'GET', timeout: STEP_MS,
      headers: { Host: host, 'User-Agent': 'D2UGuard-Checkup/1.0 (+https://www.d2uguard.com)' } };
    if (mod === https) { opts.servername = host; opts.rejectUnauthorized = false; }
    const r = mod.request(opts, (res) => { resolve({ status: res.statusCode, headers: res.headers }); res.destroy(); });
    r.on('error', () => resolve(null));
    r.on('timeout', () => { r.destroy(); resolve(null); });
    r.end();
  });
}

// Follow redirects only while they stay on this domain (apex or a subdomain of it), up to three hops.
async function fetchHeaders(domain, host, ip) {
  let cur = { host, ip, path: '/' };
  for (let i = 0; i < 4; i++) {
    const res = await head(https, cur.ip, cur.host, cur.path);
    if (!res) return null;
    if (res.status >= 300 && res.status < 400 && res.headers.location && i < 3) {
      let next;
      try { next = new URL(res.headers.location, `https://${cur.host}${cur.path}`); } catch { return { ...res, host: cur.host }; }
      const h = next.hostname.toLowerCase();
      if (next.protocol !== 'https:' || !(h === domain || h.endsWith('.' + domain))) return { ...res, host: cur.host };
      const addr = h === cur.host ? { ip: cur.ip } : await publicAddress(h);
      if (!addr || !addr.ip) return { ...res, host: cur.host };
      cur = { host: h, ip: addr.ip, path: next.pathname + next.search };
      continue;
    }
    return { ...res, host: cur.host };
  }
  return null;
}

const F = (area, item, status, detail, fix = '') => ({ area, item, status, detail, fix });

async function emailChecks(domain) {
  const out = [];
  const [mx, rootTxt, dmarcTxt, stsTxt, rptTxt, dkimHits] = await Promise.all([
    timeout(dns.resolveMx(domain)).catch(() => []),
    txt(domain),
    txt('_dmarc.' + domain),
    txt('_mta-sts.' + domain),
    txt('_smtp._tls.' + domain),
    Promise.all(DKIM_SELECTORS.map(async (s) => ((await txt(`${s}._domainkey.${domain}`)).some((t) => /p=/i.test(t)) ? s : null))),
  ]);
  const hasMx = mx.length > 0;
  out.push(hasMx
    ? F('email', 'Mail servers (MX)', 'ok', `${mx.length} mail server${mx.length > 1 ? 's' : ''} published.`)
    : F('email', 'Mail servers (MX)', 'info', 'No mail servers published. If this domain never sends or receives email, lock it down with SPF "-all" and DMARC "p=reject".'));

  const spf = rootTxt.filter((t) => /^v=spf1\b/i.test(t));
  if (spf.length === 0) out.push(F('email', 'SPF', 'bad', 'No SPF record found. Anyone can send email that claims to come from this domain.', 'Publish an SPF record listing the services allowed to send mail, ending in "-all".'));
  else if (spf.length > 1) out.push(F('email', 'SPF', 'bad', `${spf.length} SPF records found. Receivers treat this as an error and SPF fails.`, 'Merge them into a single SPF record.'));
  else {
    const r = spf[0];
    const all = (/([-~?+])all\b/i.exec(r) || [])[1];
    const lookups = (r.match(/\b(include:|a\b|a:|mx\b|mx:|ptr|exists:|redirect=)/gi) || []).length;
    if (all === '-') out.push(F('email', 'SPF', lookups > 10 ? 'warn' : 'ok', `SPF published with a hard fail ("-all").${lookups > 10 ? ` It uses about ${lookups} DNS lookups; over 10 makes SPF fail.` : ''}`, lookups > 10 ? 'Flatten or trim the record to 10 lookups or fewer.' : ''));
    else if (all === '~') out.push(F('email', 'SPF', 'warn', 'SPF published with a soft fail ("~all"). Spoofed mail is marked, not rejected.', 'Move to "-all" once DMARC reports confirm all legitimate senders are listed.'));
    else out.push(F('email', 'SPF', 'bad', `SPF published but ends in "${all ? all + 'all' : 'no all rule'}", which does not stop spoofing.`, 'End the record with "-all".'));
  }

  const dmarc = dmarcTxt.find((t) => /^v=DMARC1/i.test(t));
  if (!dmarc) out.push(F('email', 'DMARC', 'bad', 'No DMARC record. The domain can be impersonated and there is no reporting on who is sending as it.', 'Publish DMARC with p=none and a reporting address, then move to quarantine and reject.'));
  else {
    const p = ((/;\s*p=([a-z]+)/i.exec(dmarc) || [])[1] || 'none').toLowerCase();
    const rua = /rua=/i.test(dmarc);
    if (p === 'reject') out.push(F('email', 'DMARC', rua ? 'ok' : 'warn', `DMARC enforced (p=reject).${rua ? ' Aggregate reports are configured.' : ' No reporting address is set.'}`, rua ? '' : 'Add a rua= reporting address so failures are visible.'));
    else if (p === 'quarantine') out.push(F('email', 'DMARC', 'warn', `DMARC at p=quarantine. Spoofed mail goes to junk rather than being rejected.${rua ? '' : ' No reporting address is set.'}`, 'Move to p=reject once reports are clean.'));
    else out.push(F('email', 'DMARC', 'bad', `DMARC is monitor-only (p=none), so spoofed mail is still delivered.${rua ? '' : ' No reporting address is set.'}`, 'Review the reports, then move to quarantine and reject.'));
  }

  const found = dkimHits.filter(Boolean);
  out.push(found.length
    ? F('email', 'DKIM', 'ok', `DKIM key found (selector: ${found.join(', ')}).`)
    : F('email', 'DKIM', hasMx ? 'warn' : 'info', 'No DKIM key found on common selectors. It may use a custom selector, or signing may be off.', 'Confirm DKIM signing is enabled on every service that sends mail for the domain.'));

  const sts = stsTxt.some((t) => /^v=STSv1/i.test(t));
  const rpt = rptTxt.some((t) => /^v=TLSRPTv1/i.test(t));
  out.push(sts
    ? F('email', 'MTA-STS', rpt ? 'ok' : 'warn', `MTA-STS published${rpt ? ' with TLS reporting.' : '; TLS reporting is not set.'}`, rpt ? '' : 'Add a TLS-RPT record to receive delivery failure reports.')
    : F('email', 'MTA-STS', hasMx ? 'warn' : 'info', 'MTA-STS not published, so mail to this domain can be downgraded to unencrypted delivery.', 'Publish an MTA-STS policy and a TLS-RPT record.'));
  return out;
}

async function webChecks(domain) {
  const out = [];
  let host = domain;
  let addr = await publicAddress(domain);
  if (!addr || !addr.ip) { host = 'www.' + domain; addr = await publicAddress(host); }
  if (!addr) { out.push(F('web', 'Website', 'info', 'No website address found for this domain, so web checks were skipped.')); return out; }
  if (addr.blocked) { out.push(F('web', 'Website', 'info', 'The website resolves to a private address, so web checks were skipped.')); return out; }

  const [t, plain, res] = await Promise.all([tlsInfo(addr.ip, host), head(http, addr.ip, host), fetchHeaders(domain, host, addr.ip)]);
  if (!t) { out.push(F('web', 'HTTPS', 'bad', `The website at ${host} did not accept a secure (HTTPS) connection.`, 'Install a valid certificate and serve the site over HTTPS.')); return out; }

  const days = t.validTo ? Math.floor((Date.parse(t.validTo) - Date.now()) / 864e5) : null;
  if (!t.authorised) out.push(F('web', 'Certificate', 'bad', `The certificate is not trusted (${(t.error || 'unknown reason').replace(/_/g, ' ').toLowerCase()}).`, 'Replace it with a certificate from a trusted authority that matches the site name.'));
  else if (days !== null && days < 14) out.push(F('web', 'Certificate', 'bad', `The certificate expires in ${days} day${days === 1 ? '' : 's'}.`, 'Renew it now and automate renewal.'));
  else if (days !== null && days < 30) out.push(F('web', 'Certificate', 'warn', `The certificate expires in ${days} days.`, 'Check that automatic renewal is working.'));
  else out.push(F('web', 'Certificate', 'ok', `Trusted certificate${t.issuer ? ' from ' + t.issuer : ''}, valid for another ${days} days.`));

  out.push(/TLSv1\.[23]/.test(t.protocol || '')
    ? F('web', 'TLS version', 'ok', `Connected using ${t.protocol.replace('v', ' ')}.`)
    : F('web', 'TLS version', 'bad', `Connected using ${t.protocol || 'an unknown protocol'}, which is outdated.`, 'Disable TLS 1.0 and 1.1; allow TLS 1.2 and 1.3 only.'));

  if (plain) {
    const loc = String(plain.headers.location || '');
    out.push(plain.status >= 300 && plain.status < 400 && loc.startsWith('https://')
      ? F('web', 'HTTP to HTTPS', 'ok', 'Visitors who type http:// are sent to the secure site.')
      : F('web', 'HTTP to HTTPS', 'warn', 'The site still answers over unencrypted http:// without redirecting.', 'Redirect all http:// requests to https://.'));
  }

  if (!res) { out.push(F('web', 'Security headers', 'info', 'The website did not return a page, so headers could not be checked.')); return out; }
  const h = res.headers;
  const csp = String(h['content-security-policy'] || '');
  const add = (item, okCond, okText, badText, fix, sev = 'warn') => out.push(okCond ? F('web', item, 'ok', okText) : F('web', item, sev, badText, fix));
  add('HSTS', !!h['strict-transport-security'], 'Browsers are told to always use HTTPS (HSTS).', 'HSTS is not set, so a first visit can be downgraded to http://.', 'Add Strict-Transport-Security with a max-age of at least six months.', 'bad');
  add('Content Security Policy', !!csp, 'A Content Security Policy is set.', 'No Content Security Policy, which leaves more room for injected scripts.', 'Add a Content-Security-Policy header suited to the site.');
  add('Clickjacking protection', !!h['x-frame-options'] || /frame-ancestors/i.test(csp), 'The site cannot be framed by other websites.', 'The site can be embedded in other websites (clickjacking risk).', 'Add X-Frame-Options: DENY or a CSP frame-ancestors rule.');
  add('MIME sniffing', String(h['x-content-type-options'] || '').toLowerCase() === 'nosniff', 'X-Content-Type-Options is set to nosniff.', 'X-Content-Type-Options is not set.', 'Add X-Content-Type-Options: nosniff.');
  add('Referrer policy', !!h['referrer-policy'], 'A referrer policy is set.', 'No referrer policy, so full page addresses can leak to other sites.', 'Add Referrer-Policy: strict-origin-when-cross-origin.');
  const server = String(h['x-powered-by'] || '');
  if (server) out.push(F('web', 'Version disclosure', 'warn', `The site advertises its software ("${server.slice(0, 40)}").`, 'Remove the X-Powered-By header.'));
  return out;
}

function score(findings) {
  const w = { ok: 1, warn: 0.5, bad: 0 };
  const area = (a) => {
    const f = findings.filter((x) => x.area === a && x.status in w);
    return f.length ? Math.round((f.reduce((s, x) => s + w[x.status], 0) / f.length) * 100) : null;
  };
  const email = area('email'), web = area('web');
  const parts = [email, web].filter((x) => x !== null);
  return { overall: parts.length ? Math.round(parts.reduce((a, b) => a + b, 0) / parts.length) : null, email, web };
}

export default async (req) => {
  if (req.method !== 'GET') return json({ error: 'Method not allowed' }, 405);
  const raw = (new URL(req.url).searchParams.get('domain') || '').trim().toLowerCase();
  let domain = raw.replace(/^[a-z]+:\/\//, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '').replace(/\.$/, '');
  if (domain.startsWith('www.')) domain = domain.slice(4);
  if (!DOMAIN_RE.test(domain)) return json({ error: 'Enter a domain name such as example.com.au' }, 400);

  const started = Date.now();
  try {
    const [email, web] = await timeout(Promise.all([emailChecks(domain), webChecks(domain)]), 9000);
    const findings = [...email, ...web];
    return json({ domain, checkedAt: new Date().toISOString(), ms: Date.now() - started, score: score(findings), findings });
  } catch {
    return json({ error: 'The checks took too long to complete. Please try again.' }, 504);
  }
};
