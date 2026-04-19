#!/usr/bin/env node
/*
 * whoer.js - Whoer.com scraper / IP inspector
 *
 * Scrapes whoer.com's embedded __NUXT_DATA__ payload to pull every piece
 * of information the site exposes about an IP address (yours or a supplied
 * one): ISP, hostname, OS, browser, canvas, IP type, DNS/anonymizer/blacklist
 * flags, ASN, fraud score, and the rest.
 */

const readline = require('readline');
const fs = require('fs');
const path = require('path');

const UA =
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36';

// ----------- ANSI helpers -----------
const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  blue: '\x1b[34m', magenta: '\x1b[35m', cyan: '\x1b[36m', gray: '\x1b[90m',
};
const c = (col, s) => `${C[col]}${s}${C.reset}`;

// ----------- Networking -----------
async function httpGet(url) {
  const res = await fetch(url, {
    headers: {
      'User-Agent': UA,
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    redirect: 'follow',
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  return await res.text();
}

// ----------- Nuxt payload parser -----------
// The payload is a "devalue"-style flat array where each slot is either a
// primitive, an array of indices (meaning a real array of those resolved
// values), an object whose values are indices, or a tagged tuple like
// ["Reactive", idx] / ["ShallowReactive", idx] / ["Set", ...idxs].
function extractNuxtData(html) {
  const m = html.match(/id="__NUXT_DATA__"[^>]*>(\[[\s\S]*?\])<\/script>/);
  if (!m) return null;
  return JSON.parse(m[1]);
}

function resolveNuxt(raw) {
  const seen = new Map();
  const resolve = (i) => {
    if (typeof i !== 'number') return i;
    if (seen.has(i)) return seen.get(i);
    const node = raw[i];
    if (node === null || typeof node !== 'object') {
      seen.set(i, node);
      return node;
    }
    if (Array.isArray(node)) {
      // Tagged tuples
      if (typeof node[0] === 'string' &&
          ['Reactive', 'ShallowReactive', 'Ref', 'ShallowRef',
           'EmptyShallowRef', 'EmptyRef'].includes(node[0])) {
        const out = resolve(node[1]);
        seen.set(i, out);
        return out;
      }
      if (node[0] === 'Set') {
        const s = new Set();
        seen.set(i, s);
        for (let k = 1; k < node.length; k++) s.add(resolve(node[k]));
        return s;
      }
      if (node[0] === 'Map') {
        const m2 = new Map();
        seen.set(i, m2);
        for (let k = 1; k < node.length; k += 2)
          m2.set(resolve(node[k]), resolve(node[k + 1]));
        return m2;
      }
      // Plain array-of-indices
      const arr = [];
      seen.set(i, arr);
      for (const idx of node) arr.push(resolve(idx));
      return arr;
    }
    const obj = {};
    seen.set(i, obj);
    for (const [k, v] of Object.entries(node)) obj[k] = resolve(v);
    return obj;
  };
  return resolve(0);
}

// Walk the resolved structure looking for the ip-keyed record.
function findIpRecord(resolved, ip) {
  const stack = [resolved];
  const visited = new Set();
  while (stack.length) {
    const n = stack.pop();
    if (!n || typeof n !== 'object' || visited.has(n)) continue;
    visited.add(n);
    if (!Array.isArray(n)) {
      for (const [k, v] of Object.entries(n)) {
        if (ip && typeof k === 'string' && k.startsWith(`ip-${ip}-`) &&
            v && typeof v === 'object') {
          return v;
        }
        if (v && typeof v === 'object') stack.push(v);
      }
    } else {
      for (const v of n) if (v && typeof v === 'object') stack.push(v);
    }
  }
  return null;
}

function findAsnRecord(resolved, ip) {
  const stack = [resolved];
  const visited = new Set();
  while (stack.length) {
    const n = stack.pop();
    if (!n || typeof n !== 'object' || visited.has(n)) continue;
    visited.add(n);
    if (!Array.isArray(n)) {
      for (const [k, v] of Object.entries(n)) {
        if (ip && typeof k === 'string' && k.startsWith(`asn-${ip}-`) &&
            v && typeof v === 'object') {
          return v;
        }
        if (v && typeof v === 'object') stack.push(v);
      }
    } else {
      for (const v of n) if (v && typeof v === 'object') stack.push(v);
    }
  }
  return null;
}

// ----------- Scraping entry points -----------
async function scrapeSelf() {
  const html = await httpGet('https://whoer.com/');
  return parseWhoerHtml(html, null);
}

async function scrapeIp(ip) {
  const html = await httpGet(`https://whoer.com/ip/${encodeURIComponent(ip)}/`);
  return parseWhoerHtml(html, ip);
}

function parseWhoerHtml(html, ipHint) {
  const raw = extractNuxtData(html);
  if (!raw) throw new Error('Could not locate __NUXT_DATA__ in response');
  const resolved = resolveNuxt(raw);

  // Try to find the ip record. For the home page we don't know the ip yet,
  // so scan for any "ip-*" key.
  let ipRec = ipHint ? findIpRecord(resolved, ipHint) : null;
  let asnRec = ipHint ? findAsnRecord(resolved, ipHint) : null;
  if (!ipRec) {
    // generic scan
    const stack = [resolved]; const visited = new Set();
    while (stack.length && !ipRec) {
      const n = stack.pop();
      if (!n || typeof n !== 'object' || visited.has(n)) continue;
      visited.add(n);
      if (!Array.isArray(n)) {
        for (const [k, v] of Object.entries(n)) {
          if (typeof k === 'string' && /^ip-.*-/.test(k)
              && v && typeof v === 'object'
              && (v.ip || v.browser)) { ipRec = v; break; }
          if (v && typeof v === 'object') stack.push(v);
        }
      } else for (const v of n) if (v && typeof v === 'object') stack.push(v);
    }
  }
  if (!ipRec) throw new Error('IP record not found in payload');

  if (!asnRec) {
    const ipVal = ipRec.ip?.ip || ipRec.ip;
    if (typeof ipVal === 'string') asnRec = findAsnRecord(resolved, ipVal);
  }

  return buildReport(ipRec, asnRec);
}

function yn(v) {
  if (v === true) return 'Yes';
  if (v === false) return 'No';
  if (v === null || v === undefined || v === '') return 'Unknown';
  return String(v);
}

function buildReport(ipRec, asnRec) {
  const ip = ipRec.ip || {};
  const br = ipRec.browser || {};

  // whoer's score is an isp_score 0..10 (higher = cleaner); we also expose
  // a derived "fraud score" 0..100 (higher = riskier) like popular IP
  // reputation tools.
  let isp_score = typeof ip.isp_score === 'number' ? ip.isp_score : null;
  let fraud_score = null;
  if (isp_score !== null) {
    fraud_score = Math.max(0, Math.min(100, Math.round((10 - isp_score) * 10)));
    if (ip.is_anonymous_vpn) fraud_score = Math.max(fraud_score, 75);
    if (ip.is_public_proxy) fraud_score = Math.max(fraud_score, 85);
    if (ip.is_route_ip_black_list) fraud_score = Math.max(fraud_score, 90);
  }

  return {
    ip: ip.ip ?? null,
    hostname: ip.hostname ?? null,
    isp: ip.isp ?? ip.asn_organization ?? null,
    asn: ip.asn ?? asnRec?.asn ?? null,
    asn_organization: ip.asn_organization ?? asnRec?.desc ?? null,
    network: ip.network ?? asnRec?.cidr ?? null,
    ip_range: ip.ip_range ?? null,
    ip_type: ip.user_type ?? null,
    connection_type: ip.connection_type ?? null,
    country: ip.country ?? null,
    iso_code: ip.iso_code ?? null,
    continent: ip.continent ?? null,
    continent_code: ip.continent_code ?? null,
    province: ip.province ?? null,
    city: ip.city ?? null,
    postal: ip.postal ?? null,
    latitude: ip.latitude ?? null,
    longitude: ip.longitude ?? null,
    timezone: ip.timezone ?? null,
    local_time: ip.local_time ?? null,
    version: ip.version ?? null,
    ip_number: ip.ip_number ?? null,
    dns_proxy: ip.dns ?? null,
    is_anonymous_vpn: ip.is_anonymous_vpn ?? null,
    is_public_proxy: ip.is_public_proxy ?? null,
    is_route_ip_black_list: ip.is_route_ip_black_list ?? null,
    blacklist: ip.is_route_ip_black_list ?? null,
    anonymizer: (ip.is_anonymous_vpn || ip.is_public_proxy) ?? null,
    os: br.os ?? null,
    user_agent: br.ua ?? null,
    browser: br.name ?? null,
    browser_version: br.version ?? null,
    language: br.language ?? null,
    languages: br.languages ?? null,
    dnt: br.dnt ?? null,
    canvas: br.canvas ?? null,
    isp_score,
    fraud_score,
    asn_record: asnRec || null,
  };
}

// ----------- Presentation -----------
function fmtReport(r) {
  const rows = [
    ['IP Address',       r.ip],
    ['Hostname',         r.hostname],
    ['ISP',              r.isp],
    ['ASN',              r.asn ? `${r.asn}${r.asn_organization ? ' (' + r.asn_organization + ')' : ''}` : null],
    ['Network / CIDR',   r.network],
    ['IP Range',         r.ip_range],
    ['IP Type',          r.ip_type],
    ['Connection Type',  r.connection_type],
    ['IP Version',       r.version ? 'IPv' + r.version : null],
    ['Country',          r.country ? `${r.country}${r.iso_code ? ' [' + r.iso_code + ']' : ''}` : null],
    ['Region / Province',r.province],
    ['City',             r.city],
    ['Postal',           r.postal],
    ['Continent',        r.continent],
    ['Coordinates',      (r.latitude != null && r.longitude != null) ? `${r.latitude}, ${r.longitude}` : null],
    ['Timezone',         r.timezone],
    ['Local Time',       r.local_time],
    ['OS',               r.os],
    ['Browser',          r.browser ? `${r.browser}${r.browser_version ? ' ' + r.browser_version : ''}` : null],
    ['User Agent',       r.user_agent],
    ['Language',         r.language],
    ['Languages',        Array.isArray(r.languages) ? r.languages.join(', ') : r.languages],
    ['Do Not Track',     r.dnt],
    ['Canvas FP',        r.canvas],
    ['DNS / Proxy DNS',  r.dns_proxy],
    ['Anonymous VPN',    yn(r.is_anonymous_vpn)],
    ['Public Proxy',     yn(r.is_public_proxy)],
    ['Anonymizer',       yn(r.anonymizer)],
    ['Blacklisted',      yn(r.blacklist)],
    ['ISP Score',        r.isp_score != null ? `${r.isp_score}/10` : null],
    ['Fraud Score',      r.fraud_score != null ? `${r.fraud_score}/100` : null],
  ];

  const labelW = Math.max(...rows.map(([l]) => l.length));
  const line = '-'.repeat(labelW + 40);
  const out = [];
  out.push(c('cyan', line));
  out.push(c('bold', c('cyan', '  WHOER.COM  —  IP INTELLIGENCE REPORT')));
  out.push(c('cyan', line));
  for (const [label, val] of rows) {
    const v = (val === null || val === undefined || val === '') ? c('gray', 'Unknown') : String(val);
    let col = 'green';
    if (label === 'Fraud Score' && r.fraud_score != null)
      col = r.fraud_score >= 75 ? 'red' : r.fraud_score >= 40 ? 'yellow' : 'green';
    if (label === 'Blacklisted' && r.blacklist) col = 'red';
    if (label === 'Anonymous VPN' && r.is_anonymous_vpn) col = 'red';
    if (label === 'Public Proxy' && r.is_public_proxy) col = 'red';
    if (label === 'Anonymizer' && r.anonymizer) col = 'yellow';
    out.push(`  ${c('bold', label.padEnd(labelW))}  ${c(col, v)}`);
  }
  out.push(c('cyan', line));
  return out.join('\n');
}

// ----------- File output -----------
function saveReport(report, text, outPath) {
  const ext = path.extname(outPath).toLowerCase();
  const stripAnsi = (s) => s.replace(/\x1b\[[0-9;]*m/g, '');
  let content;
  if (ext === '.json') content = JSON.stringify(report, null, 2);
  else content = stripAnsi(text);
  fs.writeFileSync(outPath, content, 'utf8');
}

// ----------- CLI -----------
function parseArgs(argv) {
  const args = { mode: null, ip: null, out: null, help: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') args.help = true;
    else if (a === '--self' || a === '-s') args.mode = 'self';
    else if (a === '--ip' || a === '-i') { args.mode = 'ip'; args.ip = argv[++i]; }
    else if (a === '--out' || a === '-o') args.out = argv[++i];
    else if (a === '--menu' || a === '-m') args.mode = 'menu';
  }
  if (!args.mode && !args.help) args.mode = 'menu';
  return args;
}

function helpText() {
  return `
${c('bold', 'whoer.js')} — Whoer.com scraper / IP inspector

Usage:
  node whoer.js                    Interactive menu
  node whoer.js --self             Check your own public IP
  node whoer.js --ip <ADDR>        Check a specific IP
  node whoer.js --ip 8.8.8.8 -o report.json
  node whoer.js --help             Show this help

Options:
  -s, --self            Detect and report the caller's public IP
  -i, --ip <ADDR>       Report on the given IPv4/IPv6 address
  -o, --out <FILE>      Save report to file (.json => JSON, else plain text)
  -m, --menu            Force interactive menu
  -h, --help            Help
`;
}

// Line-queue prompt: works reliably with both interactive TTYs and piped
// stdin (rl.question races on fast piped input and can drop lines).
function makePrompter() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: process.stdin.isTTY,
  });
  const queue = [];
  const waiters = [];
  let closed = false;
  rl.on('line', (line) => {
    if (waiters.length) waiters.shift()(line);
    else queue.push(line);
  });
  rl.on('close', () => {
    closed = true;
    while (waiters.length) waiters.shift()(null);
  });
  const prompt = (q) => {
    process.stdout.write(q);
    if (queue.length) return Promise.resolve(queue.shift());
    if (closed) return Promise.resolve(null);
    return new Promise((resolve) => waiters.push(resolve));
  };
  return { prompt, close: () => rl.close() };
}

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/;
const IPV6 = /^[0-9a-fA-F:]+$/;
function isValidIp(s) {
  if (!s) return false;
  s = s.trim();
  if (IPV4.test(s)) return true;
  if (s.includes(':') && IPV6.test(s) && s.length >= 3) return true;
  return false;
}

async function runSelf(outFile) {
  console.log(c('gray', '[*] Querying whoer.com for your public IP...'));
  const report = await scrapeSelf();
  const text = fmtReport(report);
  console.log(text);
  if (outFile) {
    saveReport(report, text, outFile);
    console.log(c('green', `[+] Saved to ${outFile}`));
  }
  return report;
}

async function runIp(ip, outFile) {
  if (!isValidIp(ip)) throw new Error(`Invalid IP address: ${ip}`);
  console.log(c('gray', `[*] Querying whoer.com for ${ip}...`));
  const report = await scrapeIp(ip);
  const text = fmtReport(report);
  console.log(text);
  if (outFile) {
    saveReport(report, text, outFile);
    console.log(c('green', `[+] Saved to ${outFile}`));
  }
  return report;
}

async function menu() {
  const { prompt, close } = makePrompter();
  try {
    while (true) {
      console.log();
      console.log(c('bold', c('magenta', '============================================')));
      console.log(c('bold', c('magenta', '   Whoer ip checker')));
      console.log(c('bold', c('magenta', '============================================')));
      console.log(`  ${c('cyan', '1)')} Check MY IP (auto-detect via whoer.com)`);
      console.log(`  ${c('cyan', '2)')} Check a specific IP address`);
      console.log(`  ${c('cyan', '3)')} Help`);
      console.log(`  ${c('cyan', 'q)')} Quit`);
      const choice = (await prompt( c('yellow', 'Select option > '))).trim().toLowerCase();
      if (choice === 'q' || choice === 'quit' || choice === 'exit' || choice === '0') {
        console.log(c('gray', 'Bye.'));
        break;
      }
      try {
        if (choice === '1') {
          const save = (await prompt( 'Save report to a file? (y/N) ')).trim().toLowerCase();
          let out = null;
          if (save === 'y' || save === 'yes') {
            out = (await prompt( 'Output file path: ')).trim() || null;
          }
          await runSelf(out);
        } else if (choice === '2') {
          const ip = (await prompt( 'Enter IP address: ')).trim();
          if (!isValidIp(ip)) { console.log(c('red', 'Invalid IP.')); continue; }
          const save = (await prompt( 'Save report to a file? (y/N) ')).trim().toLowerCase();
          let out = null;
          if (save === 'y' || save === 'yes') {
            out = (await prompt( 'Output file path: ')).trim() || null;
          }
          await runIp(ip, out);
        } else if (choice === '3') {
          console.log(helpText());
        } else {
          console.log(c('red', 'Unknown option.'));
        }
      } catch (e) {
        console.log(c('red', `[!] ${e.message}`));
      }
    }
  } finally {
    close();
  }
}

async function main() {
  const args = parseArgs(process.argv);
  if (args.help) { console.log(helpText()); return; }
  try {
    if (args.mode === 'self') await runSelf(args.out);
    else if (args.mode === 'ip') await runIp(args.ip, args.out);
    else await menu();
  } catch (e) {
    console.error(c('red', `[!] ${e.message}`));
    process.exit(1);
  }
}

main();
