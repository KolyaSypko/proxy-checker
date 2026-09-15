require('dotenv').config();
const express = require('express');
const net = require('net');
const dns = require('dns').promises;
const crypto = require('crypto');
const axios = require('axios');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');

const app = express();
app.set('trust proxy', 1); // за реверс-проксі хостингу (Render/Railway/…) req.ip = реальний IP клієнта

// --- Базова автентифікація (вмикається, якщо задано APP_USER + APP_PASSWORD) ---
// Обов'язково вмикати перед публічним деплоєм: сервер сам ходить на довільні
// host:port, тому без пароля будь-хто в інтернеті зможе використати його як
// відкритий сканер портів / інструмент для SSRF-проб чужих серверів.
const AUTH_USER = process.env.APP_USER;
const AUTH_PASS = process.env.APP_PASSWORD;

function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

app.use((req, res, next) => {
  if (!AUTH_USER || !AUTH_PASS) return next(); // пароль не заданий — auth вимкнено (лише для локальної розробки)
  const header = req.headers.authorization || '';
  const [scheme, encoded] = header.split(' ');
  if (scheme === 'Basic' && encoded) {
    const [user, pass] = Buffer.from(encoded, 'base64').toString().split(':');
    if (user && pass && safeEqual(user, AUTH_USER) && safeEqual(pass, AUTH_PASS)) {
      return next();
    }
  }
  res.set('WWW-Authenticate', 'Basic realm="Proxy Checker"');
  res.status(401).send('Потрібна автентифікація.');
});

// --- Просте обмеження частоти запитів на перевірку (захист від зловживання) ---
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT_MAX = 20;
const rateBuckets = new Map();

function isRateLimited(ip) {
  const now = Date.now();
  const bucket = rateBuckets.get(ip) || [];
  const fresh = bucket.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
  fresh.push(now);
  rateBuckets.set(ip, fresh);
  return fresh.length > RATE_LIMIT_MAX;
}

app.use(express.json());
app.use(express.static('public'));

const TEST_URL = 'https://www.cloudflare.com/cdn-cgi/trace';

const DETECT_TIMEOUT_MS = 4000;
const ROUND_TIMEOUT_MS = 8000;
const ROUNDS = 10;
const INTERVAL_MS = 1000;

// --- Захист від SSRF: перевіряємо не введений рядок, а реально резолвлену IP,
// щоб не можна було обійти фільтр доменом, що вказує на приватну адресу
// (напр. на 169.254.169.254 — метадата-сервіс хмарних провайдерів). ---
function ipToInt(ip) {
  return ip.split('.').reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
}

function inCidr(ip, base, bits) {
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipToInt(ip) & mask) === (ipToInt(base) & mask);
}

const BLOCKED_V4_RANGES = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16], // link-local, у т.ч. метадата AWS/GCP/Azure
  ['172.16.0.0', 12],
  ['192.168.0.0', 16],
  ['224.0.0.0', 4],
];

function isBlockedIp(ip) {
  if (net.isIPv4(ip)) {
    return BLOCKED_V4_RANGES.some(([base, bits]) => inCidr(ip, base, bits));
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    return lower === '::1' || lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd') ||
      lower.startsWith('::ffff:127.') || lower.startsWith('::ffff:169.254.');
  }
  return true; // невідомий формат — блокуємо за замовчуванням
}

async function resolveAndCheck(host) {
  if (/^localhost$/i.test(host)) return { blocked: true };
  if (net.isIP(host)) return { ip: host, blocked: isBlockedIp(host) };
  try {
    const { address } = await dns.lookup(host);
    return { ip: address, blocked: isBlockedIp(address) };
  } catch {
    return { blocked: true, unresolved: true };
  }
}

// --- Визначення типу проксі шляхом прямого зондування протоколу ---

function detectSocks5(host, port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(DETECT_TIMEOUT_MS, () => finish(false));
    socket.once('error', () => finish(false));
    socket.connect(port, host, () => {
      // SOCKS5 привітання: версія 5, 1 метод автентифікації, "без автентифікації"
      socket.write(Buffer.from([0x05, 0x01, 0x00]));
    });
    socket.once('data', (data) => {
      // Коректна SOCKS5-відповідь: [0x05, <обраний метод>]
      // 0x00 — без пароля, 0x02 — логін/пароль, 0xFF — жоден метод не підійшов,
      // але сервер все одно "розмовляє" протоколом SOCKS5.
      const valid = data.length >= 2 && data[0] === 0x05 && [0x00, 0x02, 0xff].includes(data[1]);
      finish(valid);
    });
  });
}

function detectHttpProxy(host, port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(DETECT_TIMEOUT_MS, () => finish(false));
    socket.once('error', () => finish(false));
    socket.connect(port, host, () => {
      socket.write(
        'CONNECT example.com:443 HTTP/1.1\r\n' +
        'Host: example.com:443\r\n' +
        'Proxy-Connection: Keep-Alive\r\n\r\n'
      );
    });
    socket.once('data', (data) => {
      const head = data.toString('utf8', 0, Math.min(data.length, 32));
      finish(/^HTTP\/1\.[01]\s/.test(head));
    });
  });
}

async function detectProxyType(host, port) {
  if (await detectSocks5(host, port)) return 'socks5';
  if (await detectHttpProxy(host, port)) return 'http';
  return 'unknown';
}

function buildAgent(type, host, port, username, password) {
  const auth = username ? `${encodeURIComponent(username)}:${encodeURIComponent(password || '')}@` : '';
  if (type === 'socks5') {
    return new SocksProxyAgent(`socks5://${auth}${host}:${port}`);
  }
  return new HttpsProxyAgent(`http://${auth}${host}:${port}`);
}

async function runSingleCheck(agent) {
  const start = Date.now();
  try {
    const res = await axios.get(TEST_URL, {
      httpAgent: agent,
      httpsAgent: agent,
      proxy: false,
      timeout: ROUND_TIMEOUT_MS,
      validateStatus: () => true,
    });
    const latency = Date.now() - start;
    const ok = res.status >= 200 && res.status < 500;
    let ip = null, loc = null;
    if (ok && typeof res.data === 'string') {
      const ipMatch = res.data.match(/ip=([^\n]+)/);
      const locMatch = res.data.match(/loc=([^\n]+)/);
      if (ipMatch) ip = ipMatch[1].trim();
      if (locMatch) loc = locMatch[1].trim();
    }
    return { ok, status: res.status, latency, ip, loc };
  } catch (e) {
    return { ok: false, error: e.code || e.message, latency: Date.now() - start };
  }
}

function summarize(type, rounds) {
  const successes = rounds.filter((r) => r.ok);
  const successRate = rounds.length ? successes.length / rounds.length : 0;
  const latencies = successes.map((r) => r.latency);
  const avg = latencies.length ? latencies.reduce((a, b) => a + b, 0) / latencies.length : null;
  const min = latencies.length ? Math.min(...latencies) : null;
  const max = latencies.length ? Math.max(...latencies) : null;
  const jitter = latencies.length > 1
    ? Math.sqrt(latencies.reduce((s, l) => s + (l - avg) ** 2, 0) / latencies.length)
    : 0;

  // Найдовша серія підряд успішних/невдалих спроб — показує, чи збої випадкові,
  // чи проксі "відвалюється" надовго.
  let longestFail = 0, currentFail = 0;
  for (const r of rounds) {
    if (!r.ok) { currentFail++; longestFail = Math.max(longestFail, currentFail); }
    else currentFail = 0;
  }

  let verdict;
  if (rounds.length === 0 || successRate === 0) verdict = 'failed';
  else if (successRate === 1 && jitter <= (avg || 0) * 0.35) verdict = 'excellent';
  else if (successRate >= 0.9 && longestFail <= 1) verdict = 'good';
  else if (successRate >= 0.5) verdict = 'unstable';
  else verdict = 'failed';

  const exit = successes.find((r) => r.ip);

  return {
    type,
    rounds,
    successRate,
    avg, min, max, jitter,
    longestFail,
    verdict,
    exitIp: exit ? exit.ip : null,
    exitLoc: exit ? exit.loc : null,
  };
}

app.post('/api/check-stream', async (req, res) => {
  const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
  if (isRateLimited(clientIp)) {
    return res.status(429).json({ error: `Забагато перевірок. Ліміт: ${RATE_LIMIT_MAX} за 15 хв.` });
  }

  const { host, port, username, password } = req.body || {};
  const portNum = Number(port);

  res.writeHead(200, {
    'Content-Type': 'application/x-ndjson; charset=utf-8',
    'Cache-Control': 'no-cache',
    'Transfer-Encoding': 'chunked',
  });
  const send = (msg) => res.write(JSON.stringify(msg) + '\n');

  if (!host || !Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
    send({ event: 'error', message: 'Вкажіть коректну адресу та порт (1–65535).' });
    return res.end();
  }

  const resolved = await resolveAndCheck(String(host).trim());
  if (resolved.blocked) {
    send({ event: 'error', message: 'Ця адреса заборонена (локальна/службова мережа).' });
    return res.end();
  }

  send({ event: 'status', message: 'Визначаю тип проксі…' });
  const type = await detectProxyType(resolved.ip, portNum);

  if (type === 'unknown') {
    send({
      event: 'result',
      data: summarize('unknown', []),
      message: 'Порт не відповідає ні як SOCKS5, ні як HTTP-проксі. Проксі недоступний або заблокований.',
    });
    return res.end();
  }

  send({ event: 'type-detected', type });

  const agent = buildAgent(type, resolved.ip, portNum, username, password);
  const rounds = [];

  for (let i = 0; i < ROUNDS; i++) {
    const r = await runSingleCheck(agent);
    rounds.push(r);
    send({ event: 'round', index: i, total: ROUNDS, ...r });
    if (i < ROUNDS - 1) await new Promise((r2) => setTimeout(r2, INTERVAL_MS));
  }

  const summary = summarize(type, rounds);
  send({ event: 'result', data: summary });
  res.end();
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Proxy Checker запущено: http://localhost:${PORT}`);
  if (!AUTH_USER || !AUTH_PASS) {
    console.warn('УВАГА: APP_USER/APP_PASSWORD не задані — сервер відкритий без пароля. Не деплойте так публічно.');
  }
});
