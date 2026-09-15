const form = document.getElementById('form');
const submitBtn = document.getElementById('submit');
const progressCard = document.getElementById('progressCard');
const resultCard = document.getElementById('resultCard');
const statusText = document.getElementById('statusText');
const typeBadge = document.getElementById('typeBadge');
const dotsEl = document.getElementById('dots');
const progressFill = document.getElementById('progressFill');
const verdictBadge = document.getElementById('verdictBadge');
const exitInfo = document.getElementById('exitInfo');
const messageEl = document.getElementById('message');
const chartEl = document.getElementById('chart');

const VERDICT_LABEL = {
  excellent: 'Відмінно',
  good: 'Добре',
  unstable: 'Нестабільно',
  failed: 'Недоступно',
  unknown: 'Недоступно',
};

document.getElementById('toggleExplain').addEventListener('click', (e) => {
  const body = document.getElementById('explainBody');
  const hidden = body.hasAttribute('hidden');
  if (hidden) body.removeAttribute('hidden'); else body.setAttribute('hidden', '');
  e.target.textContent = `Як відбувається перевірка? ${hidden ? '▴' : '▾'}`;
});

function resetUI(total) {
  progressCard.hidden = false;
  resultCard.hidden = true;
  typeBadge.hidden = true;
  statusText.textContent = 'Підготовка…';
  progressFill.style.width = '0%';
  dotsEl.innerHTML = '';
  for (let i = 0; i < total; i++) {
    const d = document.createElement('div');
    d.className = 'dot pending';
    d.textContent = i + 1;
    dotsEl.appendChild(d);
  }
}

function setDot(index, ok) {
  const dot = dotsEl.children[index];
  if (!dot) return;
  dot.classList.remove('pending');
  dot.classList.add(ok ? 'ok' : 'fail');
  dot.textContent = ok ? '✓' : '✕';
}

function fmtMs(v) {
  return v === null || v === undefined ? '—' : `${Math.round(v)} мс`;
}

function renderChart(rounds) {
  chartEl.innerHTML = '';
  const maxLatency = Math.max(1, ...rounds.filter(r => r.ok).map(r => r.latency));
  rounds.forEach((r) => {
    const bar = document.createElement('div');
    bar.className = 'bar' + (r.ok ? '' : ' fail');
    const h = r.ok ? Math.max(6, (r.latency / maxLatency) * 100) : 8;
    bar.style.height = `${h}%`;
    bar.title = r.ok ? `${r.latency} мс` : (r.error || 'помилка');
    chartEl.appendChild(bar);
  });
}

function renderResult(summary, fallbackMessage) {
  resultCard.hidden = false;
  const verdict = summary.verdict || 'unknown';
  verdictBadge.className = `badge badge-lg ${verdict}`;
  verdictBadge.textContent = VERDICT_LABEL[verdict] || verdict;

  exitInfo.textContent = summary.exitIp
    ? `Вихідна IP: ${summary.exitIp}${summary.exitLoc ? ' · ' + summary.exitLoc : ''}`
    : '';

  document.getElementById('statSuccess').textContent = summary.rounds.length
    ? `${summary.rounds.filter(r => r.ok).length}/${summary.rounds.length}`
    : '0/0';
  document.getElementById('statAvg').textContent = fmtMs(summary.avg);
  document.getElementById('statJitter').textContent = fmtMs(summary.jitter);
  document.getElementById('statFail').textContent = summary.longestFail ?? '—';

  if (summary.rounds.length) renderChart(summary.rounds);
  else chartEl.innerHTML = '';

  const messages = {
    excellent: 'Проксі стабільне: усі запити пройшли з рівномірною затримкою.',
    good: 'Проксі працює добре, поодинокі збої не критичні.',
    unstable: 'Проксі періодично втрачає з’єднання або сильно "плаває" за часом відповіді — для тривалих задач ризиковано.',
    failed: 'Більшість запитів через проксі не пройшли — проксі фактично непридатний для роботи.',
    unknown: 'Не вдалося визначити тип проксі: порт закритий, недоступний або не відповідає жодним відомим протоколом.',
  };
  messageEl.textContent = fallbackMessage || messages[verdict] || '';
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const host = document.getElementById('host').value.trim();
  const port = document.getElementById('port').value.trim();
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;

  submitBtn.disabled = true;
  submitBtn.textContent = 'Перевіряю…';
  resetUI(10);

  try {
    const resp = await fetch('/api/check-stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host, port, username, password }),
    });

    if (!resp.body) throw new Error('Потокова відповідь не підтримується браузером');

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        handleMessage(JSON.parse(line));
      }
    }
  } catch (err) {
    statusText.textContent = 'Помилка з’єднання із сервером перевірки.';
    renderResult({ verdict: 'unknown', rounds: [] }, err.message);
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Перевірити проксі';
  }
});

function handleMessage(msg) {
  if (msg.event === 'status') {
    statusText.textContent = msg.message;
  } else if (msg.event === 'type-detected') {
    typeBadge.hidden = false;
    typeBadge.textContent = msg.type === 'socks5' ? 'SOCKS5' : 'HTTP';
    statusText.textContent = 'Тестую стабільність з’єднання…';
  } else if (msg.event === 'round') {
    setDot(msg.index, msg.ok);
    progressFill.style.width = `${((msg.index + 1) / msg.total) * 100}%`;
    statusText.textContent = `Спроба ${msg.index + 1} з ${msg.total}: ${msg.ok ? fmtMs(msg.latency) : 'не вдалась'}`;
  } else if (msg.event === 'result') {
    progressFill.style.width = '100%';
    statusText.textContent = 'Готово';
    renderResult(msg.data, msg.message);
  } else if (msg.event === 'error') {
    renderResult({ verdict: 'unknown', rounds: [] }, msg.message);
  }
}

// --- Моніторинг тривалості сесії ---

const monitorBtn = document.getElementById('monitorBtn');
const monitorLive = document.getElementById('monitorLive');
const monLog = document.getElementById('monLog');
const monIp = document.getElementById('monIp');
const monSession = document.getElementById('monSession');
const monChanges = document.getElementById('monChanges');
const monUptime = document.getElementById('monUptime');
const intervalSelect = document.getElementById('interval');

let monitorController = null;
let monitorTicker = null;
let lastSessionStartClient = null;

function fmtDuration(ms) {
  if (ms === null || ms === undefined) return '—';
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return `${m}:${String(rem).padStart(2, '0')}`;
}

function addMonRow(tick) {
  if (tick.sessionChanged) {
    const div = document.createElement('div');
    div.className = 'mon-divider';
    div.textContent = 'нова сесія — IP змінилась';
    monLog.prepend(div);
  }
  const row = document.createElement('div');
  row.className = 'mon-row' + (!tick.ok ? ' fail' : tick.sessionChanged ? ' changed' : '');
  const time = new Date(tick.timestamp).toLocaleTimeString();
  row.innerHTML = `
    <span class="mon-time">${time}</span>
    <span class="mon-ip">${tick.ok ? (tick.ip || '—') + (tick.loc ? ' · ' + tick.loc : '') : 'помилка з’єднання'}</span>
    <span class="mon-lat">${tick.ok ? fmtMs(tick.latency) : ''}</span>
  `;
  monLog.prepend(row);
}

function stopMonitor(finalMessage) {
  if (monitorController) monitorController.abort();
  monitorController = null;
  if (monitorTicker) clearInterval(monitorTicker);
  monitorTicker = null;
  monitorBtn.classList.remove('active');
  monitorBtn.textContent = 'Почати моніторинг сесії';
  if (finalMessage) statusTextForMonitor(finalMessage);
}

function statusTextForMonitor(text) {
  const row = document.createElement('div');
  row.className = 'mon-divider';
  row.textContent = text;
  monLog.prepend(row);
}

monitorBtn.addEventListener('click', async () => {
  if (monitorController) {
    stopMonitor('Моніторинг зупинено вручну.');
    return;
  }

  const host = document.getElementById('host').value.trim();
  const port = document.getElementById('port').value.trim();
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;
  const intervalSeconds = Number(intervalSelect.value);

  if (!host || !port) {
    alert('Спочатку вкажи адресу та порт проксі вище.');
    return;
  }

  monitorLive.hidden = false;
  monLog.innerHTML = '';
  monIp.textContent = '—';
  monSession.textContent = '—';
  monChanges.textContent = '0';
  monUptime.textContent = '—';
  lastSessionStartClient = null;

  monitorController = new AbortController();
  monitorBtn.classList.add('active');
  monitorBtn.textContent = 'Зупинити моніторинг';

  monitorTicker = setInterval(() => {
    if (lastSessionStartClient) {
      monSession.textContent = fmtDuration(Date.now() - lastSessionStartClient);
    }
  }, 1000);

  try {
    const resp = await fetch('/api/monitor-stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host, port, username, password, intervalSeconds }),
      signal: monitorController.signal,
    });

    if (!resp.body) throw new Error('Потокова відповідь не підтримується браузером');
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.error || `HTTP ${resp.status}`);
    }

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        handleMonitorMessage(JSON.parse(line));
      }
    }
    stopMonitor();
  } catch (err) {
    if (err.name !== 'AbortError') {
      statusTextForMonitor(`Моніторинг перервано: ${err.message}`);
    }
    stopMonitor();
  }
});

function handleMonitorMessage(msg) {
  if (msg.event === 'status') {
    statusTextForMonitor(msg.message);
  } else if (msg.event === 'type-detected') {
    statusTextForMonitor(`Тип проксі: ${msg.type === 'socks5' ? 'SOCKS5' : 'HTTP'}. Починаю моніторинг…`);
  } else if (msg.event === 'tick') {
    if (msg.ok) {
      monIp.textContent = msg.ip || '—';
      lastSessionStartClient = Date.now() - msg.currentSessionMs;
      monSession.textContent = fmtDuration(msg.currentSessionMs);
    }
    monChanges.textContent = String(msg.changeCount);
    monUptime.textContent = `${Math.round(msg.uptimePct * 100)}%`;
    addMonRow(msg);
  } else if (msg.event === 'error') {
    statusTextForMonitor(msg.message);
  } else if (msg.event === 'done') {
    statusTextForMonitor(msg.reachedLimit ? 'Досягнуто ліміту 30 хв — моніторинг зупинено. Можна почати новий.' : 'Моніторинг завершено.');
  }
}
