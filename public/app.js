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
