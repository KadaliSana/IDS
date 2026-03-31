const ATTACK_COLORS = {
  'Analysis': '#4a8ec9', 'Backdoor': '#8b6aae', 'Benign': '#34b87a',
  'Bot': '#cf4944', 'Brute Force': '#c97a30', 'DDoS': '#cf4944',
  'DoS': '#3a9e8e', 'Exploits': '#d4922a', 'Fuzzers': '#7a519a',
  'Generic': '#4a8ec9', 'Infilteration': '#a83832', 'Reconnaissance': '#3877a5',
  'Shellcode': '#b5622a', 'Theft': '#cf4944', 'Worms': '#a83832',
  'Injection': '#c97a30', 'Man-in-the-Middle': '#8b6aae',
  'Password Attack': '#d4922a', 'Ransomware': '#cf4944',
  'Port Scan': '#4a8ec9', 'XSS': '#c97a30',
};

const BAR_COLORS = ['#c97a30', '#4a8ec9', '#3a9e8e', '#8b6aae', '#cf4944', '#d4922a', '#34b87a', '#7a519a'];
const attackCountsMap = new Map();

let alerts = [];
let trafficFlows = [];
let selectedIdx = null;
let trafficData = Array(60).fill(0);
let anomalyData = Array(60).fill(0);

const apiBase = window.location.protocol === 'file:' ? 'http://localhost:8000' : '';

function switchTab(name, el) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.getElementById(`tab-${name}`).classList.add('active');
  el.classList.add('active');
}

function fmtUptime(ms) {
  const s = Math.floor(ms / 1000), m = Math.floor(s / 60) % 60, h = Math.floor(s / 3600);
  return String(h).padStart(2, '0') + ':' + String(m).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0');
}

function fmtBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  return (b / 1048576).toFixed(1) + ' MB';
}

function fmtNumber(n) {
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1) + 'k';
  return String(n);
}

// ── Traffic Canvas (Insights Chart) ───────────────────────────
const tCanvas = document.getElementById('trafficCanvas');
const tCtx = tCanvas.getContext('2d');

function drawTraffic() {
  const W = tCanvas.offsetWidth;
  tCanvas.width = W;
  tCanvas.height = 160;
  const H = 160;
  const max = Math.max(...trafficData, 1);
  const sw = W / 60;

  tCtx.clearRect(0, 0, W, H);

  // Grid lines
  tCtx.strokeStyle = 'rgba(255,255,255,0.04)';
  tCtx.lineWidth = 1;
  for (let i = 1; i < 5; i++) {
    const y = (H / 5) * i;
    tCtx.beginPath();
    tCtx.moveTo(0, y);
    tCtx.lineTo(W, y);
    tCtx.stroke();
  }

  // Area gradient fill
  tCtx.beginPath();
  tCtx.moveTo(0, H);
  trafficData.forEach((v, i) => {
    const x = i * sw + sw / 2;
    const y = H - 20 - Math.min(v / max, 1) * (H - 40);
    if (i === 0) tCtx.moveTo(x, y);
    else tCtx.lineTo(x, y);
  });
  tCtx.lineTo(W, H);
  tCtx.lineTo(0, H);
  tCtx.closePath();
  const grad = tCtx.createLinearGradient(0, 0, 0, H);
  grad.addColorStop(0, 'rgba(58,158,142,0.15)');
  grad.addColorStop(1, 'rgba(58,158,142,0.01)');
  tCtx.fillStyle = grad;
  tCtx.fill();

  // Main line
  tCtx.beginPath();
  trafficData.forEach((v, i) => {
    const x = i * sw + sw / 2;
    const y = H - 20 - Math.min(v / max, 1) * (H - 40);
    if (i === 0) tCtx.moveTo(x, y);
    else tCtx.lineTo(x, y);
  });
  tCtx.strokeStyle = 'rgba(58,158,142,0.6)';
  tCtx.lineWidth = 1.5;
  tCtx.stroke();

  // Anomaly spikes
  anomalyData.forEach((v, i) => {
    if (v > 0) {
      const x = i * sw + sw / 2;
      const dotY = H - 20 - v * (H - 40);
      // Vertical spike
      tCtx.beginPath();
      tCtx.setLineDash([3, 3]);
      tCtx.moveTo(x, H - 20);
      tCtx.lineTo(x, dotY);
      tCtx.strokeStyle = v > 0.7 ? 'rgba(231,76,60,0.5)' : 'rgba(243,156,18,0.4)';
      tCtx.lineWidth = 1;
      tCtx.stroke();
      tCtx.setLineDash([]);
      // Dot
      tCtx.beginPath();
      tCtx.arc(x, dotY, 4, 0, Math.PI * 2);
      tCtx.fillStyle = v > 0.7 ? '#e74c3c' : '#f39c12';
      tCtx.fill();
    }
  });
}

// ── Donut Chart ───────────────────────────────────────────────
function drawDonut(benign, malicious) {
  const canvas = document.getElementById('donutCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const size = 160;
  canvas.width = size;
  canvas.height = size;
  const cx = size / 2, cy = size / 2, r = 58, lineW = 14;
  const total = benign + malicious || 1;

  ctx.clearRect(0, 0, size, size);

  // Background ring
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, Math.PI * 2);
  ctx.strokeStyle = 'rgba(255,255,255,0.05)';
  ctx.lineWidth = lineW;
  ctx.stroke();

  // Benign arc
  const benignAngle = (benign / total) * Math.PI * 2;
  const startAngle = -Math.PI / 2;
  if (benign > 0) {
    ctx.beginPath();
    ctx.arc(cx, cy, r, startAngle, startAngle + benignAngle);
    ctx.strokeStyle = '#3a9e8e';
    ctx.lineWidth = lineW;
    ctx.lineCap = 'round';
    ctx.stroke();
  }

  // Malicious arc
  if (malicious > 0) {
    ctx.beginPath();
    ctx.arc(cx, cy, r, startAngle + benignAngle, startAngle + Math.PI * 2);
    ctx.strokeStyle = '#cf4944';
    ctx.lineWidth = lineW;
    ctx.lineCap = 'round';
    ctx.stroke();
  }

  // Update legend
  document.getElementById('donut-benign-val').textContent = fmtNumber(benign);
  document.getElementById('donut-malicious-val').textContent = fmtNumber(malicious);
}

// ── Attack Bars (Top Traffic) ─────────────────────────────────
function renderBars() {
  const types = Array.from(attackCountsMap.entries())
    .map(([name, count], i) => ({
      name,
      count,
      color: ATTACK_COLORS[name] || BAR_COLORS[i % BAR_COLORS.length],
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);

  const total = types.reduce((sum, t) => sum + t.count, 0) || 1;
  const container = document.getElementById('attackBars');

  container.innerHTML = types.map((t, i) => {
    const pct = ((t.count / total) * 100).toFixed(0);
    return `
      <tr>
        <td class="row-num">${String(i + 1).padStart(2, '0')}</td>
        <td class="atk-name">${t.name}</td>
        <td class="bar-cell">
          <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${t.color}"></div></div>
        </td>
        <td style="text-align:right">
          <span class="pct-badge" style="background:${t.color}22;color:${t.color}">${pct}%</span>
        </td>
      </tr>`;
  }).join('');
}

// ── Alert List ────────────────────────────────────────────────
function sevClass(sev) {
  return sev === 'critical' ? 'critical' : sev === 'high' ? 'high' : sev === 'medium' ? 'medium' : 'low';
}

function renderAlerts() {
  const el = document.getElementById('alertList');
  document.getElementById('alertCount').textContent = alerts.length + ' alert' + (alerts.length !== 1 ? 's' : '');

  el.innerHTML = alerts.slice().reverse().map((a, ri) => {
    const i = alerts.length - 1 - ri;
    const sc = sevClass(a.sev);
    return `<div class="alert-item${selectedIdx === i ? ' selected' : ''}" onclick="selectAlert(${i})">
      <div class="sev-dot ${sc}"></div>
      <div class="alert-main">
        <div class="alert-type">${a.type}</div>
        <div class="alert-src">${a.src} → ${a.dst} ${a.time}</div>
      </div>
      <div class="score-badge ${sc}">${a.score}</div>
    </div>`;
  }).join('');
}

// ── Traffic Table ─────────────────────────────────────────────
function renderTrafficTable() {
  const tbody = document.getElementById('trafficBody');
  tbody.innerHTML = trafficFlows.slice(0, 100).map(f => {
    const ts = f.timestamp ? new Date(f.timestamp * 1000).toTimeString().slice(0, 8) : '--';
    const cls = f.is_malicious ? 'malicious' : '';
    const tag = f.is_malicious ? '<span class="tag malicious">THREAT</span>' : '<span class="tag benign">OK</span>';
    return `<tr class="${cls}">
      <td>${ts}</td><td>${f.src || '?'}</td><td>${f.dst || '?'}</td>
      <td>${f.proto || '?'}</td><td>${fmtBytes(f.bytes_in || 0)}</td><td>${fmtBytes(f.bytes_out || 0)}</td>
      <td>${f.risk_score || 0}</td><td>${tag}</td>
    </tr>`;
  }).join('');
}

// ── Detail Panel ──────────────────────────────────────────────
function selectAlert(idx) {
  selectedIdx = idx;
  renderAlerts();
  const a = alerts[idx];
  const sc = sevClass(a.sev);
  const scoreColor = sc === 'critical' ? 'var(--red)' : sc === 'high' ? 'var(--amber)' : 'var(--blue)';
  document.getElementById('noSel').style.display = 'none';
  const dc = document.getElementById('detailContent');
  dc.style.display = 'block';

  // Gauge arc
  const pct = a.score / 100;
  const gaugeR = 55, cx = 80, cy = 70;
  const startA = Math.PI * 0.75, endA = Math.PI * 2.25;
  const a2 = startA + (endA - startA) * pct;
  function arc(r, start, end, stroke, width) {
    const x1 = cx + r * Math.cos(start), y1 = cy + r * Math.sin(start);
    const x2 = cx + r * Math.cos(end), y2 = cy + r * Math.sin(end);
    const large = end - start > Math.PI ? 1 : 0;
    return `<path d="M${x1},${y1} A${r},${r} 0 ${large} 1 ${x2},${y2}" fill="none" stroke="${stroke}" stroke-width="${width}" stroke-linecap="round"/>`;
  }

  const tlsSection = (a.ja3 || a.tls_version || (a.tls_risk_factors && a.tls_risk_factors.length)) ? `
    <div class="panel-section">
      <div class="panel-label">🔐 TLS Fingerprint Analysis</div>
      <div class="tls-detail-grid">
        ${a.ja3 ? `<div class="tls-detail-item"><div class="label">JA3 Hash</div><div class="value">${a.ja3}</div></div>` : ''}
        ${a.ja3s ? `<div class="tls-detail-item"><div class="label">JA3S Hash</div><div class="value">${a.ja3s}</div></div>` : ''}
        ${a.tls_version ? `<div class="tls-detail-item"><div class="label">TLS Version</div><div class="value">${a.tls_version}</div></div>` : ''}
        ${a.tls_threat ? `<div class="tls-detail-item"><div class="label">Threat Match</div><div class="value" style="color:var(--red);font-weight:600">${a.tls_threat}</div></div>` : ''}
      </div>
      ${a.tls_risk_factors && a.tls_risk_factors.length ? `
      <div class="tls-factors">
        ${a.tls_risk_factors.map(f => `<div class="tls-factor">${f}</div>`).join('')}
      </div>` : ''}
    </div>` : '';

  dc.innerHTML = `
    <div class="panel-section">
      <div class="panel-label">Risk Score</div>
      <div class="gauge-wrap">
        <svg width="160" height="120" viewBox="0 0 160 120">
          ${arc(gaugeR, Math.PI * 0.75, Math.PI * 2.25, '#2a2f4a', 8)}
          ${arc(gaugeR, Math.PI * 0.75, a2, scoreColor, 8)}
          <text x="${cx}" y="${cy - 8}" text-anchor="middle" font-family="Inter,sans-serif" font-size="28" font-weight="700" fill="${scoreColor}">${a.score}</text>
          <text x="${cx}" y="${cy + 12}" text-anchor="middle" font-family="Inter,sans-serif" font-size="11" font-weight="600" fill="#6b7a99">${a.sev.toUpperCase()}</text>
          <text x="${cx}" y="${cy + 28}" text-anchor="middle" font-family="Inter,sans-serif" font-size="10" fill="#4a5578">${a.type}</text>
        </svg>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:4px">
        <div><div style="font-size:10px;color:var(--muted);margin-bottom:2px;font-weight:600">Source</div><div style="font-size:11px">${a.src}</div></div>
        <div><div style="font-size:10px;color:var(--muted);margin-bottom:2px;font-weight:600">Destination</div><div style="font-size:11px">${a.dst}</div></div>
        <div><div style="font-size:10px;color:var(--muted);margin-bottom:2px;font-weight:600">Protocol</div><div style="font-size:11px">${a.proto}</div></div>
        <div><div style="font-size:10px;color:var(--muted);margin-bottom:2px;font-weight:600">Time</div><div style="font-size:11px">${a.time}</div></div>
      </div>
    </div>

    ${tlsSection}

    <div class="panel-section">
      <div class="panel-label">SHAP Feature Attribution</div>
      ${a.shap.map(([label, val]) => `
        <div class="shap-row">
          <div class="shap-label" title="${label}">${label}</div>
          <div class="shap-bar-wrap">
            <div class="shap-bar" style="width:${(val * 100).toFixed(0)}%;background:${scoreColor};opacity:${0.4 + val * 0.6}"></div>
            <div class="shap-val">${val.toFixed(2)}</div>
          </div>
        </div>`).join('')}
    </div>

    <div class="panel-section">
      <div class="panel-label">Plain-Language Explanation</div>
      <div class="plain-box">
        <div class="what">What's happening?</div>
        ${a.plain}
      </div>
    </div>

    <div class="panel-section">
      <div class="panel-label">Response Actions</div>
      <div class="action-row">
        <button class="btn danger" onclick="blockAlert(${idx})">🛡 Block ${a.src.split(':')[0]}</button>
        <button class="btn" onclick="ignoreAlert(${idx})">✓ Mark Safe</button>
      </div>
    </div>
  `;
}

async function blockAlert(i) {
  const ip = alerts[i].src.split(':')[0];
  try {
    const res = await fetch(apiBase + '/block/' + ip, { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      alerts[i].blocked = true;
      const dc = document.getElementById('detailContent');
      const btn = dc.querySelector('.btn.danger');
      if (btn) { btn.textContent = '✓ Blocked'; btn.disabled = true; btn.style.opacity = '0.5'; }
      fetchBlocked();
    } else {
      alert('Already blocked: ' + ip);
    }
  } catch (e) { console.error('Block API error:', e); }
}

function ignoreAlert(i) {
  alerts.splice(i, 1);
  selectedIdx = null;
  document.getElementById('noSel').style.display = 'block';
  document.getElementById('detailContent').style.display = 'none';
  renderAlerts();
}

// ── Blocked IPs ───────────────────────────────────────────────
async function fetchBlocked() {
  try {
    const res = await fetch(apiBase + '/blocked');
    const data = await res.json();
    const list = data.blocked || [];
    document.getElementById('blockedCount').textContent = list.length;
    const el = document.getElementById('blockedList');
    if (list.length === 0) {
      el.innerHTML = '<div style="color:var(--muted);font-size:11px;text-align:center;padding:16px">No IPs currently blocked</div>';
      return;
    }
    el.innerHTML = list.map(b => `
      <div class="blocked-item">
        <span>${b.ip} <span style="color:var(--muted);font-size:10px">expires in ${b.expires_in}s</span></span>
        <button class="unblock-btn" onclick="unblockIP('${b.ip}')">Unblock</button>
      </div>
    `).join('');
  } catch (e) {}
}

async function unblockIP(ip) {
  try {
    await fetch(apiBase + '/unblock/' + ip, { method: 'POST' });
    fetchBlocked();
  } catch (e) {}
}

// ── TLS Stats ─────────────────────────────────────────────────
async function fetchTLSStats() {
  try {
    const res = await fetch(apiBase + '/tls/stats');
    const data = await res.json();
    document.getElementById('tls-unique').textContent = data.unique_ja3_count || 0;
    document.getElementById('tls-threats').textContent = data.threats_detected || 0;
    document.getElementById('m-tls').textContent = fmtNumber(data.total_fingerprinted || 0);

    const list = data.top_ja3 || [];
    const el = document.getElementById('tlsJa3List');
    if (list.length === 0) {
      el.innerHTML = '<div style="color:var(--muted);font-size:11px;text-align:center;padding:16px">No TLS data yet</div>';
      return;
    }
    el.innerHTML = list.map(([hash, count]) => `
      <div class="ja3-item">
        <span class="ja3-hash" title="${hash}">${hash}</span>
        <span class="ja3-count">${count}</span>
      </div>
    `).join('');
  } catch (e) {}
}

// ── API Fetch ─────────────────────────────────────────────────
async function fetchStats() {
  try {
    const res = await fetch(apiBase + '/stats');
    if (!res.ok) return;
    const data = await res.json();

    document.getElementById('uptimeLabel').textContent = fmtUptime(data.uptime_seconds * 1000);
    const flows = data.flows_per_sec || 0;
    const totalFlows = data.flows_total || 0;
    const benign = data.benign_count || 0;
    const malicious = data.malicious_count || 0;

    document.getElementById('m-flows').textContent = fmtNumber(totalFlows);
    document.getElementById('m-threats-total').textContent = fmtNumber(data.alerts_total || 0);
    document.getElementById('m-threats-active').textContent = data.alerts_total || 0;
    document.getElementById('m-benign').textContent = fmtNumber(benign);
    document.getElementById('m-malicious').textContent = fmtNumber(malicious);

    trafficData.shift();
    trafficData.push(flows);
    anomalyData.shift();
    anomalyData.push(0);
    drawTraffic();
    drawDonut(benign, malicious);
  } catch (err) {}
}

async function fetchTraffic() {
  try {
    const res = await fetch(apiBase + '/traffic?limit=100');
    const data = await res.json();
    trafficFlows = data.flows || [];
    renderTrafficTable();
  } catch (e) {}
}

// ── WebSocket ─────────────────────────────────────────────────
function connectWS() {
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsHost = window.location.protocol === 'file:' ? 'localhost:8000' : window.location.host;
  const wsUrl = `${wsProtocol}//${wsHost}/ws/alerts`;
  const ws = new WebSocket(wsUrl);

  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.type === 'history' || msg.type === 'alert') {
      const a = msg.data;
      const ts = a.timestamp ? new Date(a.timestamp * 1000) : new Date();

      const alert_ = {
        score: a.risk_score,
        sev: a.severity || 'medium',
        type: a.attack_type || 'Unknown Anomaly',
        src: a.src,
        dst: a.dst,
        proto: a.proto || 'TCP',
        time: ts.toTimeString().slice(0, 8),
        shap: a.top_features || [],
        plain: a.explanation || 'Anomaly detected in traffic pattern.',
        uid: a.uid,
        blocked: a.should_block || a.ja3_blocked,
        ja3: a.ja3 || null,
        ja3s: a.ja3s || null,
        tls_version: a.tls_version || null,
        tls_threat: a.tls_threat || null,
        tls_risk_factors: a.tls_risk_factors || [],
        tls_risk_score: a.tls_risk_score || 0,
      };

      if (alert_.type === 'Benign') return;

      if (msg.type === 'history') {
        if (!alerts.some(x => x.uid === alert_.uid)) {
          alerts.push(alert_);
          const t = alert_.type;
          attackCountsMap.set(t, (attackCountsMap.get(t) || 0) + 1);
        }
      } else {
        if (!alerts.some(x => x.uid === alert_.uid)) {
          alerts.push(alert_);
          if (alerts.length > 50) alerts.shift();
          trafficData[trafficData.length - 1] += 50;
          anomalyData[anomalyData.length - 1] = alert_.score > 80 ? 0.9 : 0.55;
          const t = alert_.type;
          attackCountsMap.set(t, (attackCountsMap.get(t) || 0) + 1);
        }
      }

      renderAlerts();
      renderBars();
    }

    if (msg.type === 'flow' || msg.type === 'flow_history') {
      const f = msg.data;
      if (!trafficFlows.some(x => x.uid === f.uid)) {
        trafficFlows.unshift(f);
        if (trafficFlows.length > 200) trafficFlows.pop();
        renderTrafficTable();
      }
    }
  };

  ws.onclose = () => {
    console.log('WS closed, reconnecting in 3s...');
    setTimeout(connectWS, 3000);
  };
  ws.onerror = () => { ws.close(); };
}

// ── Init ──────────────────────────────────────────────────────
renderBars();
drawTraffic();
drawDonut(0, 0);
setInterval(fetchStats, 1000);
setInterval(fetchBlocked, 5000);
setInterval(fetchTLSStats, 3000);
setInterval(fetchTraffic, 2000);
fetchStats();
fetchBlocked();
fetchTLSStats();
connectWS();
