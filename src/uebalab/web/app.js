// UEBA Lab UI: plain ES module, no build step. Hash routes:
// #/ case queue, #/case/<id>, #/users, #/user/<pid>, #/evaluation, #/audit
const app = document.getElementById("app");
const ANALYST = "analyst.demo";

const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const hdrs = { "Content-Type": "application/json", "X-Analyst": ANALYST };
async function call(url, opts = {}) {
  const r = await fetch(url, { headers: hdrs, ...opts });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.detail || `${url}: ${r.status}`);
  return body;
}
const get = (url) => call(url);
const post = (url, body) => call(url, { method: "POST", body: JSON.stringify(body || {}) });
const pct = (v) => (v == null ? "n/a" : `${Math.round(v * 100)}%`);
const LABELS = { true_positive: "True positive", benign: "Benign", expected: "Expected" };
const DETECTORS = {
  deviation: "Deviation from self and peers", offhours: "Unusual hours", rare_resource: "Rare resource",
  novelty: "New country or device", impossible_travel: "Impossible travel", sequence: "Sequence rule",
  service_interactive: "Service account used interactively", after_end_date: "Activity after end date",
  iforest: "Isolation forest",
};
let summary = null;

function scoreCls(s) { return s >= 70 ? "hi" : s >= 45 ? "md" : "lo"; }
function statusChip(st, label) {
  if (st === "closed") return `<span class="chip ${label === "true_positive" ? "bad" : "good"}">closed: ${esc(LABELS[label] || label)}</span>`;
  return `<span class="chip ${st === "open" ? "warn" : "acc"}">${esc(st)}</span>`;
}
function spark(vals) {
  const w = 90, h = 22, n = vals.length;
  const pts = vals.map((v, i) => `${((i / Math.max(1, n - 1)) * w).toFixed(1)},${(h - 2 - (v / 100) * (h - 4)).toFixed(1)}`).join(" ");
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" aria-hidden="true"><polyline points="${pts}"/></svg>`;
}

// Risk trend: one y-axis, 0 to 100. Case window shaded, case threshold dashed.
function trendChart(trend, win, threshold) {
  const W = 760, H = 230, L = 36, R = 10, T = 12, B = 26;
  const n = trend.length;
  const x = (d) => L + (d / Math.max(1, n - 1)) * (W - L - R);
  const y = (v) => T + (1 - v / 100) * (H - T - B);
  const grid = [0, 25, 50, 75, 100].map((v) => `<g class="grid"><line x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}"/></g>
    <g class="axis"><text x="${L - 6}" y="${y(v) + 4}" text-anchor="end">${v}</text></g>`).join("");
  const ticks = trend.filter((t) => t.day % 14 === 0).map((t) => `<g class="axis"><text x="${x(t.day)}" y="${H - 8}" text-anchor="middle">${t.date.slice(5)}</text></g>`).join("");
  const path = trend.map((t, i) => `${i ? "L" : "M"}${x(t.day).toFixed(1)},${y(t.score).toFixed(1)}`).join("");
  const shade = win ? `<rect class="casewin" x="${x(win[0])}" y="${T}" width="${Math.max(3, x(win[1]) - x(win[0]))}" height="${H - T - B}"/>` : "";
  const th = threshold != null ? `<line class="thresh" x1="${L}" x2="${W - R}" y1="${y(threshold)}" y2="${y(threshold)}"/>
    <text x="${W - R}" y="${y(threshold) - 4}" text-anchor="end" font-size="11" style="fill:var(--bad)">case opens</text>` : "";
  return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="risk score by day">${shade}${grid}${ticks}${th}<path class="line" d="${path}"/></svg>`;
}

// ------------------------------------------------------------------ case queue
async function queue() {
  const [c, u] = await Promise.all([get("/api/cases"), get("/api/users?limit=8")]);
  const s = summary;
  const rows = c.cases.map((r) => `<tr>
      <td><a href="#/case/${esc(r.case_id)}"><code>${esc(r.case_id)}</code></a></td>
      <td class="num"><span class="score ${scoreCls(r.peak_score)}">${Math.round(r.peak_score)}</span></td>
      <td class="wrap"><code>${esc(r.subject)}</code><div class="note">${esc(r.peer_group)}</div></td>
      <td class="wrap">${r.reasons.slice(0, 2).map((x) => esc(x.reason)).join("<br>")}</td>
      <td class="hide-sm">${esc(r.detect_date)}</td>
      <td>${statusChip(r.status, r.label)}</td></tr>`).join("");
  const users = u.users.map((r) => `<tr><td><a href="#/user/${esc(r.subject)}"><code>${esc(r.subject)}</code></a><div class="note">${esc(r.role)}</div></td>
      <td class="num"><span class="score ${scoreCls(r.peak_14d)}">${Math.round(r.peak_14d)}</span></td><td>${spark(r.spark)}</td></tr>`).join("");
  app.innerHTML = `
    <section class="panel c12"><div class="kpis">
      <div class="kpi"><div class="v">${s.identities.toLocaleString()}</div><div class="l">identities baselined (${s.service_accounts} service accounts)</div></div>
      <div class="kpi"><div class="v">${s.events.toLocaleString()}</div><div class="l">log events over ${s.days} days</div></div>
      <div class="kpi"><div class="v">${s.signals.toLocaleString()}</div><div class="l">detector signals</div></div>
      <div class="kpi"><div class="v">${s.cases}</div><div class="l">cases to investigate</div></div>
      <div class="kpi"><div class="v">${s.by_status.new}</div><div class="l">new, ${s.by_status.open} open, ${s.by_status.closed} closed</div></div>
    </div></section>
    <section class="panel c8"><h2>Case queue, ranked by risk</h2><div class="scroll"><table>
      <thead><tr><th>Case</th><th class="num">Risk</th><th>Subject</th><th>Top reasons</th><th class="hide-sm">Opened</th><th>Status</th></tr></thead>
      <tbody>${rows || `<tr><td colspan="6" class="muted">No cases.</td></tr>`}</tbody></table></div>
      <p class="note">Subjects are pseudonyms. Names are shown only after an analyst opens a case and gives a reason, and every lookup is audited.</p></section>
    <section class="panel c4"><h2>Highest risk, last 14 days</h2><div class="scroll"><table>
      <thead><tr><th>Subject</th><th class="num">Peak</th><th>30 days</th></tr></thead><tbody>${users}</tbody></table></div>
      <p class="note"><a href="#/users">All users by risk</a></p></section>`;
}

// ------------------------------------------------------------------ case detail
async function caseView(id) {
  const c = await get(`/api/cases/${encodeURIComponent(id)}`);
  const reasons = c.all_reasons.slice(0, 5).map((r) => `<div class="reason-card"><span class="pts">${r.points.toFixed(0)} pts</span>
      <strong>${esc(DETECTORS[r.detector] || r.detector)}</strong> <span class="muted">(${esc(r.key)}, ${r.days} day${r.days > 1 ? "s" : ""})</span>
      <div>${esc(r.reason)}</div>${r.notes.map((n) => `<div class="note">${esc(n)}</div>`).join("")}</div>`).join("");
  const tl = c.timeline.map((t) => t.type === "signal"
    ? `<li class="signal"><div class="when">${esc(t.date)}</div><div class="what"><strong>${esc(DETECTORS[t.detector] || t.detector)}</strong>
        <span class="chip bad">${t.points.toFixed(0)} pts</span>${t.points !== t.raw_points ? `<span class="chip">was ${t.raw_points.toFixed(0)}</span>` : ""}
        <div>${esc(t.text)}</div>${t.notes.map((n) => `<div class="note">${esc(n)}</div>`).join("")}</div></li>`
    : `<li class="event"><div class="when">${esc(t.date.slice(5))} ${esc(t.time.slice(0, 5))}</div><div class="what">${esc(t.source)} ${esc(t.action)}
        <code>${esc(t.resource)}</code>${t.count > 1 ? ` x${t.count}` : ""}${t.mb ? `, ${t.mb} MB` : ""} from ${esc(t.city)} (${esc(t.country)}) on <code>${esc(t.device)}</code></div></li>`).join("");
  const audit = c.audit.slice(-6).reverse().map((a) => `<tr><td>${esc(a.ts.slice(5, 16).replace("T", " "))}</td><td>${esc(a.analyst)}</td><td>${esc(a.action)}</td></tr>`).join("");
  const closed = c.status === "closed";
  app.innerHTML = `
    <section class="panel c12"><div class="row" style="justify-content:space-between">
      <div><h3>Case <code>${esc(c.case_id)}</code> ${statusChip(c.status, c.label)}</h3>
      <div class="muted">Subject <a href="#/user/${esc(c.subject)}"><code>${esc(c.subject)}</code></a>, ${esc(c.kind)}, peer group ${esc(c.peer_group)}.
        Activity ${esc(c.dates.start)} to ${esc(c.dates.end)}, case opened ${esc(c.detect_date)}, ${c.signals} signals.</div></div>
      <div class="kpi"><div class="v score ${scoreCls(c.peak_score)}">${Math.round(c.peak_score)}</div><div class="l">peak risk</div></div></div></section>
    <section class="panel c8"><h2>Risk trend for this subject</h2>${trendChart(c.trend, [c.start_day, c.end_day], 48.7)}
      <p class="note">Daily risk score from 0 to 100. Points decay with a 3 day half-life. Shaded: the case window.</p></section>
    <section class="panel c4"><h2>Analyst actions</h2>
      <div class="row">
        <button class="act primary" id="open" ${c.status !== "new" ? "disabled" : ""}>Open case</button>
        ${Object.entries(LABELS).map(([k, v]) => `<button class="act" data-fb="${k}" ${closed ? "disabled" : ""}>${v}</button>`).join("")}
      </div>
      <div class="row" style="margin-top:10px"><input class="reason" id="why" placeholder="Reason for re-identification" value="Investigating ${esc(c.case_id)}">
        <button class="act" id="reid">Show identity</button></div>
      <div id="ident" style="margin-top:10px"></div><div id="msg" class="note" style="margin-top:8px"></div>
      <h2 style="margin-top:14px">Audit for this case</h2><div class="scroll"><table><tbody>${audit}</tbody></table></div></section>
    <section class="panel c6"><h2>Top contributing signals</h2>${reasons}
      ${c.context_notes.length ? `<h2 style="margin-top:12px">Context applied</h2>${c.context_notes.map((n) => `<div class="note">${esc(n)}</div>`).join("")}` : ""}</section>
    <section class="panel c6"><h2>Timeline</h2><ul class="tl">${tl}</ul></section>`;
  const msg = document.getElementById("msg");
  document.getElementById("open").onclick = async () => { await post(`/api/cases/${id}/open`); route(); };
  document.querySelectorAll("[data-fb]").forEach((b) => { b.onclick = async () => {
    const r = await post(`/api/cases/${id}/feedback`, { label: b.dataset.fb });
    await refreshSummary();
    msg.textContent = `Saved. Applies to the same pattern from day ${r.effective_day}. Cases ${r.cases_before} to ${r.cases_after}.`;
    setTimeout(route, 900);
  }; });
  document.getElementById("reid").onclick = async () => {
    try {
      const r = await post(`/api/cases/${id}/reidentify`, { reason: document.getElementById("why").value });
      document.getElementById("ident").innerHTML = `<div class="ident"><dl class="kv"><dt>Name</dt><dd>${esc(r.name)}</dd>
        <dt>Employee id</dt><dd><code>${esc(r.employee_id)}</code></dd><dt>Email</dt><dd>${esc(r.email)}</dd>
        <dt>Manager</dt><dd><code>${esc(r.manager || "none")}</code></dd></dl><div class="note">This lookup was written to the audit log.</div></div>`;
    } catch (e) { msg.textContent = e.message; }
  };
}

// ------------------------------------------------------------------ users
async function usersView() {
  const u = await get("/api/users?limit=60");
  const rows = u.users.map((r) => `<tr><td><a href="#/user/${esc(r.subject)}"><code>${esc(r.subject)}</code></a></td>
    <td class="hide-sm">${esc(r.peer_group)}</td><td class="num"><span class="score ${scoreCls(r.current_score)}">${Math.round(r.current_score)}</span></td>
    <td class="num">${Math.round(r.peak_14d)}</td><td class="num">${r.cases}</td><td>${spark(r.spark)}</td></tr>`).join("");
  app.innerHTML = `<section class="panel c12"><h2>Users and service accounts by risk</h2><div class="scroll"><table>
    <thead><tr><th>Subject</th><th class="hide-sm">Peer group</th><th class="num">Now</th><th class="num">Peak 14d</th><th class="num">Cases</th><th>Last 30 days</th></tr></thead>
    <tbody>${rows}</tbody></table></div></section>`;
}

async function userView(pid) {
  const u = await get(`/api/users/${encodeURIComponent(pid)}`);
  const cases = u.cases.map((c) => `<li><a href="#/case/${esc(c.case_id)}"><code>${esc(c.case_id)}</code></a> peak ${Math.round(c.peak_score)}, ${esc(c.detect_date)}</li>`).join("");
  const sig = u.signals.slice(-20).reverse().map((s) => `<tr><td class="num">${s.day}</td><td>${esc(DETECTORS[s.detector] || s.detector)}</td>
    <td class="num">${s.points.toFixed(0)}</td><td class="wrap">${esc(s.text)}</td></tr>`).join("");
  app.innerHTML = `<section class="panel c12"><h3><code>${esc(u.subject)}</code></h3><div class="muted">${esc(u.kind)}, ${esc(u.role)}, ${esc(u.team)}</div></section>
    <section class="panel c8"><h2>Risk trend</h2>${trendChart(u.trend, null, 48.7)}</section>
    <section class="panel c4"><h2>Cases</h2>${cases ? `<ul>${cases}</ul>` : `<p class="muted">None.</p>`}</section>
    <section class="panel c12"><h2>Recent signals</h2><div class="scroll"><table><thead><tr><th class="num">Day</th><th>Detector</th><th class="num">Points</th><th>Reason</th></tr></thead>
    <tbody>${sig || `<tr><td colspan="4" class="muted">No signals.</td></tr>`}</tbody></table></div></section>`;
}

// ------------------------------------------------------------------ evaluation
function weeklyBars(configs) {
  const keys = ["full", "neither"];
  const weeks = configs.full.weekly.length;
  const max = Math.max(1, ...keys.flatMap((k) => configs[k]?.weekly || []));
  const W = 560, H = 190, L = 30, B = 24, T = 10, gw = (W - L) / weeks, bw = gw / 2 - 3;
  const y = (v) => T + (1 - v / max) * (H - T - B);
  let bars = "";
  keys.forEach((k, j) => (configs[k]?.weekly || []).forEach((v, i) => {
    bars += `<rect class="bar ${j ? "alt" : ""}" x="${L + i * gw + 2 + j * (bw + 2)}" y="${y(v)}" width="${bw}" height="${H - B - y(v)}"><title>week ${i + 1}: ${v}</title></rect>`;
  }));
  const ticks = [...Array(weeks).keys()].map((i) => `<g class="axis"><text x="${L + i * gw + gw / 2}" y="${H - 8}" text-anchor="middle">w${i + 1}</text></g>`).join("");
  const grid = [0, Math.round(max / 2), max].map((v) => `<g class="grid"><line x1="${L}" x2="${W}" y1="${y(v)}" y2="${y(v)}"/></g><g class="axis"><text x="${L - 6}" y="${y(v) + 4}" text-anchor="end">${v}</text></g>`).join("");
  return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="cases per week">${grid}${bars}${ticks}</svg>
    <div class="row note"><span><span class="chip acc">blue</span> peers and context</span><span><span class="chip">grey</span> neither</span></div>`;
}

async function evaluation() {
  const ev = await get("/api/evaluation");
  const srows = ev.scenarios.map((r) => `<tr><td>${esc(r.sid)}</td><td class="wrap">${esc(r.kind.replaceAll("_", " "))}<div class="note">${esc(r.description)}</div></td>
    <td>${r.detected ? `<span class="chip good">detected</span>` : `<span class="chip bad">missed</span>`}</td>
    <td class="num">${r.days_to_detect ?? "n/a"}</td><td class="num">${r.peak_score == null ? "" : Math.round(r.peak_score)}</td>
    <td class="wrap">${r.case_id ? `<a href="#/case/${esc(r.case_id)}">${esc(r.top_reasons[0] || "")}</a>` : ""}</td></tr>`).join("");
  const crow = Object.values(ev.configs).map((c) => `<tr><td>${esc(c.label)}</td><td class="num">${c.signals.toLocaleString()}</td>
    <td class="num">${c.cases}</td><td class="num">${c.cases_per_week}</td><td class="num">${c.detected} / ${c.scenarios}</td>
    <td class="num">${c.benign_cases}</td><td class="num">${c.other_cases}</td><td class="num">${pct(c.precision)}</td></tr>`).join("");
  const g = ev.gate;
  app.innerHTML = `
    <section class="panel c12"><div class="kpis">
      <div class="kpi"><div class="v">${ev.configs.full.detected} / ${ev.configs.full.scenarios}</div><div class="l">planted scenarios caught</div></div>
      <div class="kpi"><div class="v">${ev.configs.full.median_days_to_detect ?? "n/a"}</div><div class="l">median days to detect</div></div>
      <div class="kpi"><div class="v">${ev.configs.full.cases_per_week}</div><div class="l">cases per week (${ev.configs.full.signals_per_week} signals)</div></div>
      <div class="kpi"><div class="v">${ev.configs.full.benign_cases}</div><div class="l">cases on benign surprises</div></div>
      <div class="kpi"><div class="v"><span class="chip ${g.passed ? "good" : "bad"}">${g.passed ? "passed" : "failed"}</span></div><div class="l">CI gate: within ${g.max_days} days, at most ${g.max_benign} benign</div></div>
    </div></section>
    <section class="panel c12"><h2>Planted scenarios</h2><div class="scroll"><table>
      <thead><tr><th>Id</th><th>Scenario</th><th>Result</th><th class="num">Days to detect</th><th class="num">Peak risk</th><th>Top reason</th></tr></thead><tbody>${srows}</tbody></table></div></section>
    <section class="panel c8"><h2>Alert volume: what context and peer baselines buy</h2><div class="scroll"><table>
      <thead><tr><th>Configuration</th><th class="num">Signals</th><th class="num">Cases</th><th class="num">Per week</th><th class="num">Caught</th><th class="num">Benign cases</th><th class="num">Other cases</th><th class="num">Precision</th></tr></thead>
      <tbody>${crow}</tbody></table></div>
      <p class="note">${ev.identities.toLocaleString()} identities, ${ev.events.toLocaleString()} events, ${ev.days} days with the first ${ev.warmup_days} used only to learn baselines.
      Benign surprises: approved travel, a team reorg, and the finance quarter-end close. Precision counts cases that match a planted scenario.</p></section>
    <section class="panel c4"><h2>Cases per week</h2>${weeklyBars(ev.configs)}</section>`;
}

async function audit() {
  const a = await get("/api/audit?limit=200");
  const rows = a.entries.map((e) => `<tr><td>${esc(e.ts.replace("T", " ").slice(0, 19))}</td><td>${esc(e.analyst)}</td><td>${esc(e.action)}</td>
    <td>${e.case_id ? `<a href="#/case/${esc(e.case_id)}"><code>${esc(e.case_id)}</code></a>` : ""}</td><td><code>${esc(e.subject || "")}</code></td>
    <td class="wrap">${esc(e.reason || e.label || "")}</td></tr>`).join("");
  app.innerHTML = `<section class="panel c12"><h2>Audit log: who viewed what</h2><div class="scroll"><table>
    <thead><tr><th>Time (UTC)</th><th>Analyst</th><th>Action</th><th>Case</th><th>Subject</th><th>Reason or label</th></tr></thead>
    <tbody>${rows || `<tr><td colspan="6" class="muted">Nothing yet.</td></tr>`}</tbody></table></div></section>`;
}

// ------------------------------------------------------------------ router
async function refreshSummary() { summary = await get("/api/summary"); }

async function route() {
  const h = location.hash.replace(/^#/, "") || "/";
  const parts = h.split("/").filter(Boolean);
  const nav = { "": "queue", case: "queue", users: "users", user: "users", evaluation: "evaluation", audit: "audit" }[parts[0] || ""];
  document.querySelectorAll("nav a").forEach((a) => a.classList.toggle("on", a.dataset.nav === nav));
  try {
    if (!summary) await refreshSummary();
    document.getElementById("company").textContent = `${summary.company}, ${summary.start_date} to ${summary.end_date}`;
    if (parts[0] === "case") await caseView(parts[1]);
    else if (parts[0] === "users") await usersView();
    else if (parts[0] === "user") await userView(parts[1]);
    else if (parts[0] === "evaluation") await evaluation();
    else if (parts[0] === "audit") await audit();
    else { await refreshSummary(); await queue(); }
  } catch (e) {
    app.innerHTML = `<section class="panel c12"><p class="muted">${esc(e.message)}</p></section>`;
  }
}
window.addEventListener("hashchange", route);
route();
