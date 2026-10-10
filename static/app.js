"use strict";
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const badge = (s) => `<span class="badge ${esc(s)}">${esc(s)}</span>`;
const list = (a) => (a && a.length ? `<ul>${a.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : '<p class="muted">None.</p>');
const note = (t) => (t ? `<p class="note">${esc(t)}</p>` : "");
let aiStatus = { enabled: false, available: false };

async function post(url, body) {
  const opts = { method: "POST" };
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content;
  if (csrf) opts.headers = { "X-CSRF-Token": csrf };
  if (body instanceof FormData) opts.body = body;
  else { opts.headers = { ...opts.headers, "Content-Type": "application/json" }; opts.body = JSON.stringify(body); }
  const r = await fetch(url, opts);
  const data = await r.json().catch(() => ({ error: "Server returned an invalid response" }));
  if (!r.ok) throw new Error(data.error || "Request failed");
  return data;
}
async function run(btn, out, fn) {
  btn.disabled = true; out.innerHTML = '<p class="muted">Analyzing...</p>';
  try { await fn(); } catch (e) { out.innerHTML = `<p class="err">${esc(e.message)}</p>`; }
  btn.disabled = false;
}
function addFiles(fd, ...inputs) {
  for (const inp of inputs) for (const f of inp.files) fd.append("files", f, f.webkitRelativePath || f.name);
}

/* ---------------- renderers ---------------- */
function renderError(r) {
  const loc = r.location ? `${esc(r.location.file)}:${r.location.line}` : "unknown";
  const snip = r.snippet ? `<h3>Source: ${esc(r.snippet.file)}</h3><pre class="code">${r.snippet.lines.map((l) =>
    `<span class="${l.hit ? "hit" : ""}"><span class="ln">${l.n}</span>${esc(l.text)}</span>`).join("")}</pre>` : "";
  const sim = (r.similar || []).length ? `<div class="box"><h3>Similar earlier errors</h3>${r.similar.map((s) =>
    `<div>#${s.id} - ${esc(s.title)} <span class="muted">(similarity ${s.similarity})</span></div>`).join("")}</div>` : "";
  return `<div class="box"><h2 style="margin-top:0">${esc(r.error_type || "Unknown error")} ${badge(r.category)}</h2>
    <p>${esc(r.explanation)}</p><p class="muted">Language: ${esc(r.language)} - Location: ${loc} - Confidence: ${esc(r.confidence)}</p></div>
    <div class="two"><div class="box"><h3>Verified from your input</h3>${list(r.verified)}</div>
    <div class="box"><h3>Possible causes <span class="muted">(hypotheses)</span></h3>${list(r.possible_causes)}</div></div>
    <div class="box"><h3>Suggested next steps</h3>${list(r.suggestions)}</div>
    ${r.learning ? `<div class="box"><h3>Learning mode</h3><p>${esc(r.learning)}</p></div>` : ""}
    ${snip}${sim}${note(r.note)}`;
}

function graphSvg(g) {
  const nodes = g.nodes.slice(0, 40); if (!nodes.length) return "";
  const W = 760, H = 420, cx = W / 2, cy = H / 2, R = Math.min(W, H) / 2 - 55, pos = {};
  nodes.forEach((n, i) => { const a = (2 * Math.PI * i) / nodes.length; pos[n.id] = [cx + R * Math.cos(a), cy + R * Math.sin(a)]; });
  const edges = g.edges.filter((e) => pos[e.source] && pos[e.target]).map((e) =>
    `<line x1="${pos[e.source][0]}" y1="${pos[e.source][1]}" x2="${pos[e.target][0]}" y2="${pos[e.target][1]}"/>`).join("");
  const dots = nodes.map((n) => `<circle cx="${pos[n.id][0]}" cy="${pos[n.id][1]}" r="6"><title>${esc(n.id)}</title></circle>
    <text x="${pos[n.id][0]}" y="${pos[n.id][1] - 10}" text-anchor="middle">${esc(n.label)}</text>`).join("");
  return `<svg class="graph" viewBox="0 0 ${W} ${H}">${edges}${dots}</svg>`;
}

function renderCode(r) {
  const s = r.summary;
  const cards = ["files", "lines", "functions", "classes", "issues"].map((k) => `<div class="card"><div class="n">${s[k]}</div><div class="l">${k}</div></div>`).join("");
  const files = r.files.map((f) => `<tr><td>${esc(f.path)}</td><td>${esc(f.language)} <span class="muted">${esc(f.mode)}</span></td><td>${f.lines}</td>
    <td>${f.functions.map((x) => esc(x.name) + (x.complexity ? ` (cx ${x.complexity})` : "")).join(", ") || "-"}</td>
    <td>${f.classes.map((x) => esc(x.name)).join(", ") || "-"}</td></tr>`).join("");
  const issues = r.issues.length ? `<table><tr><th>Severity</th><th>File</th><th>Line</th><th>Type</th><th>Message</th></tr>${r.issues.map((i) =>
    `<tr><td>${badge(i.severity)}</td><td>${esc(i.file)}</td><td>${i.line}</td><td>${esc(i.type)}</td><td>${esc(i.message)}</td></tr>`).join("")}</table>` : "<p>No quality issues found.</p>";
  const ext = Object.keys(r.external_imports).join(", ") || "none detected";
  return `<div class="cards">${cards}</div><h2>Dependency graph</h2>${graphSvg(r.graph) || "<p class='muted'>No files.</p>"}
    <p class="muted">${r.graph.edges.length} import relationship(s) between project files. External packages: ${esc(ext)}</p>
    <h2>Quality findings</h2><div class="box">${issues}</div><h2>Files</h2><div class="box" style="overflow:auto"><table>
    <tr><th>Path</th><th>Language</th><th>Lines</th><th>Functions</th><th>Classes</th></tr>${files}</table></div>${note(r.note)}`;
}

function renderSecurity(r) {
  const c = r.counts;
  const cards = ["critical", "high", "medium", "low"].map((k) => `<div class="card"><div class="n">${c[k]}</div><div class="l">${k}</div></div>`).join("");
  const f = r.findings.length ? r.findings.map((x) => `<div class="box"><div>${badge(x.severity)}<b>${esc(x.title)}</b>
    <span class="muted"> ${esc(x.rule)} - ${esc(x.confidence)}</span></div><div class="muted">${esc(x.file)}:${x.line}</div>
    <pre class="code"><span>${esc(x.evidence)}</span></pre><div>${esc(x.explanation)}</div><div><b>Fix:</b> ${esc(x.remediation)}</div></div>`).join("") : "<p>No findings.</p>";
  const d = r.dependencies;
  const deps = d.count ? `<table><tr><th>Status</th><th>Package</th><th>Spec</th><th>Notes</th></tr>${d.dependencies.map((x) =>
    `<tr><td>${badge(x.status)}</td><td>${esc(x.ecosystem)}: ${esc(x.name)}</td><td>${esc(x.spec)}</td><td>${[...x.flags.map(esc), ...x.advisories.map((a) =>
      `<b>${esc(a.id)}</b> ${esc(a.summary)}${a.fixed_in ? ` (fixed in ${esc(a.fixed_in)})` : ""} - ${esc(a.certainty)} [${esc(a.source)}]`)].join("<br>") || "-"}</td></tr>`).join("")}</table>` : "<p class='muted'>No requirements.txt / package.json found.</p>";
  return `<div class="cards">${cards}</div><p class="muted">${r.files_scanned} file(s) scanned.</p><h2>Findings</h2>${f}
    <h2>Dependencies</h2><div class="box" style="overflow:auto">${deps}${d.online_error ? `<p class="err">Online check failed: ${esc(d.online_error)}</p>` : ""}${note(d.note)}</div>${note(r.note)}`;
}

function renderLogs(r) {
  const lv = Object.entries(r.levels).map(([k, v]) => `<div class="card"><div class="n">${v}</div><div class="l">${esc(k)}</div></div>`).join("");
  const g = r.error_groups.length ? `<table><tr><th>Count</th><th>Lines</th><th>Pattern (sample)</th></tr>${r.error_groups.map((x) =>
    `<tr><td><b>${x.count}</b></td><td>${x.first_line}-${x.last_line}</td><td>${esc(x.sample)}</td></tr>`).join("")}</table>` : "<p>No error-level entries.</p>";
  const b = r.bursts.length ? list(r.bursts.map((x) => `${x.minute}: ${x.errors} errors`)) : '<p class="muted">No error bursts detected.</p>';
  const ev = r.events.length ? `<table>${r.events.map((e) => `<tr><td>${e.line}</td><td>${esc(e.text)}</td></tr>`).join("")}</table>` : "";
  return `<div class="cards"><div class="card"><div class="n">${r.total_lines}</div><div class="l">lines</div></div>${lv}
    <div class="card"><div class="n">${r.distinct_errors}</div><div class="l">distinct error patterns</div></div></div>
    <h2>Grouped errors</h2><div class="box">${g}</div><h2>Bursts</h2><div class="box">${b}</div>
    ${r.rare_errors.length ? `<h2>Rare errors (worth a look)</h2><div class="box">${list(r.rare_errors.map((x) => `line ${x.first_line}: ${x.sample}`))}</div>` : ""}
    ${ev ? `<h2>Noteworthy events</h2><div class="box">${ev}</div>` : ""}${note(r.note)}`;
}

function renderGit(r) {
  const repoFiles = (r.files || []).length ? `<section class="repo-file-guide"><div class="section-heading"><div><p class="eyebrow">REPOSITORY MAP</p><h2>Files &amp; likely purpose</h2></div><span class="muted">${r.files.length}${r.files_truncated ? "+" : ""} files</span></div>
    <p class="muted">Purpose notes are estimates based on filenames, paths, and declarations. Open a file to confirm its role.</p>
    <div class="repo-file-list">${r.files.map((file) => `<article class="repo-file-row"><code>${esc(file.path)}</code><p>${esc(file.purpose)}</p></article>`).join("")}</div>
    ${r.files_truncated ? '<p class="note">The list is capped at the configured file limit.</p>' : ""}</section>` : "";
  const commits = `<table><tr><th>Commit</th><th>Author</th><th>Date</th><th>Subject</th><th>Files</th></tr>${r.commits.map((c) =>
    `<tr><td>${esc(c.hash)}</td><td>${esc(c.author)}</td><td>${esc(c.date.slice(0, 16))}</td><td>${esc(c.subject)}</td><td>${c.files.length}</td></tr>`).join("")}</table>`;
  const sus = r.suspects.length ? list(r.suspects.map((s) => `${s.commit} (${s.author}) changed ${s.file}: ${s.subject}`)) : '<p class="muted">No suspects (no error given, or no recent change touched the failing files).</p>';
  const bl = r.blame.length ? `<table>${r.blame.map((b) => `<tr><td>${esc(b.file)}:${b.line}</td><td>${esc(b.commit)}</td><td>${esc(b.author)}</td><td>${esc(b.summary)}</td><td><code>${esc(b.code)}</code></td></tr>`).join("")}</table>` : '<p class="muted">No blame data.</p>';
  const diff = r.diff ? `<h2>Diff ${esc(r.diff.base)}..${esc(r.diff.head)}</h2><div class="box">${esc(r.diff.stat)}${list(r.diff.files.map((f) => `${f.status} ${f.path}`))}</div>` : "";
  return `<h2>Suspect changes</h2><div class="box">${sus}</div><h2>Last change to failing lines (git blame)</h2><div class="box">${bl}</div>${diff}
    ${repoFiles}<h2>Recent commits</h2><div class="box" style="overflow:auto">${commits}</div>${note(r.note)}`;
}
const RENDER = { error: renderError, code: renderCode, security: renderSecurity, logs: renderLogs, git: renderGit };

/* ---------------- wiring ---------------- */
document.querySelectorAll("[data-tab]").forEach((button) => button.addEventListener("click", () => {
  const tab = button.dataset.tab;
  document.querySelectorAll("#nav button").forEach((item) => item.classList.toggle("active", item.dataset.tab === tab));
  document.querySelectorAll(".tab").forEach((item) => item.classList.toggle("active", item.id === "tab-" + tab));
  if (tab === "dashboard") loadDashboard();
  if (tab === "history") loadHistory();
}));

$("err-run").onclick = () => run($("err-run"), $("err-out"), async () => {
  const fd = new FormData(); fd.append("text", $("err-text").value); addFiles(fd, $("err-files"));
  $("err-out").innerHTML = renderError(await post("/api/error", fd));
});
$("err-sample").onclick = () => { $("err-text").value = `Traceback (most recent call last):\n  File "app.py", line 12, in checkout\n    avg = total / len(items)\nZeroDivisionError: division by zero`; };
$("code-run").onclick = () => run($("code-run"), $("code-out"), async () => {
  const fd = new FormData(); addFiles(fd, $("code-files"), $("code-folder")); $("code-out").innerHTML = renderCode(await post("/api/code", fd));
});
$("sec-run").onclick = () => run($("sec-run"), $("sec-out"), async () => {
  const fd = new FormData(); addFiles(fd, $("sec-files"), $("sec-folder")); fd.append("online", $("sec-online").checked ? "1" : "");
  $("sec-out").innerHTML = renderSecurity(await post("/api/security", fd));
});
$("log-run").onclick = () => run($("log-run"), $("log-out"), async () => {
  const fd = new FormData(); fd.append("text", $("log-text").value); addFiles(fd, $("log-file")); $("log-out").innerHTML = renderLogs(await post("/api/logs", fd));
});
$("git-run").onclick = () => run($("git-run"), $("git-out"), async () => {
  $("git-out").innerHTML = renderGit(await post("/api/git", { repo_path: $("git-path").value, repo_url: $("git-url").value, base: $("git-base").value, head: $("git-head").value, error_text: $("git-err").value }));
});

const row = (i) => `<div class="item" data-id="${i.id}"><span>${badge(i.kind)}${esc(i.title)}<br><span class="muted">${esc(i.summary || "")}</span></span><span class="muted">${esc((i.created_at || "").slice(0, 16).replace("T", " "))}</span></div>`;
function bindOpen(root) { root.querySelectorAll(".item[data-id]").forEach((el) => el.onclick = () => openItem(el.dataset.id)); }
async function openItem(id) {
  document.querySelector('#nav button[data-tab="history"]').click();
  const d = await (await fetch("/api/history/" + id)).json();
  $("hist-view").innerHTML = `<h2>${esc(d.title)} <a class="download-link" href="/api/history/${id}/export.json">JSON</a> <a class="download-link" href="/api/history/${id}/export.pdf">PDF</a> <button data-ai-explain="${id}" ${aiStatus.enabled && aiStatus.available ? "" : "disabled"}>Explain locally</button> <button id="del">Delete</button></h2><div id="ai-explanation-${id}"></div>` + (RENDER[d.kind] ? RENDER[d.kind](d.result) : "");
  const explainButton = document.querySelector(`[data-ai-explain="${id}"]`);
  explainButton.onclick = () => run(explainButton, $(`ai-explanation-${id}`), async () => {
    const response = await post(`/api/history/${id}/explain`, {});
    $(`ai-explanation-${id}`).innerHTML = renderAiExplanation(response);
  });
  $("del").onclick = async () => {
    await fetch("/api/history/" + id, { method: "DELETE", headers: { "X-CSRF-Token": document.querySelector('meta[name="csrf-token"]').content } });
    $("hist-view").innerHTML = ""; loadHistory();
  };
}
async function loadHistory() {
  const d = await (await fetch("/api/history")).json();
  $("hist-list").innerHTML = d.items.map(row).join("") || '<p class="muted">Nothing yet - run an analysis.</p>'; bindOpen($("hist-list"));
}

function renderAiExplanation(data) {
  const explanation = data.explanation;
  return `<section class="ai-explanation"><p class="eyebrow">LOCAL AI EXPLANATION</p><p>${esc(explanation.explanation)}</p>
    <div class="two"><div><h3>Verified facts</h3>${list(explanation.verified_facts)}</div><div><h3>Possible causes</h3>${list(explanation.possible_causes)}</div></div>
    <h3>Suggested checks</h3>${list(explanation.suggested_checks)}<p class="note">${esc(data.disclaimer)}</p></section>`;
}

function updateAiExplainButtons() {
  document.querySelectorAll("[data-ai-explain]").forEach((button) => {
    button.disabled = !aiStatus.enabled || !aiStatus.available || !aiStatus.chat_model_installed;
  });
}

async function loadAiStatus() {
  const response = await fetch("/api/ai/status");
  const data = await response.json();
  aiStatus = data;
  const status = $("ai-status");
  const modelsReady = data.embedding_model_installed && data.chat_model_installed;
  if (!data.enabled) status.textContent = "Off by default. Configure local Ollama to enable semantic search and explanations.";
  else if (!data.available) status.textContent = data.error || "Local Ollama is not reachable.";
  else if (!modelsReady) status.textContent = `Ollama is running. Pull ${data.embedding_model} and ${data.chat_model} to enable all tools.`;
  else status.textContent = `Ready · ${data.embedding_model} + ${data.chat_model} · requests stay on this machine.`;
  $("ai-search-button").disabled = !data.enabled || !data.available || !data.embedding_model_installed;
  $("ai-cluster-button").disabled = !data.enabled || !data.available || !data.embedding_model_installed;
  updateAiExplainButtons();
}

$("ai-search-form").onsubmit = (event) => {
  event.preventDefault();
  run($("ai-search-button"), $("ai-search-results"), async () => {
    const data = await post("/api/ai/search", { query: $("ai-search-query").value });
    $("ai-search-results").innerHTML = data.results.map((item) =>
      `<div class="item" data-id="${item.id}"><span>${badge(item.kind)}${esc(item.title)}<br><span class="muted">${esc(item.summary || "")}</span></span><span class="ai-score">${Math.round(item.similarity * 100)}% match</span></div>`).join("") || '<p class="muted">No similar analyses found.</p>';
    bindOpen($("ai-search-results"));
  });
};

$("ai-cluster-button").onclick = () => run($("ai-cluster-button"), $("ai-cluster-results"), async () => {
  const response = await fetch("/api/ai/error-clusters");
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Could not group errors.");
  $("ai-cluster-results").innerHTML = data.clusters.length ? data.clusters.map((cluster, index) =>
    `<section class="ai-cluster"><h3>Recurring group ${index + 1} <span class="muted">${cluster.count} analyses</span></h3><div class="list">${cluster.analyses.map((item) =>
      `<div class="item" data-id="${item.id}"><span>${esc(item.title)}<br><span class="muted">${esc(item.summary || "")}</span></span></div>`).join("")}</div></section>`).join("") : '<p class="muted">No recurring error groups found.</p>';
  bindOpen($("ai-cluster-results"));
});
async function loadDashboard() {
  const d = await (await fetch("/api/stats")).json();
  const names = { error: "Errors", code: "Code scans", security: "Security scans", logs: "Log analyses", git: "Git analyses" };
  $("stats").innerHTML = Object.keys(names).map((k) => `<div class="card"><div class="n">${d.counts[k] || 0}</div><div class="l">${names[k]}</div></div>`).join("");
  $("recent").innerHTML = d.recent.map(row).join("") || '<p class="muted">No analyses yet.</p>'; bindOpen($("recent"));
  $("recurring").innerHTML = d.recurring.map((r) => `<div class="item"><span>${esc(r.title)}</span><span><b>${r.n}x</b> <span class="muted">last ${esc(r.last_seen.slice(0, 10))}</span></span></div>`).join("") || '<p class="muted">No recurring errors yet.</p>';
}

let sampleProjectFiles = [];

function showSampleFile(file) {
  $("sample-selected-name").textContent = file.name;
  $("sample-file-title").textContent = file.name;
  $("sample-file-description").textContent = file.description;
  $("sample-source").innerHTML = file.content.split("\n").map((line, index) =>
    `<span><span class="sample-line-number">${index + 1}</span>${esc(line) || " "}</span>`).join("");
  document.querySelectorAll("[data-sample-file]").forEach((button) => {
    const active = button.dataset.sampleFile === file.name;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
  });
}

function showSampleResults(results) {
  const code = results.code;
  const security = results.security;
  const findings = security.findings.length ? `<ul class="sample-findings">${security.findings.map((finding) =>
    `<li><span class="badge ${esc(finding.severity)}">${esc(finding.severity)}</span><b>${esc(finding.title)}</b><span class="muted">${esc(finding.file)}:${finding.line}</span><p>${esc(finding.explanation)}</p></li>`).join("")}</ul>` : '<p class="muted">No sample findings.</p>';
  $("guided-results").innerHTML = `<div class="section-heading"><div><p class="eyebrow">STATIC ANALYSIS COMPLETE</p><h3>Here is what DebugLens noticed</h3></div><span class="muted">Suggestions to review, not guarantees</span></div>
    <div class="cards"><div class="card"><div class="n">${code.summary.files}</div><div class="l">source files mapped</div></div><div class="card"><div class="n">${code.summary.functions}</div><div class="l">functions found</div></div><div class="card"><div class="n">${code.summary.issues}</div><div class="l">code quality notes</div></div><div class="card"><div class="n">${security.findings.length}</div><div class="l">security indicators</div></div></div>
    <h3>Example security findings</h3>${findings}<p class="muted">These reports have also been saved to your analysis history. The sample application itself was not run.</p>`;
  $("guided-results").hidden = false;
}

$("guided-start").onclick = async () => {
  const button = $("guided-start");
  const status = $("guided-status");
  button.disabled = true;
  $("tab-dashboard").classList.add("sample-mode");
  $("guided-tour").hidden = false;
  $("guided-results").hidden = true;
  status.textContent = "Loading the sample files...";
  try {
    const response = await fetch("/api/demo/sample-project/files");
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not load the sample project.");
    sampleProjectFiles = data.files;
    $("sample-file-list").innerHTML = sampleProjectFiles.map((file) =>
      `<button class="sample-file-button" data-sample-file="${esc(file.name)}" role="tab" aria-selected="false"><span class="sample-file-icon">${file.name === "Dockerfile" ? "D" : file.name.endsWith(".txt") ? "T" : "PY"}</span><span>${esc(file.name)}</span></button>`).join("");
    document.querySelectorAll("[data-sample-file]").forEach((fileButton) => fileButton.addEventListener("click", () => {
      const file = sampleProjectFiles.find((item) => item.name === fileButton.dataset.sampleFile);
      if (file) showSampleFile(file);
    }));
    if (sampleProjectFiles[0]) showSampleFile(sampleProjectFiles[0]);
    status.textContent = "";
  } catch (error) {
    status.textContent = error.message;
  } finally {
    button.disabled = false;
  }
};
$("guide-close").onclick = () => {
  $("guided-tour").hidden = true;
  $("tab-dashboard").classList.remove("sample-mode");
  $("guided-start").focus();
};
$("guided-analyze").onclick = async () => {
  const button = $("guided-analyze");
  const status = $("guided-status");
  button.disabled = true;
  status.textContent = "Analyzing the sample files as text...";
  try {
    const results = await post("/api/demo/sample-project", {});
    showSampleResults(results);
    status.textContent = "Analysis is ready.";
    loadDashboard();
  } catch (error) {
    status.textContent = error.message;
  } finally {
    button.disabled = false;
  }
};

async function initializeAccount() {
  const data = await (await fetch("/api/auth/session")).json();
  if (!data.authenticated) return;
  $("account-email").textContent = data.user.email;
  $("invite-user").hidden = data.user.role !== "owner";
}

$("logout").onclick = async () => {
  await post("/api/auth/logout", {});
  window.location.href = "/login";
};
$("invite-user").onclick = async () => {
  const status = $("account-message");
  try {
    const invite = await post("/api/auth/invites", {});
    status.textContent = `Invitation token (expires in ${invite.expires_in_days} days): ${invite.token}`;
    try { await navigator.clipboard.writeText(invite.token); status.textContent += " (copied)"; } catch (_) { }
  } catch (error) { status.textContent = error.message; }
};
initializeAccount();
loadAiStatus();
loadDashboard();
