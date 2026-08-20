const state = { report: null, selectedFinding: null };

const drop = document.getElementById("dropzone");
const input = document.getElementById("file-input");
const statusEl = document.getElementById("status");
const reportEl = document.getElementById("report");

drop.addEventListener("click", (event) => {
  if (event.target.tagName !== "LABEL") input.click();
});
drop.addEventListener("dragover", (event) => {
  event.preventDefault();
  drop.classList.add("drag");
});
drop.addEventListener("dragleave", () => drop.classList.remove("drag"));
drop.addEventListener("drop", (event) => {
  event.preventDefault();
  drop.classList.remove("drag");
  if (event.dataTransfer.files[0]) analyzeFile(event.dataTransfer.files[0]);
});
input.addEventListener("change", () => {
  if (input.files[0]) analyzeFile(input.files[0]);
});

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => showTab(tab.dataset.tab));
});

async function analyzeFile(file) {
  statusEl.textContent = `Analyzing ${file.name}…`;
  const body = new FormData();
  body.append("file", file, file.name);
  try {
    const response = await fetch("/api/analyze", { method: "POST", body });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || response.statusText);
    }
    state.report = await response.json();
    state.selectedFinding = null;
    render(state.report);
    statusEl.textContent = `Static report for ${file.name}`;
  } catch (error) {
    statusEl.textContent = `Analysis failed: ${error.message}`;
    reportEl.hidden = true;
  }
}

function showTab(name) {
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.tab === name);
  });
  document.querySelectorAll(".panel").forEach((panel) => {
    panel.classList.toggle("active", panel.id === `panel-${name}`);
  });
}

function render(report) {
  reportEl.hidden = false;
  renderIdentity(report);
  renderOverview(report);
  renderComposition(report);
  renderFindings(report);
  renderEvidence(report, state.selectedFinding);
  renderDetails(report);
  showTab("overview");
}

function renderIdentity(report) {
  const ident = report.identity;
  const cells = [
    ["Name", ident.name],
    ["Detected", `${ident.detected_type} (${ident.detected_family})`],
    ["Size", `${ident.size} bytes`],
    ["SHA-256", report.hashes.sha256 || "n/a"],
    ["Extension match", String(ident.extension_matches)],
    ["Analyzed", `${report.limits.analyzed_bytes} / ${report.limits.file_size} bytes`],
  ];
  document.getElementById("identity-bar").innerHTML = cells
    .map(([k, v]) => `<div><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`)
    .join("");
}

function renderOverview(report) {
  const counts = countBy(report.findings, (item) => item.severity);
  const comp = report.composition || {};
  const ident = (comp.identity || {});
  const caps = (comp.capabilities || []).map((item) => item.family);
  const uniqueCaps = [...new Set(caps)].join(", ") || "none derived";
  const complete = (comp.completeness || {}).state || "unknown";
  document.getElementById("panel-overview").innerHTML = `
    <div class="toolbar">
      <button class="action" id="download-json">Download JSON</button>
    </div>
    <div class="overview">
      <p><strong>${esc(ident.category_label || report.identity.detected_type)}</strong> — ${esc(ident.description || report.identity.description)}</p>
      <p class="muted">${esc(comp.behavior_disclaimer || "Static analysis only. Files are not executed.")}</p>
      <div class="kv">
        <span>Category</span><span>${esc(ident.category_label || "")}</span>
        <span>SHA-256</span><span>${esc(ident.sha256 || report.hashes.sha256 || "n/a")}</span>
        <span>Signed</span><span>${esc(_signedLabel(ident))}</span>
        <span>Capabilities</span><span>${esc(uniqueCaps)}</span>
        <span>Coverage</span><span>${esc(complete)}</span>
        <span>Findings</span><span>${report.findings.length} total
          (high ${counts.high || 0}, medium ${counts.medium || 0}, low ${counts.low || 0}, info ${counts.info || 0})</span>
        <span>Executed</span><span>no</span>
        <span>Network lookups</span><span>no</span>
      </div>
      <h2>Important observations</h2>
      <ul class="next">${((comp.important_observations || []).slice(0, 6).map((item) => `<li>${esc(item.title)} — ${esc(item.summary)}</li>`).join("")) || "<li>None beyond identity.</li>"}</ul>
      <p class="muted">Open the Composition tab for components, dependencies, and analysis gaps.</p>
    </div>
  `;
  document.getElementById("download-json").onclick = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${report.identity.name}.exsoftware.json`;
    a.click();
    URL.revokeObjectURL(url);
  };
}

function _signedLabel(ident) {
  if (ident.signed === "certificate_present") {
    return `certificate present (${ident.certificate_subject || "subject present"}); trust not verified`;
  }
  if (ident.signed === "none") return "no Authenticode table; catalog not checked";
  return "not applicable";
}

function renderComposition(report) {
  const comp = report.composition || {};
  const ident = comp.identity || {};
  const stats = comp.stats || {};
  const tree = (comp.component_tree || [])[0];
  const caps = comp.capabilities || [];
  const deps = comp.dependencies || [];
  const gaps = comp.gaps || [];
  const important = comp.important_observations || [];
  const complete = comp.completeness || {};
  document.getElementById("panel-composition").innerHTML = `
    <div class="compose">
      <h2>What this is</h2>
      <p>${esc(ident.category_label || "")}. ${esc(ident.description || "")}</p>
      <p class="muted">${esc(comp.behavior_disclaimer || "")}</p>
      <div class="kv">
        <span>SHA-256</span><span>${esc(ident.sha256 || "")}</span>
        <span>Extension</span><span>${ident.extension_agrees === false ? "does not match detected type" : ident.extension_agrees === true ? "matches" : "not used as a strong hint"}</span>
        <span>Signed</span><span>${esc(_signedLabel(ident))}</span>
        <span>Coverage</span><span>${esc(complete.state || "")}</span>
      </div>
      <h2>Composition</h2>
      <p>${esc(_statsLine(stats))}</p>
      ${tree ? `<pre class="tree">${esc(_treeText(tree, true, "", true))}</pre>` : ""}
      <h2>Capabilities observed</h2>
      ${caps.map((cap) => `<article class="finding low"><div class="meta">${esc(cap.id)} · ${esc(cap.family)} · ${esc(cap.certainty)}</div><h3>${esc(cap.title)}</h3><p>${esc(cap.statement)}</p><p class="muted">Not established: ${esc(cap.not_established)}</p></article>`).join("") || "<p>None derived.</p>"}
      <h2>Important observations</h2>
      ${important.map((item) => `<article class="finding ${esc(item.severity || "info")}"><div class="meta">${esc(item.id)}</div><h3>${esc(item.title)}</h3><p>${esc(item.summary)}</p><p class="muted">Why surfaced: ${esc(item.why_surfaced)}</p></article>`).join("") || "<p>None beyond identity.</p>"}
      <h2>Dependencies</h2>
      <ul class="next">${deps.slice(0, 40).map((dep) => `<li>[${esc(dep.group)}] ${esc(dep.name)}</li>`).join("") || "<li>None observed.</li>"}</ul>
      <h2>Analysis gaps</h2>
      <p class="muted">${esc(complete.explanation || "")}</p>
      <ul class="next">${gaps.map((gap) => `<li>${esc(gap.statement)}</li>`).join("")}</ul>
    </div>
  `;
}

function _statsLine(stats) {
  const roles = Object.entries(stats.by_role || {}).map(([k, v]) => `${v} ${k.replaceAll("_", " ")}`);
  const extra = stats.contained_entries
    ? `Contained entries ${stats.contained_entries}; unique content ${stats.unique_content_artifacts}; duplicate occurrences ${stats.duplicate_occurrences}.`
    : "No contained file components.";
  return (roles.join("; ") ? roles.join("; ") + ". " : "") + extra;
}

function _treeText(node, isRoot, prefix, isLast) {
  const label = node.label || node.summary || "";
  let text = isRoot ? label + "\n" : prefix + (isLast ? "└── " : "├── ") + label + "\n";
  const children = node.children || [];
  const nextPrefix = isRoot ? "" : prefix + (isLast ? "    " : "│   ");
  children.forEach((child, index) => {
    const last = index === children.length - 1;
    text += _treeText(child, false, nextPrefix, last);
  });
  return text;
}

function renderFindings(report) {
  const items = report.findings
    .map(
      (finding, index) => `
      <article class="finding ${esc(finding.severity)}" data-index="${index}">
        <div class="meta">${esc(finding.severity)} · ${esc(finding.confidence)} confidence · ${esc(finding.certainty || "derived")} · ${esc(finding.category)} · ${esc(finding.analyzer)}</div>
        <h3>${esc(finding.title)}</h3>
        <p>${esc(finding.summary)}</p>
      </article>`
    )
    .join("");
  document.getElementById("panel-findings").innerHTML = `
    <p class="muted">Click a finding to jump to its evidence. Severity means attention, not malice.</p>
    ${items || "<p>No findings.</p>"}
  `;
  document.querySelectorAll("#panel-findings .finding").forEach((node) => {
    node.addEventListener("click", () => {
      state.selectedFinding = report.findings[Number(node.dataset.index)];
      renderEvidence(report, state.selectedFinding);
      showTab("evidence");
    });
  });
}

function renderEvidence(report, selected) {
  const findings = selected ? [selected] : report.findings.filter((item) => item.severity !== "info");
  const blocks = findings
    .map((finding) => {
      const rows = (finding.evidence || [])
        .map(
          (item) => `
          <tr>
            <td>${esc(item.kind)}</td>
            <td>${esc(item.location || "")}</td>
            <td>${esc(item.summary)}</td>
            <td>${esc(item.value || "")}</td>
          </tr>`
        )
        .join("");
      return `
        <div class="evidence-block">
          <div class="meta">${esc(finding.rule_id || finding.legacy_id || finding.id)} · ${esc(finding.certainty || "derived")}</div>
          <h3>${esc(finding.title)}</h3>
          <p class="muted">${esc(finding.summary)}</p>
          <table>
            <thead><tr><th>Kind</th><th>Location</th><th>Summary</th><th>Value</th></tr></thead>
            <tbody>${rows || "<tr><td colspan='4'>No structured evidence attached.</td></tr>"}</tbody>
          </table>
        </div>`;
    })
    .join("");
  document.getElementById("panel-evidence").innerHTML = `
    <p class="muted">${selected ? "Showing evidence for the selected finding." : "Showing evidence for non-info findings. Select one from Findings to focus."}</p>
    ${blocks || "<p>No evidence to show.</p>"}
  `;
}

function renderDetails(report) {
  const analyzers = (report.analyzers || [])
    .map((section) => {
      const err = (section.errors || [])
        .map((item) => `<div class="err">${esc(item.exception_type || "error")}: ${esc(item.message)}</div>`)
        .join("");
      const skip = section.skipped ? `<p class="muted">Skipped: ${esc(section.skip_reason || "")}</p>` : "";
      return `
        <details class="analyzer" ${section.skipped ? "" : "open"}>
          <summary>${esc(section.title)} · ${esc(section.name)} · ${section.duration_ms} ms · ${section.finding_count} finding(s)</summary>
          ${skip}${err}
          <pre>${esc(JSON.stringify(section.details, null, 2))}</pre>
        </details>`;
    })
    .join("");
  document.getElementById("panel-details").innerHTML = analyzers || "<p>No analyzer output.</p>";
}

function countBy(items, fn) {
  const out = {};
  for (const item of items) {
    const key = fn(item);
    out[key] = (out[key] || 0) + 1;
  }
  return out;
}

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}
