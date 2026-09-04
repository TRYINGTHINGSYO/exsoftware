const state = {
  report: null,
  selectedFinding: null,
  selectedKind: null,
  selectedId: null,
  graphView: "artifacts",
};

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
    state.selectedKind = null;
    state.selectedId = null;
    state.graphView = "artifacts";
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
  state.report = report;
  reportEl.hidden = false;
  renderIdentity(report);
  renderOverview(report);
  renderComposition(report);
  renderGraph(report);
  renderFindings(report);
  renderEvidence(report, state.selectedFinding);
  renderDetails(report);
  showTab("overview");
}

function graphIndex(report) {
  return {
    artifacts: Object.fromEntries((report.artifacts || []).map((item) => [item.id, item])),
    relationships: Object.fromEntries((report.relationships || []).map((item) => [item.id, item])),
    observations: Object.fromEntries((report.observations || []).map((item) => [item.id, item])),
    evidence: Object.fromEntries((report.evidence || []).map((item) => [item.id, item])),
    findings: Object.fromEntries((report.findings || []).map((item) => [item.id, item])),
  };
}

function artifactLabel(report, artifactId) {
  const artifact = graphIndex(report).artifacts[artifactId];
  if (!artifact) return artifactId || "";
  return artifact.names?.[0] || artifact.primary_name || artifact.id;
}

function selectGraph(kind, id, { switchTab = true } = {}) {
  state.selectedKind = kind;
  state.selectedId = id;
  if (kind === "artifacts" || kind === "artifact") state.graphView = "artifacts";
  else if (kind === "relationships" || kind === "relationship") state.graphView = "relationships";
  else if (kind === "observations" || kind === "observation") state.graphView = "observations";
  else if (kind === "evidence") state.graphView = "evidence";
  else if (kind === "findings" || kind === "finding") {
    const finding = (state.report.findings || []).find((item) => item.id === id);
    if (finding) {
      state.selectedFinding = finding;
      renderEvidence(state.report, finding);
      showTab("evidence");
      return;
    }
    state.graphView = "artifacts";
  }
  renderGraph(state.report);
  if (switchTab) showTab("graph");
}

function bindRefClicks(root) {
  root.querySelectorAll("[data-kind][data-id]").forEach((node) => {
    node.addEventListener("click", (event) => {
      event.preventDefault();
      selectGraph(node.dataset.kind, node.dataset.id);
    });
  });
}

function renderRefs(report, refs, title = "Provenance") {
  if (!refs) return "";
  const index = graphIndex(report);
  const groups = [
    ["Artifacts", refs.artifact_ids, "artifact", (id) => artifactLabel(report, id)],
    ["Relationships", refs.relationship_ids, "relationship", (id) => {
      const rel = index.relationships[id];
      return rel ? `${rel.type} ${artifactLabel(report, rel.source_id)} → ${artifactLabel(report, rel.target_id)}` : id;
    }],
    ["Observations", refs.observation_ids, "observation", (id) => index.observations[id]?.statement || id],
    ["Evidence", refs.evidence_ids, "evidence", (id) => index.evidence[id]?.summary || id],
    ["Findings", refs.finding_ids, "finding", (id) => index.findings[id]?.title || id],
    ["Rules", refs.rule_ids, null, (id) => id],
  ];
  const blocks = groups
    .map(([label, ids, kind, formatter]) => {
      const values = [...new Set(ids || [])].filter(Boolean);
      if (!values.length) return "";
      const items = values
        .slice(0, 12)
        .map((id) => {
          const text = esc(formatter(id));
          if (!kind) return `<li>${text}</li>`;
          return `<li><button type="button" class="ref-link" data-kind="${esc(kind)}" data-id="${esc(id)}">${text}</button></li>`;
        })
        .join("");
      return `<div class="ref-group"><div class="meta">${esc(label)}</div><ul>${items}</ul></div>`;
    })
    .join("");
  return blocks ? `<div class="refs"><div class="meta">${esc(title)}</div>${blocks}</div>` : "";
}

function _cryptoState(report) {
  const findings = report.findings || [];
  const validFinding = findings.some((item) => item.legacy_id === "signature.crypto-valid" || item.rule_id === "SIG.CRYPTO.VALID.001");
  const invalidFinding = findings.some((item) => item.legacy_id === "signature.crypto-invalid" || item.rule_id === "SIG.CRYPTO.INVALID.001");
  const rels = (report.relationships || []).filter((rel) => rel.type === "SIGNED_BY");
  if (validFinding || rels.some((rel) => rel.extra && rel.extra.crypto_valid === true)) return "valid";
  if (invalidFinding || rels.some((rel) => rel.extra && rel.extra.crypto_valid === false)) return "invalid";
  return "unknown";
}

function _signedLabel(ident, report) {
  if (ident.signed === "certificate_present") {
    const subject = ident.certificate_subject || "subject present";
    const crypto = _cryptoState(report || {});
    const cryptoBit =
      crypto === "valid"
        ? "embedded digest/CMS verify"
        : crypto === "invalid"
          ? "embedded digest/CMS did not verify"
          : "embedded crypto not established";
    return `certificate present (${subject}); ${cryptoBit}; Windows trust not verified`;
  }
  if (ident.signed === "none") return "no Authenticode table; catalog not checked";
  return "not applicable";
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
  const ident = comp.identity || {};
  const caps = (comp.capabilities || []).map((item) => item.family);
  const uniqueCaps = [...new Set(caps)].join(", ") || "none derived";
  const complete = comp.completeness || {};
  const coverage = complete.state || "unknown";
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
        <span>Signed</span><span>${esc(_signedLabel(ident, report))}</span>
        <span>Capabilities</span><span>${esc(uniqueCaps)}</span>
        <span>Coverage</span><span>${esc(coverage)} · completed ${complete.completed ?? "n/a"} · unsupported ${complete.unsupported ?? "n/a"} · failed ${complete.failed ?? "n/a"}</span>
        <span>Findings</span><span>${report.findings.length} total
          (high ${counts.high || 0}, medium ${counts.medium || 0}, low ${counts.low || 0}, info ${counts.info || 0})</span>
        <span>Executed</span><span>no</span>
        <span>Network lookups</span><span>no</span>
        <span>Trust verified</span><span>${ident.trust_verified === true ? "true" : "false"}</span>
      </div>
      <h2>Important observations</h2>
      <ul class="next">${((comp.important_observations || []).slice(0, 6).map((item) => `<li>${esc(item.title)} — ${esc(item.summary)}</li>`).join("")) || "<li>None beyond identity.</li>"}</ul>
      <p class="muted">Open Composition for components and gaps. Open Graph to follow provenance refs into artifacts, relationships, observations, and evidence.</p>
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
  const notable = comp.notable_components || [];
  const refs = comp.external_references || {};
  const panel = document.getElementById("panel-composition");
  panel.innerHTML = `
    <div class="compose">
      <h2>What this is</h2>
      <p>${esc(ident.category_label || "")}. ${esc(ident.description || "")}</p>
      <p class="muted">${esc(comp.behavior_disclaimer || "")}</p>
      <div class="kv">
        <span>SHA-256</span><span>${esc(ident.sha256 || "")}</span>
        <span>Extension</span><span>${ident.extension_agrees === false ? "does not match detected type" : ident.extension_agrees === true ? "matches" : "not used as a strong hint"}</span>
        <span>Signed</span><span>${esc(_signedLabel(ident, report))}</span>
        <span>Trust verified</span><span>${ident.trust_verified === true ? "true" : "false"}</span>
        <span>Coverage</span><span>${esc(complete.state || "")} · completed ${complete.completed ?? "n/a"} · unsupported ${complete.unsupported ?? "n/a"} · failed ${complete.failed ?? "n/a"} · timeout ${complete.timeout ?? "n/a"} · encrypted ${complete.encrypted_members ?? "n/a"} · limit-rejected ${complete.limit_rejected ?? "n/a"}</span>
      </div>
      <h2>Composition</h2>
      <p>${esc(_statsLine(stats))}</p>
      ${notable.length ? `<p>Notable components: ${notable.map((item) => esc(item.label)).join("; ")}</p>` : ""}
      ${tree ? _treeHtml(tree) : ""}
      <h2>Capabilities observed</h2>
      <p class="muted">${esc(comp.behavior_disclaimer || "")}</p>
      ${caps.map((cap) => `
        <article class="finding low">
          <div class="meta">${esc(cap.id)} · ${esc(cap.family)} · ${esc(cap.certainty)}${cap.confidence ? ` · ${esc(cap.confidence)}` : ""}</div>
          <h3>${esc(cap.title)}</h3>
          <p>${esc(cap.statement)}</p>
          ${(cap.evidence || []).length ? `<div class="chips">${cap.evidence.slice(0, 8).map((item) => `<span class="chip">${esc(item)}</span>`).join("")}</div>` : ""}
          <p class="muted">Not established: ${esc(cap.not_established)}</p>
          ${renderRefs(report, cap.refs, "Capability provenance")}
        </article>`).join("") || "<p>None derived.</p>"}
      <h2>Important observations</h2>
      ${important.map((item) => `
        <article class="finding ${esc(item.severity || "info")}">
          <div class="meta">${esc(item.id)}</div>
          <h3>${esc(item.title)}</h3>
          <p>${esc(item.summary)}</p>
          <p class="muted">Why surfaced: ${esc(item.why_surfaced)}</p>
          ${renderRefs(report, item.refs, "Observation provenance")}
        </article>`).join("") || "<p>None beyond identity.</p>"}
      <h2>Dependencies</h2>
      <ul class="next">${deps.slice(0, 40).map((dep) => `
        <li>[${esc(dep.group)}] ${esc(dep.name)} · ${esc(dep.relationship_type || "")}
          ${renderRefs(report, dep.refs, "")}
        </li>`).join("") || "<li>None observed.</li>"}</ul>
      ${_externalHtml(refs)}
      <h2>Analysis gaps</h2>
      <p class="muted">${esc(complete.explanation || "")}</p>
      ${gaps.map((gap) => `<article class="finding info"><p>${esc(gap.statement)}</p>${renderRefs(report, gap.refs, "Gap provenance")}</article>`).join("")}
    </div>
  `;
  bindRefClicks(panel);
}

function _externalHtml(refs) {
  const groups = [
    ["urls", "URLs (strings; not fetched)"],
    ["ips", "IP literals (strings; not contacted)"],
    ["registry_paths", "Registry path strings"],
    ["domains", "Domains (strings; not contacted)"],
    ["imported_modules", "Imported modules"],
    ["referenced_libraries", "Referenced libraries"],
  ];
  const blocks = groups
    .map(([key, title]) => {
      const values = refs[key] || [];
      if (!values.length) return "";
      return `<h2>${esc(title)}</h2><ul class="next">${values.slice(0, 12).map((item) => `<li>${esc(item.value || item)}</li>`).join("")}</ul>`;
    })
    .join("");
  return blocks;
}

function _statsLine(stats) {
  const roles = Object.entries(stats.by_role || {}).map(([k, v]) => `${v} ${k.replaceAll("_", " ")}`);
  const extra = stats.contained_entries
    ? `Contained entries ${stats.contained_entries}; unique content ${stats.unique_content_artifacts}; duplicate occurrences ${stats.duplicate_occurrences}.`
    : "No contained file components.";
  return (roles.join("; ") ? roles.join("; ") + ". " : "") + extra;
}

function _treeHtml(node) {
  return `<ul class="tree-list">${_treeItem(node)}</ul>`;
}

function _treeItem(node) {
  const label = node.label || node.summary || node.artifact_id || "";
  const button = node.artifact_id
    ? `<button type="button" class="tree-link" data-kind="artifact" data-id="${esc(node.artifact_id)}">${esc(label)}</button>`
    : esc(label);
  const children = (node.children || []).map(_treeItem).join("");
  return `<li>${button}${children ? `<ul>${children}</ul>` : ""}</li>`;
}

function renderGraph(report) {
  const views = [
    ["artifacts", "Artifacts"],
    ["relationships", "Relationships"],
    ["observations", "Observations"],
    ["evidence", "Evidence"],
  ];
  const filters = views
    .map(([id, label]) => `<button type="button" class="action graph-filter${state.graphView === id ? " selected" : ""}" data-view="${id}">${label}</button>`)
    .join(" ");
  const panel = document.getElementById("panel-graph");
  panel.innerHTML = `
    <p class="muted">This tab presents the investigation graph already in the report. It does not invent runtime behavior or Windows trust.</p>
    <div class="filter">${filters}</div>
    <div class="graph-layout">
      <div>${_graphTable(report, state.graphView)}</div>
      <div id="graph-detail">${_graphDetail(report)}</div>
    </div>
  `;
  panel.querySelectorAll(".graph-filter").forEach((button) => {
    button.addEventListener("click", () => {
      state.graphView = button.dataset.view;
      renderGraph(report);
    });
  });
  panel.querySelectorAll("tr[data-kind][data-id]").forEach((row) => {
    row.addEventListener("click", () => selectGraph(row.dataset.kind, row.dataset.id, { switchTab: false }));
  });
  bindRefClicks(panel);
}

function _graphTable(report, view) {
  const rows = {
    artifacts: (report.artifacts || []).map((item) => [
      item.id,
      item.kind,
      (item.names || []).slice(0, 2).join(", ") || item.id,
      item.detected_type || "",
    ]),
    relationships: (report.relationships || []).map((item) => [
      item.id,
      item.type,
      artifactLabel(report, item.source_id),
      artifactLabel(report, item.target_id),
    ]),
    observations: (report.observations || []).map((item) => [
      item.id,
      item.kind,
      item.statement || "",
      artifactLabel(report, item.artifact_id),
    ]),
    evidence: (report.evidence || []).map((item) => [
      item.id,
      item.kind,
      item.summary || "",
      item.value || "",
    ]),
  };
  const headers = {
    artifacts: ["Id", "Kind", "Name", "Type"],
    relationships: ["Id", "Type", "Source", "Target"],
    observations: ["Id", "Kind", "Statement", "Artifact"],
    evidence: ["Id", "Kind", "Summary", "Value"],
  };
  const kind = view.replace(/s$/, "") === "evidence" ? "evidence" : view.replace(/s$/, "");
  const body = (rows[view] || [])
    .slice(0, 200)
    .map((cols) => {
      const selected = state.selectedKind && ["artifact", "relationship", "observation", "evidence"].includes(state.selectedKind) && state.selectedId === cols[0];
      return `<tr data-kind="${esc(kind)}" data-id="${esc(cols[0])}" class="${selected ? "selected" : ""}">${cols.map((col) => `<td>${esc(col)}</td>`).join("")}</tr>`;
    })
    .join("");
  return `
    <table class="graph-table">
      <thead><tr>${(headers[view] || []).map((col) => `<th>${esc(col)}</th>`).join("")}</tr></thead>
      <tbody>${body || `<tr><td colspan="4">None in this report.</td></tr>`}</tbody>
    </table>
    ${(rows[view] || []).length > 200 ? `<p class="muted">Showing first 200 of ${(rows[view] || []).length}.</p>` : ""}
  `;
}

function _graphDetail(report) {
  if (!state.selectedId) {
    return `<p class="muted">Select a row to inspect the object and its connected relationships.</p>`;
  }
  const index = graphIndex(report);
  const kind = state.selectedKind;
  if (kind === "artifact") {
    const item = index.artifacts[state.selectedId];
    if (!item) return "<p>Unknown artifact.</p>";
    const rels = (report.relationships || []).filter((rel) => rel.source_id === item.id || rel.target_id === item.id);
    return `
      <h3>${esc(item.names?.[0] || item.id)}</h3>
      <div class="kv">
        <span>Id</span><span>${esc(item.id)}</span>
        <span>Kind</span><span>${esc(item.kind)}</span>
        <span>Type</span><span>${esc(item.detected_type || "")}</span>
        <span>Complete</span><span>${esc(String(item.complete))}</span>
      </div>
      <div class="ref-group"><div class="meta">Relationships</div><ul>${
        rels.slice(0, 24).map((rel) => `<li><button type="button" class="ref-link" data-kind="relationship" data-id="${esc(rel.id)}">${esc(rel.type)} ${esc(artifactLabel(report, rel.source_id))} → ${esc(artifactLabel(report, rel.target_id))}</button></li>`).join("") || "<li>None.</li>"
      }</ul></div>
    `;
  }
  if (kind === "relationship") {
    const rel = index.relationships[state.selectedId];
    if (!rel) return "<p>Unknown relationship.</p>";
    const extra = rel.extra || {};
    return `
      <h3>${esc(rel.type)}</h3>
      <div class="kv">
        <span>Id</span><span>${esc(rel.id)}</span>
        <span>Certainty</span><span>${esc(rel.certainty)}</span>
        <span>Source</span><span><button type="button" class="ref-link" data-kind="artifact" data-id="${esc(rel.source_id)}">${esc(artifactLabel(report, rel.source_id))}</button></span>
        <span>Target</span><span><button type="button" class="ref-link" data-kind="artifact" data-id="${esc(rel.target_id)}">${esc(artifactLabel(report, rel.target_id))}</button></span>
        <span>trust_validated</span><span>${esc(String(extra.trust_validated ?? "n/a"))}</span>
        <span>crypto_valid</span><span>${esc(String(extra.crypto_valid ?? "n/a"))}</span>
      </div>
    `;
  }
  if (kind === "observation") {
    const item = index.observations[state.selectedId];
    if (!item) return "<p>Unknown observation.</p>";
    return `
      <h3>${esc(item.kind)}</h3>
      <p>${esc(item.statement || "")}</p>
      <div class="kv">
        <span>Certainty</span><span>${esc(item.certainty || "")}</span>
        <span>Artifact</span><span><button type="button" class="ref-link" data-kind="artifact" data-id="${esc(item.artifact_id || "")}">${esc(artifactLabel(report, item.artifact_id))}</button></span>
      </div>
      ${renderRefs(report, { evidence_ids: item.evidence_ids || [] }, "Backing evidence")}
    `;
  }
  if (kind === "evidence") {
    const item = index.evidence[state.selectedId];
    if (!item) return "<p>Unknown evidence.</p>";
    return `
      <h3>${esc(item.kind)}</h3>
      <p>${esc(item.summary || "")}</p>
      <div class="kv">
        <span>Value</span><span>${esc(item.value || "")}</span>
        <span>Location</span><span>${esc(item.location || "")}</span>
      </div>
    `;
  }
  return "";
}

function renderFindings(report) {
  const items = report.findings
    .map(
      (finding, index) => `
      <article class="finding ${esc(finding.severity)}" data-index="${index}">
        <div class="meta">${esc(finding.severity)} · ${esc(finding.confidence)} confidence · ${esc(finding.certainty || "derived")} · ${esc(finding.category)} · ${esc(finding.analyzer)}${finding.artifact_id ? ` · ${esc(artifactLabel(report, finding.artifact_id))}` : ""}</div>
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
  const index = graphIndex(report);
  const blocks = findings
    .map((finding) => {
      const rows = (finding.evidence || [])
        .map((item) => {
          const store = item.id && index.evidence[item.id];
          return `
          <tr ${item.id ? `data-kind="evidence" data-id="${esc(item.id)}"` : ""}>
            <td>${esc(item.kind)}</td>
            <td>${esc(item.location || "")}</td>
            <td>${esc(item.summary)}</td>
            <td>${esc(item.value || (store && store.value) || "")}</td>
          </tr>`;
        })
        .join("");
      return `
        <div class="evidence-block">
          <div class="meta">${esc(finding.rule_id || finding.legacy_id || finding.id)} · ${esc(finding.certainty || "derived")}${finding.artifact_id ? ` · ${esc(artifactLabel(report, finding.artifact_id))}` : ""}</div>
          <h3>${esc(finding.title)}</h3>
          <p class="muted">${esc(finding.summary)}</p>
          <table>
            <thead><tr><th>Kind</th><th>Location</th><th>Summary</th><th>Value</th></tr></thead>
            <tbody>${rows || "<tr><td colspan='4'>No structured evidence attached.</td></tr>"}</tbody>
          </table>
          ${renderRefs(report, { observation_ids: finding.observation_ids || [], evidence_ids: finding.evidence_ids || [], artifact_ids: finding.artifact_id ? [finding.artifact_id] : [] }, "Finding provenance")}
        </div>`;
    })
    .join("");
  const panel = document.getElementById("panel-evidence");
  panel.innerHTML = `
    <p class="muted">${selected ? "Showing evidence for the selected finding." : "Showing evidence for non-info findings. Select one from Findings to focus."}</p>
    ${blocks || "<p>No evidence to show.</p>"}
  `;
  bindRefClicks(panel);
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
  const runs = (report.analyzer_runs || [])
    .map((run) => `<li>${esc(run.analyzer_id)} · ${esc(run.status)} · ${esc(artifactLabel(report, run.artifact_id))}</li>`)
    .join("");
  document.getElementById("panel-details").innerHTML = `
    ${analyzers || "<p>No analyzer output.</p>"}
    <h2 class="compose" style="font-size:15px;margin-top:18px;color:var(--muted);text-transform:uppercase;">Analyzer runs</h2>
    <ul class="next">${runs || "<li>None.</li>"}</ul>
  `;
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
