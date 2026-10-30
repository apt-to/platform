const PUBLIC_CACHE = "public, max-age=60";
const EMPTY_BADGE = '<svg xmlns="http://www.w3.org/2000/svg"></svg>';
const PATCHED_BADGE = '<svg xmlns="http://www.w3.org/2000/svg" width="66" height="20" viewBox="0 0 66 20" role="img" aria-label="Patched"><title>Patched</title><rect width="66" height="20" rx="3" fill="#216b4c"/><text x="33" y="14" fill="#fff" font-family="ui-monospace, SFMono-Regular, Consolas, monospace" font-size="11" font-weight="700" text-anchor="middle">patched</text></svg>';
const SAFE_SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const VERIFIED_TARGET_STATUS = "development-verified-production-release-pending";
const VERIFIED_RUN_URL = /^https:\/\/github\.com\/getpatched\/platform\/actions\/runs\/[1-9][0-9]*$/;

function hasVerifiedRun(target) {
  return target?.status === VERIFIED_TARGET_STATUS
    && typeof target.verification === "string"
    && VERIFIED_RUN_URL.test(target.verification);
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
}

function htmlResponse(body, status, method, cache = PUBLIC_CACHE) {
  return new Response(method === "HEAD" ? null : body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": cache,
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin-when-cross-origin",
    },
  });
}

function jsonResponse(body, status, method, cache = PUBLIC_CACHE) {
  return new Response(method === "HEAD" ? null : JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": cache,
      "x-content-type-options": "nosniff",
      "access-control-allow-origin": "*",
    },
  });
}

function svgResponse(patched, method, status = 200) {
  return new Response(method === "HEAD" ? null : (patched ? PATCHED_BADGE : EMPTY_BADGE), {
    status,
    headers: {
      "content-type": "image/svg+xml; charset=utf-8",
      "cache-control": patched ? PUBLIC_CACHE : "public, max-age=60",
      "x-content-type-options": "nosniff",
    },
  });
}

function targetDetails(targetId, target, display, source) {
  return {
    id: targetId,
    source: source || null,
    distribution: display?.distribution || null,
    releaseVersion: display?.releaseVersion || null,
    codename: display?.codename || null,
    architecture: display?.architecture || null,
    displayName: display?.displayName || targetId,
    sourceVersion: target.sourceVersion || target.baseVersion || null,
    packageVersion: target.version || null,
    releaseStatus: target.releaseStatus || null,
    status: target.status || null,
    verification: target.verification || null,
    access: target.access || null,
    delayHours: Number.isSafeInteger(target.delayHours) ? target.delayHours : null,
  };
}

function collectRecords(catalogue) {
  const vulnerabilities = new Map();
  const patches = new Map();
  for (const item of catalogue.packages || []) {
    for (const [targetId, target] of Object.entries(item.targets || {})) {
      const display = catalogue.targets?.[targetId];
      const targetInfo = targetDetails(targetId, target, display, item.source);
      for (const patch of target.patches || []) {
        if (!patch || typeof patch.slug !== "string" || !SAFE_SLUG.test(patch.slug)) continue;
        const key = `${item.source}/${patch.slug}`;
        const existing = patches.get(key) || {
          id: patch.id,
          slug: patch.slug,
          kind: patch.kind,
          title: patch.title,
          description: patch.description,
          sha256: patch.sha256,
          fileUrl: patch.fileUrl,
          cves: Array.isArray(patch.cves) ? patch.cves : [],
          upstream: patch.upstream || null,
          tests: Array.isArray(patch.tests) ? patch.tests : [],
          source: item.source,
          targets: [],
        };
        existing.targets.push({ ...targetInfo });
        patches.set(key, existing);
      }
      for (const vulnerability of target.vulnerabilities || []) {
        if (!vulnerability || typeof vulnerability.slug !== "string" || !SAFE_SLUG.test(vulnerability.slug)) continue;
        const existing = vulnerabilities.get(vulnerability.slug) || {
          id: vulnerability.id,
          slug: vulnerability.slug,
          summary: vulnerability.summary,
          ubuntuPriority: vulnerability.ubuntuPriority || null,
          cvssV3: Number.isFinite(vulnerability.cvssV3) ? vulnerability.cvssV3 : null,
          advisoryUrl: vulnerability.advisoryUrl || null,
          targets: [],
          patchRefs: new Set(),
        };
        const patchKeys = (vulnerability.patchSlugs || [])
          .filter((patchSlug) => typeof patchSlug === "string" && SAFE_SLUG.test(patchSlug))
          .map((patchSlug) => `${item.source}/${patchSlug}`);
        existing.targets.push({ ...targetInfo, patched: vulnerability.patched === true && hasVerifiedRun(target), patchKeys });
        for (const patchSlug of vulnerability.patchSlugs || []) {
          if (typeof patchSlug === "string" && SAFE_SLUG.test(patchSlug)) existing.patchRefs.add(`${item.source}/${patchSlug}`);
        }
        vulnerabilities.set(vulnerability.slug, existing);
      }
    }
  }

  const patchesBySlug = new Map();
  for (const patch of patches.values()) {
    // Public patch URLs are global, so reject ambiguous catalogue data rather
    // than serving whichever package happens to be encountered first.
    if (patchesBySlug.has(patch.slug)) patchesBySlug.set(patch.slug, null);
    else patchesBySlug.set(patch.slug, patch);
  }

  for (const vulnerability of vulnerabilities.values()) {
    vulnerability.patches = [...vulnerability.patchRefs]
      .map((key) => patches.get(key))
      .filter((patch) => patch && patchesBySlug.get(patch.slug) === patch)
      .map((patch) => ({ id: patch.id, slug: patch.slug, kind: patch.kind, title: patch.title, url: `/patches/${patch.slug}` }));
    for (const target of vulnerability.targets) {
      target.patchedPatchKeys = target.patchKeys.filter((key) => {
        const patch = patches.get(key);
        return target.patched && patch?.kind === "security"
          && patchesBySlug.get(patch.slug) === patch
          && patch.targets.some((patchTarget) => patchTarget.id === target.id);
      });
      target.patched = target.patchedPatchKeys.length > 0;
      delete target.patchKeys;
    }
    vulnerability.patched = vulnerability.targets.length > 0 && vulnerability.targets.every((target) => target.patched === true);
    delete vulnerability.patchRefs;
  }
  for (const patch of patches.values()) {
    const patchKey = `${patch.source}/${patch.slug}`;
    for (const target of patch.targets) {
      target.patched = patchesBySlug.get(patch.slug) === patch
        && patch.kind === "security" && patch.cves.length > 0 && patch.cves.every((cve) => {
        const vulnerability = vulnerabilities.get(String(cve).toLowerCase());
        return vulnerability?.targets.some((vulnerabilityTarget) =>
          vulnerabilityTarget.source === patch.source
          && vulnerabilityTarget.id === target.id
          && vulnerabilityTarget.patchedPatchKeys.includes(patchKey));
      });
    }
    patch.patched = patch.targets.length > 0 && patch.targets.every((target) => target.patched === true);
    patch.vulnerabilities = patch.cves.map((cve) => {
      const slug = String(cve).toLowerCase();
      const vulnerability = vulnerabilities.get(slug);
      return vulnerability ? { id: vulnerability.id, slug, url: `/vulnerabilities/${slug}` } : null;
    }).filter(Boolean);
  }
  for (const vulnerability of vulnerabilities.values()) {
    for (const target of vulnerability.targets) delete target.patchedPatchKeys;
  }
  return { vulnerabilities, patches: patchesBySlug };
}

function externalLink(url, label) {
  if (typeof url !== "string") return "";
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") return "";
  } catch { return ""; }
  return `<a href="${escapeHtml(url)}" rel="noopener noreferrer">${escapeHtml(label)} <span aria-hidden="true">↗</span></a>`;
}

function recordShell({ title, description, canonical, body }) {
  const safeTitle = escapeHtml(title);
  const safeDescription = escapeHtml(description);
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#fffefa">
    <meta name="description" content="${safeDescription}">
    <link rel="canonical" href="${escapeHtml(canonical)}">
    <title>${safeTitle} — GetPatched</title>
    <script src="/theme-init.js"></script>
    <link rel="stylesheet" href="/styles.css">
    <link rel="stylesheet" href="/records.css">
    <script type="module" src="/theme.js"></script>
  </head>
  <body>
    <a class="skip-link" href="#record">Skip to record</a>
    <header class="site-header">
      <a class="wordmark" href="/" aria-label="GetPatched home"><img class="brand-mark" src="/brand-mark.svg" alt=""><span class="wordmark-copy"><span class="wordmark-get">get</span><span class="wordmark-patched">patched</span></span></a>
      <nav aria-label="Main navigation"><a href="/#catalogue">Packages</a><a href="/#process">Our method</a><a href="/#evidence">Evidence</a></nav>
      <a class="account-link" href="/account">Sponsor access</a>
      <button class="theme-toggle" type="button" data-theme-toggle aria-label="Switch to dark mode" title="Switch to dark mode"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20.2 15.4A8.8 8.8 0 0 1 8.6 3.8 8.8 8.8 0 1 0 20.2 15.4Z"/></svg><span>Dark mode</span></button>
      <a class="github-link" href="https://github.com/getpatched" aria-label="GetPatched on GitHub">GitHub <span aria-hidden="true">↗</span></a>
    </header>
    <main class="record-main" id="record">${body}</main>
    <footer class="record-footer"><a href="/">GetPatched</a><span>Upstream packages remain under their original licenses. GetPatched patch metadata describes our maintenance work.</span></footer>
  </body>
</html>`;
}

function targetList(targets) {
  if (!targets.length) return '<p class="record-muted">No supported package target is listed.</p>';
  return `<ul class="record-targets">${targets.map((target) => `<li>
    <div><strong>${escapeHtml(target.source || "Package")} · ${escapeHtml(target.displayName)}</strong><span>Baseline ${escapeHtml(target.sourceVersion || "version unavailable")}</span><span>${target.patched ? "Fix verified for this target" : "No verified fix for this target"}</span></div>
    <div><code>${escapeHtml(target.packageVersion || "No GetPatched package version")}</code><span>${escapeHtml(target.releaseStatus || target.status || "Release status not listed")}</span></div>
    ${target.verification ? `<div>${externalLink(target.verification, "Hosted verification evidence")}</div>` : ""}
  </li>`).join("")}</ul>`;
}

function vulnerabilityJson(record, origin) {
  return {
    schemaVersion: 1,
    type: "vulnerability",
    id: record.id,
    slug: record.slug,
    summary: record.summary,
    ubuntuPriority: record.ubuntuPriority,
    cvssV3: record.cvssV3,
    advisoryUrl: record.advisoryUrl,
    patched: record.patched,
    status: record.patched ? "patch-available" : record.targets.some((target) => target.patched) ? "partial-coverage" : record.patches.length ? "patch-unverified" : "no-patch",
    url: `${origin}/vulnerabilities/${record.slug}`,
    badgeUrl: `${origin}/vulnerabilities/${record.slug}/badge.svg`,
    patches: record.patches.map((patch) => ({ ...patch, url: `${origin}${patch.url}` })),
    targets: record.targets,
  };
}

function patchJson(record, origin) {
  return {
    schemaVersion: 1,
    type: "patch",
    id: record.id,
    slug: record.slug,
    kind: record.kind,
    title: record.title,
    description: record.description,
    source: record.source,
    sha256: record.sha256,
    fileUrl: record.fileUrl,
    upstream: record.upstream,
    tests: record.tests,
    patched: record.patched,
    url: `${origin}/patches/${record.slug}`,
    badgeUrl: `${origin}/patches/${record.slug}/badge.svg`,
    vulnerabilities: record.vulnerabilities.map((vulnerability) => ({
      ...vulnerability,
      url: `${origin}${vulnerability.url}`,
    })),
    targets: record.targets,
  };
}

function vulnerabilityPage(record, origin) {
  const hasPatchedTarget = record.targets.some((target) => target.patched === true);
  const badge = record.patched
    ? `<img class="record-badge" src="/vulnerabilities/${escapeHtml(record.slug)}/badge.svg" alt="Patched">`
    : `<span class="record-status ${hasPatchedTarget ? "record-status-partial" : "record-status-empty"}">${hasPatchedTarget ? "Partial target coverage" : "No verified patch"}</span>`;
  const patches = record.patches.length
    ? `<ul class="record-links">${record.patches.map((patch) => `<li><a href="${escapeHtml(patch.url)}">${escapeHtml(patch.title)} <span aria-hidden="true">→</span></a><span>${escapeHtml(patch.kind)}</span></li>`).join("")}</ul>`
    : '<p class="record-muted">No GetPatched patch is listed for this vulnerability.</p>';
  const body = `<p class="record-eyebrow">VULNERABILITY · ${escapeHtml(record.ubuntuPriority ? `UBUNTU PRIORITY ${record.ubuntuPriority.toUpperCase()}` : "SECURITY TRACKER")}</p>
    <h1>${escapeHtml(record.id)}</h1>
    <p class="record-summary">${escapeHtml(record.summary)}</p>
    <div class="record-status-row">${badge}<span>${record.patched ? "A GetPatched fix is verified for every listed target." : hasPatchedTarget ? "A fix is verified for some listed targets; remaining targets are still unverified." : "No verified GetPatched fix is listed."}</span></div>
    <section class="record-section" aria-labelledby="affected-title"><h2 id="affected-title">Affected package targets</h2>${targetList(record.targets)}</section>
    <section class="record-section" aria-labelledby="patch-title"><h2 id="patch-title">GetPatched patches</h2>${patches}</section>
    <section class="record-section record-reference" aria-labelledby="reference-title"><h2 id="reference-title">References</h2><p>${externalLink(record.advisoryUrl, "Official security advisory")}</p><p><a href="${escapeHtml(`/vulnerabilities/${record.slug}.json`)}">Machine-readable vulnerability record <code>.json</code></a></p></section>`;
  return recordShell({
    title: record.id,
    description: record.summary,
    canonical: `${origin}/vulnerabilities/${record.slug}`,
    body,
  });
}

function patchPage(record, origin) {
  const hasPatchedTarget = record.targets.some((target) => target.patched === true);
  const cves = record.vulnerabilities.length
    ? `<ul class="record-links">${record.vulnerabilities.map((vulnerability) => `<li><a href="${escapeHtml(vulnerability.url)}">${escapeHtml(vulnerability.id)} <span aria-hidden="true">→</span></a><span>Vulnerability record</span></li>`).join("")}</ul>`
    : '<p class="record-muted">This patch is a build compatibility adjustment and does not claim to fix a CVE.</p>';
  const tests = record.tests.length
    ? `<div class="record-test-list">${record.tests.map((test) => `<article><h3>${escapeHtml(test.id)}</h3><dl><dt>Baseline expectation</dt><dd>${escapeHtml(test.baselineExpectation || "Not specified")}</dd><dt>Patched expectation</dt><dd>${escapeHtml(test.patchedExpectation || "Not specified")}</dd></dl></article>`).join("")}</div>`
    : '<p class="record-muted">No regression test is listed.</p>';
  const targets = record.targets.map((target) => `<li><strong>${escapeHtml(target.source || "Package")} · ${escapeHtml(target.displayName)}</strong><span>Source ${escapeHtml(target.sourceVersion || "not listed")} → GetPatched ${escapeHtml(target.packageVersion || "not released")}</span><small>${target.patched ? "Security patch verified for this target" : record.kind === "security" ? "Security patch not verified for this target" : "Security badge not applicable"} · ${escapeHtml(target.releaseStatus || target.status || "Release status not listed")}</small>${target.verification ? externalLink(target.verification, "Hosted verification evidence") : ""}</li>`).join("");
  const upstreamLabel = record.upstream
    ? `${record.upstream.repository || "Upstream"}${record.upstream.commit ? ` · ${record.upstream.commit.slice(0, 12)}` : ""}`
    : "Not applicable";
  const body = `<p class="record-eyebrow">${escapeHtml(record.kind === "security" ? "SECURITY PATCH" : "BUILD COMPATIBILITY PATCH")}</p>
    <h1>${escapeHtml(record.title)}</h1>
    <p class="record-summary">${escapeHtml(record.description)}</p>
    <div class="record-status-row">${record.patched ? `<img class="record-badge" src="/patches/${escapeHtml(record.slug)}/badge.svg" alt="Patched">` : `<span class="record-status ${hasPatchedTarget ? "record-status-partial" : "record-status-empty"}">${hasPatchedTarget ? "Partial target coverage" : record.kind === "security" ? "Not a verified security fix" : "No security badge"}</span>`}<span>${record.patched ? "This security patch is verified for every listed target." : hasPatchedTarget ? "This patch is verified for some listed targets; the badge stays empty until all listed targets pass." : record.kind === "security" ? "This patch is not verified for any listed target." : "Build compatibility patches do not receive security badges."}</span></div>
    <section class="record-section" aria-labelledby="patch-facts-title"><h2 id="patch-facts-title">Patch details</h2><dl class="record-facts"><div><dt>Patch ID</dt><dd><code>${escapeHtml(record.id)}</code></dd></div><div><dt>Package</dt><dd>${escapeHtml(record.source)}</dd></div><div><dt>Kind</dt><dd>${escapeHtml(record.kind)}</dd></div><div><dt>SHA-256</dt><dd><code>${escapeHtml(record.sha256 || "Not listed")}</code></dd></div><div><dt>Upstream</dt><dd>${record.upstream ? externalLink(record.upstream.url, upstreamLabel) : "Not applicable"}</dd></div><div><dt>Patch source</dt><dd>${externalLink(record.fileUrl, "View patch file")}</dd></div></dl></section>
    <section class="record-section" aria-labelledby="patch-targets-title"><h2 id="patch-targets-title">Target applicability</h2>${targets ? `<ul class="record-targets">${targets}</ul>` : '<p class="record-muted">No target is listed.</p>'}</section>
    <section class="record-section" aria-labelledby="patch-cves-title"><h2 id="patch-cves-title">Vulnerabilities addressed</h2>${cves}</section>
    <section class="record-section" aria-labelledby="patch-tests-title"><h2 id="patch-tests-title">Regression evidence</h2>${tests}</section>
    <p class="record-json-link"><a href="${escapeHtml(`/patches/${record.slug}.json`)}">Machine-readable patch record <code>.json</code></a></p>`;
  return recordShell({
    title: record.title,
    description: record.description,
    canonical: `${origin}/patches/${record.slug}`,
    body,
  });
}

async function readCatalogue(request, env) {
  if (!env.ASSETS?.fetch) return null;
  try {
    const assetUrl = new URL("/catalogue.json", request.url);
    const response = await env.ASSETS.fetch(new Request(assetUrl, { headers: { accept: "application/json" } }));
    if (!response.ok) return null;
    const catalogue = await response.json();
    if (catalogue?.schemaVersion !== 3 || !Array.isArray(catalogue.packages) || !catalogue.targets) return null;
    return catalogue;
  } catch { return null; }
}

function notFoundPage(method) {
  const body = recordShell({
    title: "Record not found",
    description: "No GetPatched vulnerability or patch record was found for this address.",
    canonical: "https://getpatched.dev/",
    body: '<p class="record-eyebrow">GETPATCHED RECORDS</p><h1>Record not found</h1><p class="record-summary">There is no vulnerability or patch record at this address.</p><p><a href="/#catalogue">Return to the package catalogue</a></p>',
  });
  return htmlResponse(body, 404, method, "no-store");
}

export async function handleSecurityPage(request, env) {
  const url = new URL(request.url);
  const pathname = url.pathname;
  const isVulnerabilityPath = pathname.startsWith("/vulnerabilities/");
  const isPatchPath = pathname.startsWith("/patches/");
  if (!isVulnerabilityPath && !isPatchPath) return null;

  const method = request.method.toUpperCase();
  if (method !== "GET" && method !== "HEAD") {
    return new Response(null, { status: 405, headers: { allow: "GET, HEAD", "cache-control": "no-store" } });
  }

  const isBadge = pathname.endsWith("/badge.svg");
  const isJson = pathname.endsWith(".json");
  const match = pathname.match(/^\/(vulnerabilities|patches)\/([a-z0-9]+(?:-[a-z0-9]+)*)(?:\.json|\/badge\.svg)?$/);
  if (!match) {
    if (isBadge) return svgResponse(false, method);
    if (isJson) return jsonResponse({ error: "not_found" }, 404, method, "no-store");
    return notFoundPage(method);
  }

  const [, kind, slug] = match;
  const format = isBadge ? "badge" : isJson ? "json" : "html";
  const catalogue = await readCatalogue(request, env);
  if (!catalogue) {
    if (format === "badge") return svgResponse(false, method, 503);
    const body = { error: "catalogue_unavailable" };
    return format === "json"
      ? jsonResponse(body, 503, method, "no-store")
      : htmlResponse(recordShell({
        title: "Records unavailable",
        description: "GetPatched records are temporarily unavailable.",
        canonical: `${env.PUBLIC_ORIGIN || "https://getpatched.dev"}${pathname}`,
        body: '<p class="record-eyebrow">GETPATCHED RECORDS</p><h1>Records unavailable</h1><p class="record-summary">Please try again shortly.</p>',
      }), 503, method, "no-store");
  }

  const records = collectRecords(catalogue);
  const origin = (env.PUBLIC_ORIGIN || "https://getpatched.dev").replace(/\/$/, "");
  if (kind === "vulnerabilities") {
    const record = records.vulnerabilities.get(slug);
    if (format === "badge") return svgResponse(record?.patched === true, method);
    if (!record) return format === "json"
      ? jsonResponse({ error: "not_found" }, 404, method, "no-store")
      : notFoundPage(method);
    return format === "json"
      ? jsonResponse(vulnerabilityJson(record, origin), 200, method)
      : htmlResponse(vulnerabilityPage(record, origin), 200, method);
  }

  const record = records.patches.get(slug);
  if (format === "badge") return svgResponse(record?.patched === true, method);
  if (!record) return format === "json"
    ? jsonResponse({ error: "not_found" }, 404, method, "no-store")
    : notFoundPage(method);
  return format === "json"
    ? jsonResponse(patchJson(record, origin), 200, method)
    : htmlResponse(patchPage(record, origin), 200, method);
}

export function notFoundJson(request) {
  const method = request.method.toUpperCase();
  return jsonResponse({ error: "not_found" }, 404, method, "no-store");
}
