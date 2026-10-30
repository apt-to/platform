const rows = document.querySelector("#package-rows");
const search = document.querySelector("#package-search");
const empty = document.querySelector("#empty-state");
const error = document.querySelector("#error-state");
const count = document.querySelector("#result-count");
let packages = [];
let activeFilter = "all";

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (character) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[character]));

function packageRow(item) {
  const cves = item.cves.map((cve) => `<a href="/vulnerabilities/${encodeURIComponent(cve.toLowerCase())}">${escapeHtml(cve)}</a>`).join("<span class=\"cve-separator\"> / </span>");
  const patchLinks = (item.patches || []).map((patch) => `<a href="/patches/${encodeURIComponent(patch.slug)}">${patch.kind === "security" ? "Patch details" : "Build patch"} ↗</a>`).join("");
  const policy = item.access === "sponsor"
    ? `<span class="policy-dot policy-sponsor"></span><span class="policy-main">Sponsor first</span><span class="policy-detail">Any active individual GitHub Sponsors tier, no minimum · public ${escapeHtml(item.delayHours)} hours later</span><small>Private and commercial use; no redistribution of official early binaries</small>`
    : `<span class="policy-dot policy-public"></span><span class="policy-main">Public immediately</span><span class="policy-detail">After release checks pass</span>`;
  const checks = item.verification
    ? `<a class="verification-link" href="${escapeHtml(item.verification)}"><span class="verified-check" aria-hidden="true">✓</span>Hosted verification passed<small>Build, CVE scans, regressions and signed APT client ↗</small></a>`
    : `<span class="verification-pending">Verification pending<small>Hosted build, CVE scans, installed regressions and signed-client checks required</small></span>`;
  return `<tr data-source="${escapeHtml(item.source)}">
    <th scope="row" class="package-name"><span>${escapeHtml(item.source)}</span><small>${escapeHtml(item.targetName)} source package</small></th>
    <td class="version-cell" data-label="PACKAGE VERSION"><code>${escapeHtml(item.version)}</code><span class="unpublished-mark">NOT PUBLISHED</span></td>
    <td class="cve-cell" data-label="PATCH FOCUS">${cves}<small>Patch and regression details</small></td>
    <td class="policy-cell" data-label="BINARY ACCESS">${policy}</td>
    <td data-label="DEVELOPMENT CHECKS">${checks}</td>
    <td class="row-action" data-label="PACKAGE EVIDENCE"><nav class="evidence-links" aria-label="${escapeHtml(item.source)} package evidence">
      <a href="${escapeHtml(item.sourceUrl)}">Source ↗</a>
      ${patchLinks || `<a href="${escapeHtml(item.patchUrl)}">Patch ↗</a>`}
      <a href="${escapeHtml(item.testsUrl)}">Tests ↗</a>
      <a href="${escapeHtml(item.releasesUrl)}">Releases ↗</a>
      <span class="release-status">${escapeHtml(item.releaseStatus)}</span>
    </nav></td>
  </tr>`;
}

function render() {
  const query = search.value.trim().toLowerCase();
  const filtered = packages.filter((item) => {
    const matchesPolicy = activeFilter === "all" || item.access === activeFilter;
    const searchable = [item.source, item.version, ...item.cves].join(" ").toLowerCase();
    return matchesPolicy && searchable.includes(query);
  });
  rows.innerHTML = filtered.map(packageRow).join("");
  const filterCounts = {
    all: packages.length,
    sponsor: packages.filter((item) => item.access === "sponsor").length,
    public: packages.filter((item) => item.access === "public").length,
  };
  document.querySelectorAll(".filter-button").forEach((button) => {
    const value = filterCounts[button.dataset.filter];
    if (value !== undefined) button.querySelector("span").textContent = String(value).padStart(2, "0");
  });
  rows.closest("table").hidden = filtered.length === 0;
  empty.hidden = filtered.length !== 0;
  count.textContent = `${String(filtered.length).padStart(2, "0")} ${filtered.length === 1 ? "candidate" : "candidates"}`;
}

document.querySelectorAll(".filter-button").forEach((button) => {
  button.addEventListener("click", () => {
    activeFilter = button.dataset.filter;
    document.querySelectorAll(".filter-button").forEach((item) => {
      const selected = item === button;
      item.classList.toggle("is-selected", selected);
      item.setAttribute("aria-pressed", String(selected));
    });
    render();
  });
});

search.addEventListener("input", render);
document.querySelector("#clear-search").addEventListener("click", () => {
  search.value = "";
  search.focus();
  render();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "/" && !["INPUT", "TEXTAREA"].includes(document.activeElement.tagName)) {
    event.preventDefault();
    search.focus();
  }
  if (event.key === "Escape" && document.activeElement === search) {
    search.value = "";
    render();
    search.blur();
  }
});

fetch("/catalogue.json", { headers: { Accept: "application/json" } })
  .then((response) => {
    if (!response.ok) throw new Error("Catalogue request failed");
    return response.json();
  })
  .then((catalogue) => {
    if (catalogue.schemaVersion !== 3 || !catalogue.targets || !Array.isArray(catalogue.packages)) throw new Error("Unsupported catalogue schema");
    packages = catalogue.packages.flatMap((item) => Object.entries(item.targets || {}).map(([targetId, targetPolicy]) => {
      const target = catalogue.targets[targetId];
      if (!target) throw new Error("Package target is missing from catalogue target matrix");
      return { ...item, ...targetPolicy, targetId, targetName: target.displayName };
    }));
    render();
  })
  .catch(() => {
    rows.closest("table").hidden = true;
    count.textContent = "Unavailable";
    error.hidden = false;
  });
