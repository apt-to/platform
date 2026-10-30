import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import gateway from "../src/index.js";

const TARGET = "ubuntu-focal-amd64";
const verificationUrl = "https://github.com/getpatched/platform/actions/runs/41100013097";

function fixtureCatalogue() {
  const securityPatch = (id, slug, cve, title) => ({
    id, slug, kind: "security", title, description: `Backport for ${cve}.`,
    sha256: "a".repeat(64), fileUrl: `https://github.com/getpatched/packaging-demo/blob/main/${slug}.patch`,
    cves: [cve], upstream: null,
    tests: [{ id: "regression", baselineExpectation: "Fails before the fix.", patchedExpectation: "Passes with the fix." }],
  });
  return {
    schemaVersion: 3,
    targets: {
      [TARGET]: {
        distribution: "Ubuntu", releaseVersion: "20.04", codename: "focal", architecture: "amd64",
        displayName: "Ubuntu 20.04 LTS (focal) · amd64",
      },
    },
    packages: [{
      source: "demo",
      targets: {
        [TARGET]: {
          baseVersion: "1.0-1", version: "1.0-1+getpatched1",
          status: "development-verified-production-release-pending", verification: verificationUrl,
          releaseStatus: "No production release", access: "public", delayHours: 0,
          vulnerabilities: [
            { id: "CVE-2025-10001", slug: "cve-2025-10001", summary: "Verified vulnerability.", advisoryUrl: "https://ubuntu.com/security/CVE-2025-10001", patchSlugs: ["verified-fix"], patched: true },
            { id: "CVE-2025-10002", slug: "cve-2025-10002", summary: "Unverified vulnerability.", advisoryUrl: "https://ubuntu.com/security/CVE-2025-10002", patchSlugs: ["unverified-fix"], patched: true },
          ],
          patches: [
            securityPatch("verified-fix", "verified-fix", "CVE-2025-10001", "Verified security fix"),
            securityPatch("unverified-fix", "unverified-fix", "CVE-2025-10002", "Unverified security fix"),
            { id: "build-adjustment", slug: "build-adjustment", kind: "build-compatibility", title: "Build adjustment", description: "Build-only change.", sha256: "b".repeat(64), fileUrl: null, cves: [], upstream: null, tests: [] },
          ],
        },
      },
    }],
  };
}

function assets(catalogue = fixtureCatalogue()) {
  return {
    fetch: async (request) => {
      if (new URL(request.url).pathname === "/catalogue.json") return Response.json(catalogue);
      return new Response("Not found", { status: 404, headers: { "content-type": "text/html; charset=utf-8" } });
    },
  };
}

test("every vulnerability and patch in the published catalogue has its own page, JSON record, and badge", async () => {
  const catalogue = JSON.parse(await readFile(new URL("../../site/catalogue.json", import.meta.url), "utf8"));
  const env = { ASSETS: assets(catalogue), PUBLIC_ORIGIN: "https://getpatched.dev" };
  const vulnerabilities = new Set();
  const patches = new Set();

  for (const item of catalogue.packages) {
    for (const target of Object.values(item.targets || {})) {
      for (const vulnerability of target.vulnerabilities || []) vulnerabilities.add(vulnerability.slug);
      for (const patch of target.patches || []) patches.add(patch.slug);
    }
  }

  assert.ok(vulnerabilities.size > 0, "catalogue must contain vulnerabilities");
  assert.ok(patches.size > 0, "catalogue must contain patches");
  for (const [kind, slugs] of [["vulnerabilities", vulnerabilities], ["patches", patches]]) {
    for (const slug of slugs) {
      const page = await gateway.fetch(new Request(`https://getpatched.dev/${kind}/${slug}`), env);
      assert.equal(page.status, 200, `${kind}/${slug} HTML`);
      assert.match(page.headers.get("content-type"), /text\/html/);

      const metadata = await gateway.fetch(new Request(`https://getpatched.dev/${kind}/${slug}.json`), env);
      assert.equal(metadata.status, 200, `${kind}/${slug}.json`);
      assert.match(metadata.headers.get("content-type"), /application\/json/);
      const record = await metadata.json();
      assert.equal(record.slug, slug);
      if (record.patched) assert.ok(record.targets.every((target) => target.patched), `${kind}/${slug} target statuses agree with its patched status`);

      const badge = await gateway.fetch(new Request(`https://getpatched.dev/${kind}/${slug}/badge.svg`), env);
      assert.equal(badge.status, 200, `${kind}/${slug}/badge.svg`);
      assert.match(badge.headers.get("content-type"), /image\/svg\+xml/);
      const svg = await badge.text();
      if (svg.includes('aria-label="Patched"')) assert.match(svg, /\bwidth="\d+"/);
      else assert.equal(svg, '<svg xmlns="http://www.w3.org/2000/svg"></svg>');
    }
  }
});

test("vulnerability and patch pages expose linked HTML and machine-readable records", async () => {
  const env = { ASSETS: assets(), PUBLIC_ORIGIN: "https://getpatched.dev" };
  const vulnerabilityPage = await gateway.fetch(new Request("https://getpatched.dev/vulnerabilities/cve-2025-10001"), env);
  assert.equal(vulnerabilityPage.status, 200);
  assert.match(vulnerabilityPage.headers.get("content-type"), /text\/html/);
  assert.match(await vulnerabilityPage.text(), /Verified vulnerability\./);
  assert.match(await (await gateway.fetch(new Request("https://getpatched.dev/patches/verified-fix"), env)).text(), /Verified security fix/);

  const vulnerability = await gateway.fetch(new Request("https://getpatched.dev/vulnerabilities/cve-2025-10001.json"), env);
  assert.equal(vulnerability.status, 200);
  assert.match(vulnerability.headers.get("content-type"), /application\/json/);
  assert.equal(vulnerability.headers.get("access-control-allow-origin"), "*");
  assert.equal((await vulnerability.json()).patched, true);
  const patch = await gateway.fetch(new Request("https://getpatched.dev/patches/verified-fix.json"), env);
  const patchRecord = await patch.json();
  assert.equal(patch.status, 200);
  assert.equal(patchRecord.patched, true);
  assert.equal(patchRecord.vulnerabilities[0].url, "https://getpatched.dev/vulnerabilities/cve-2025-10001");
});

test("security badges require a verified target and security patch; empty badges have no dimensions", async () => {
  const env = { ASSETS: assets() };
  const verified = await gateway.fetch(new Request("https://getpatched.dev/patches/verified-fix/badge.svg"), env);
  assert.equal(verified.status, 200);
  assert.match(await verified.text(), /aria-label="Patched"/);
  const verifiedVulnerability = await gateway.fetch(new Request("https://getpatched.dev/vulnerabilities/cve-2025-10001/badge.svg"), env);
  assert.match(await verifiedVulnerability.text(), /aria-label="Patched"/);

  for (const path of [
    "/patches/build-adjustment/badge.svg",
    "/patches/missing/badge.svg",
  ]) {
    const response = await gateway.fetch(new Request(`https://getpatched.dev${path}`), env);
    assert.equal(response.status, 200);
    const svg = await response.text();
    assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg"><\/svg>$/);
    assert.doesNotMatch(svg, /\b(?:width|height)=/);
  }

  const unverifiedCatalogue = fixtureCatalogue();
  const target = unverifiedCatalogue.packages[0].targets[TARGET];
  target.status = "verification-pending";
  target.verification = "https://example.com/not-a-run";
  const unverifiedEnv = { ASSETS: assets(unverifiedCatalogue) };
  const unverifiedBadge = await gateway.fetch(new Request("https://getpatched.dev/patches/verified-fix/badge.svg"), unverifiedEnv);
  assert.doesNotMatch(await unverifiedBadge.text(), /aria-label="Patched"/);
  const unverifiedVulnerability = await gateway.fetch(new Request("https://getpatched.dev/vulnerabilities/cve-2025-10001.json"), unverifiedEnv);
  assert.equal((await unverifiedVulnerability.json()).patched, false);
});

test("unknown and malformed .json routes return a small JSON 404, including asset fallthrough", async () => {
  const env = { ASSETS: assets() };
  for (const path of ["/patches/missing.json", "/vulnerabilities/not-a-record.json", "/other/missing.json"]) {
    const response = await gateway.fetch(new Request(`https://getpatched.dev${path}`), env);
    assert.equal(response.status, 404, path);
    assert.match(response.headers.get("content-type"), /application\/json/);
    assert.deepEqual(await response.json(), { error: "not_found" });
  }

  const head = await gateway.fetch(new Request("https://getpatched.dev/patches/missing.json", { method: "HEAD" }), env);
  assert.equal(head.status, 404);
  assert.equal(await head.text(), "");
});
