import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import gateway, { canonicalAssets, parseUtc, publishOne, releaseAssets, requireImmutableReleasesEnabled, updateState, verifyPackageRun, verifySignedSourceTag } from "../src/index.js";

class MemoryBucket {
  constructor(entries = {}) {
    this.entries = new Map(Object.entries(entries).map(([key, value]) => [key, { value, etag: `seed-${key}` }]));
  }
  async get(key) {
    const entry = this.entries.get(key);
    if (!entry) return null;
    return { etag: entry.etag, json: async () => structuredClone(entry.value) };
  }
  async put(key, body, options) {
    const current = this.entries.get(key);
    if (options.onlyIf.etagMatches && current?.etag !== options.onlyIf.etagMatches) return null;
    if (options.onlyIf.etagDoesNotMatch === "*" && current) return null;
    const value = JSON.parse(body);
    const next = { value, etag: `etag-${Math.random()}` };
    this.entries.set(key, next);
    return next;
  }
}

class MemoryAssetBucket extends MemoryBucket {
  constructor(record) {
    super({ "release-state/pilot.json": record });
    this.assets = new Map();
  }
  async put(key, body, options) {
    if (key.startsWith("release-state/")) return super.put(key, body, options);
    if (options.onlyIf.etagDoesNotMatch === "*" && this.assets.has(key)) return null;
    const bytes = Buffer.from(await new Response(body).arrayBuffer());
    const digest = createHash("sha256").update(bytes).digest();
    if (!digest.equals(Buffer.from(options.sha256))) throw new Error("R2 checksum validation failed");
    const object = {
      size: bytes.length,
      checksums: { sha256: digest.buffer.slice(digest.byteOffset, digest.byteOffset + digest.byteLength) },
      customMetadata: structuredClone(options.customMetadata),
      bytes,
    };
    this.assets.set(key, object);
    return object;
  }
  async head(key) { return this.assets.get(key) || null; }
}

test("R2 state update uses conditional writes and retries a concurrent conflict", async () => {
  const bucket = new MemoryBucket({ "release-state/pilot.json": { state: "prepared", attempts: 0 } });
  const originalPut = bucket.put.bind(bucket);
  let conflictOnce = true;
  bucket.put = async (key, body, options) => {
    if (conflictOnce) {
      conflictOnce = false;
      bucket.entries.set(key, { value: { state: "prepared", attempts: 1 }, etag: "changed" });
      return null;
    }
    return originalPut(key, body, options);
  };
  const updated = await updateState(bucket, "release-state/pilot.json", (current) => ({ ...current, attempts: current.attempts + 1 }));
  assert.equal(updated.attempts, 2);
});

test("release records cannot be overwritten on creation", async () => {
  const bucket = new MemoryBucket({ "release-state/pilot.json": { state: "prepared" } });
  const result = await bucket.put("release-state/pilot.json", JSON.stringify({ state: "public" }), {
    onlyIf: { etagDoesNotMatch: "*" },
  });
  assert.equal(result, null);
});

test("asset manifest rejects traversal and duplicate basenames", () => {
  const valid = { name: "libxml2_1.2.3_amd64.deb", sha256: "a".repeat(64), r2_key: "staging/sha256/a" };
  assert.equal(canonicalAssets([valid]).length, 1);
  assert.throws(() => canonicalAssets([{ ...valid, name: "../escape.deb" }]), /safe basenames/);
  assert.throws(() => canonicalAssets([valid, valid]), /unique/);
});

test("release staging keys are derived from the release id and manifest digest", () => {
  const assets = releaseAssets([{ name: "libarchive.deb", sha256: "a".repeat(64) }], "pilot");
  assert.deepEqual(assets, [{ name: "libarchive.deb", sha256: "a".repeat(64), r2_key: `staging/pilot/${"a".repeat(64)}` }]);
  assert.throws(() => releaseAssets([{ name: "../bad", sha256: "a".repeat(64) }], "pilot"), /safe basenames/);
});

test("asset intake requires admin auth and an exact declared manifest entry", async () => {
  const digest = createHash("sha256").update("hello").digest("hex");
  const bucket = new MemoryAssetBucket({
    id: "pilot", state: "prepared", release_checks_passed: true,
    required_assets: [{ name: "libarchive.deb", sha256: digest, r2_key: `staging/pilot/${digest}` }],
  });
  const env = { RELEASES: bucket, RELEASE_ADMIN_TOKEN: "secret-test" };
  const makeRequest = (name, token) => new Request(`https://worker.test/internal/releases/pilot/assets/${name}`, {
    method: "PUT", headers: { "content-length": "5", ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: "hello",
  });

  const unauthorized = await gateway.fetch(makeRequest("libarchive.deb"), env);
  assert.equal(unauthorized.status, 401);
  const undeclared = await gateway.fetch(makeRequest("other.deb", "secret-test"), env);
  assert.equal(undeclared.status, 404);
  assert.equal(bucket.assets.size, 0);
});

test("asset intake streams checksum-verified bytes to a create-only R2 key and allows safe retries", async () => {
  const digest = createHash("sha256").update("hello").digest("hex");
  const key = `staging/pilot/${digest}`;
  const bucket = new MemoryAssetBucket({
    id: "pilot", state: "prepared", release_checks_passed: true,
    required_assets: [{ name: "libarchive.deb", sha256: digest, r2_key: key }],
  });
  const env = { RELEASES: bucket, RELEASE_ADMIN_TOKEN: "secret-test" };
  const request = () => new Request("https://worker.test/internal/releases/pilot/assets/libarchive.deb", {
    method: "PUT", headers: { authorization: "Bearer secret-test", "content-length": "5" }, body: "hello",
  });
  const first = await gateway.fetch(request(), env);
  assert.equal(first.status, 201);
  assert.deepEqual(bucket.assets.get(key).bytes, Buffer.from("hello"));
  const retry = await gateway.fetch(request(), env);
  assert.equal(retry.status, 200);
  assert.equal((await retry.json()).replay, true);
});

test("asset intake rejects tampered, oversized, and non-prepared payloads", async () => {
  const digest = createHash("sha256").update("hello").digest("hex");
  const key = `staging/pilot/${digest}`;
  const bucket = new MemoryAssetBucket({
    id: "pilot", state: "prepared", release_checks_passed: true,
    required_assets: [{ name: "libarchive.deb", sha256: digest, r2_key: key }],
  });
  const env = { RELEASES: bucket, RELEASE_ADMIN_TOKEN: "secret-test" };
  const makeRequest = (body, length) => new Request("https://worker.test/internal/releases/pilot/assets/libarchive.deb", {
    method: "PUT", headers: { authorization: "Bearer secret-test", "content-length": String(length) }, body,
  });
  assert.equal((await gateway.fetch(makeRequest("jello", 5), env)).status, 422);
  assert.equal(bucket.assets.size, 0);
  assert.equal((await gateway.fetch(makeRequest("hello", 67108865), env)).status, 413);
  const record = (await (await bucket.get("release-state/pilot.json")).json());
  record.state = "public";
  bucket.entries.set("release-state/pilot.json", { value: record, etag: "changed" });
  assert.equal((await gateway.fetch(makeRequest("hello", 5), env)).status, 409);
});

test("asset replay rejects a pre-existing object with matching metadata but a different stored checksum", async () => {
  const digest = createHash("sha256").update("hello").digest("hex");
  const key = `staging/pilot/${digest}`;
  const bucket = new MemoryAssetBucket({
    id: "pilot", state: "prepared", release_checks_passed: true,
    required_assets: [{ name: "libarchive.deb", sha256: digest, r2_key: key }],
  });
  bucket.assets.set(key, {
    size: 5,
    checksums: { sha256: createHash("sha256").update("jello").digest().buffer },
    customMetadata: { sha256: digest, releaseId: "pilot", assetName: "libarchive.deb" },
  });
  const response = await gateway.fetch(new Request("https://worker.test/internal/releases/pilot/assets/libarchive.deb", {
    method: "PUT", headers: { authorization: "Bearer secret-test", "content-length": "5" }, body: "hello",
  }), { RELEASES: bucket, RELEASE_ADMIN_TOKEN: "secret-test" });
  assert.equal(response.status, 409);
});

test("release registration JSON has a bounded streaming body", async () => {
  const env = { RELEASES: new MemoryBucket(), RELEASE_ADMIN_TOKEN: "secret-test" };
  const oversized = await gateway.fetch(new Request("https://worker.test/internal/releases", {
    method: "POST", headers: { authorization: "Bearer secret-test" }, body: JSON.stringify({ padding: "x".repeat(65536) }),
  }), env);
  assert.equal(oversized.status, 413);
  const malformed = await gateway.fetch(new Request("https://worker.test/internal/releases", {
    method: "POST", headers: { authorization: "Bearer secret-test" }, body: "{not-json",
  }), env);
  assert.equal(malformed.status, 400);
});

test("deadline parser requires an explicit timezone", () => {
  assert.equal(parseUtc("2026-11-01T14:00:00Z").toISOString(), "2026-11-01T14:00:00.000Z");
  assert.throws(() => parseUtc("2026-11-01T14:00:00"), /UTC offset/);
});

test("release gate requires the named successful package job and exact tested source commit", async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  let displayTitle = `Verify libxml2 at ${"b".repeat(40)}`;
  globalThis.fetch = async (url) => {
    calls.push(String(url));
    if (String(url).endsWith("/actions/runs/456")) {
      return Response.json({
        id: 456, event: "workflow_dispatch", conclusion: "success", head_branch: "main",
        path: ".github/workflows/package-verification.yml",
        display_title: displayTitle, head_sha: "c".repeat(40), updated_at: "2026-10-25T14:00:00Z", run_attempt: 2,
      });
    }
    if (String(url).endsWith("/jobs?per_page=100")) {
      return Response.json({ jobs: [{ id: 9, name: "package (libxml2)", run_attempt: 2, conclusion: "success" }] });
    }
    if (String(url).endsWith("/git/ref/tags/aptto/1.2.3")) {
      return Response.json({ ref: "refs/tags/aptto/1.2.3", object: { type: "tag", sha: "d".repeat(40) } });
    }
    if (String(url).includes("/compare/aptto%2Ffocal...")) {
      return Response.json({ merge_base_commit: { sha: "b".repeat(40) } });
    }
    return Response.json({ verification: { verified: true }, object: { type: "commit", sha: "b".repeat(40) } });
  };
  try {
    const verified = await verifyPackageRun(
      { GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only" },
      "apt-to/packaging-libxml2", "b".repeat(40), "aptto/1.2.3", 456,
    );
    assert.equal(verified.job_id, 9);
    assert.equal(verified.run_id, 456);
    assert.equal(calls.length, 5);
    displayTitle = `Verify all at ${"b".repeat(40)}`;
    await assert.rejects(
      verifyPackageRun({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only" }, "apt-to/packaging-libxml2", "b".repeat(40), "aptto/1.2.3", 456),
      /successful package-verification dispatch/,
    );
    displayTitle = `Verify libxml2 at ${"b".repeat(40)}`;
    await assert.rejects(
      verifyPackageRun({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only" }, "apt-to/packaging-libxml2", "a".repeat(40), "aptto/1.2.3", 456),
      /successful package-verification dispatch/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("signed source tag must point to the tested commit", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).endsWith("/git/ref/tags/aptto/1.2.3")) {
      return Response.json({ ref: "refs/tags/aptto/1.2.3", object: { type: "tag", sha: "d".repeat(40) } });
    }
    if (String(url).includes("/compare/aptto%2Ffocal...")) {
      return Response.json({ merge_base_commit: { sha: "e".repeat(40) } });
    }
    return Response.json({ verification: { verified: true }, object: { type: "commit", sha: "e".repeat(40) } });
  };
  try {
    await assert.rejects(
      verifySignedSourceTag({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only" }, "apt-to/packaging-libxml2", "aptto/1.2.3", "b".repeat(40)),
      /point to the tested source commit/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("signed source commit must be reachable from the supported packaging branch", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).endsWith("/git/ref/tags/aptto/1.2.3")) {
      return Response.json({ ref: "refs/tags/aptto/1.2.3", object: { type: "tag", sha: "d".repeat(40) } });
    }
    if (String(url).includes("/git/tags/")) {
      return Response.json({ verification: { verified: true }, object: { type: "commit", sha: "b".repeat(40) } });
    }
    return Response.json({ merge_base_commit: { sha: "e".repeat(40) } });
  };
  try {
    await assert.rejects(
      verifySignedSourceTag({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only" }, "apt-to/packaging-libxml2", "aptto/1.2.3", "b".repeat(40)),
      /reachable from aptto\/focal/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("public releases require repository-level immutable-release enforcement", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({ enabled: false });
  try {
    await assert.rejects(
      requireImmutableReleasesEnabled({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only" }, "apt-to/packaging-libxml2"),
      /must be enabled/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("public state audits fail closed if GitHub reports a mutable release", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({ draft: false, immutable: false, tag_name: "aptto/1.2.3", assets: [] });
  const bucket = new MemoryBucket({
    "release-state/pilot.json": {
      id: "pilot", state: "public", repository: "apt-to/packaging-libxml2", tag: "aptto/1.2.3",
      source_commit: "b".repeat(40), public_release_id: 42,
      sponsor_delay_hours: 0,
      required_assets: [{ name: "libxml2.deb", sha256: "a".repeat(64), r2_key: "staging/libxml2" }],
      verified_assets: [{ name: "libxml2.deb", sha256: "a".repeat(64), r2_key: "staging/libxml2" }],
    },
  });
  try {
    await assert.rejects(publishOne({ RELEASES: bucket, GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only" }, "release-state/pilot.json", new Date()), /not immutable/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("seven-day releases remain blocked until private sponsor serving exists", async () => {
  const bucket = new MemoryBucket({
    "release-state/pilot.json": {
      id: "pilot", state: "prepared", repository: "apt-to/packaging-libxml2", tag: "aptto/1.2.3",
      sponsor_delay_hours: 168, release_checks_passed: true,
      required_assets: [{ name: "libxml2.deb", sha256: "a".repeat(64), r2_key: "staging/libxml2" }],
    },
  });
  await assert.rejects(publishOne({ RELEASES: bucket }, "release-state/pilot.json", new Date()), /sponsor authentication and private serving/);
  assert.equal((await (await bucket.get("release-state/pilot.json")).json()).state, "prepared");
});
