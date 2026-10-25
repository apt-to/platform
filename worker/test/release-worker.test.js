import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac, generateKeyPairSync, sign as signJwt } from "node:crypto";
import gateway, { beginSponsorPublication, canonicalAssets, fetchSponsorSnapshot, githubActionsIdentity, parseUtc, publishOne, readFreshSponsorSnapshot, reconcile, reconcileSponsors, releaseAssets, requireImmutableReleasesEnabled, updateState, verifyGithubSignature, verifyPackageRun, verifySignedSourceTag } from "../src/index.js";

const TEST_RELEASE_TAG_SIGNER = "aptto-release-maintainer";

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
  async list({ prefix }) {
    return { objects: [...this.entries.entries()].filter(([key]) => key.startsWith(prefix)).map(([key, entry]) => ({ key, etag: entry.etag })), truncated: false };
  }
}

function signedOidcToken(privateKey, overrides = {}, signatureKey = privateKey, keyId = "test-key") {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: keyId })).toString("base64url");
  const now = Math.floor(Date.now() / 1000);
  const claims = Buffer.from(JSON.stringify({
    iss: "https://token.actions.githubusercontent.com", aud: "aptto-release-gateway",
    exp: now + 120, iat: now, nbf: now - 1, jti: "test-jti-12345678",
    repository: "apt-to/platform", repository_id: "1433070541", repository_owner: "apt-to",
    repository_visibility: "public", event_name: "workflow_run", ref: "refs/heads/main",
    workflow_ref: "apt-to/platform/.github/workflows/private-staging.yml@refs/heads/main",
    runner_environment: "github-hosted", environment: "aptto-signing", run_id: "40210000000", run_attempt: 1,
    ...overrides,
  })).toString("base64url");
  const input = `${header}.${claims}`;
  return `${input}.${signJwt("RSA-SHA256", Buffer.from(input), signatureKey).toString("base64url")}`;
}

test("GitHub Actions OIDC accepts only signed tokens from the protected staging workflow", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: "test-key", use: "sig", alg: "RS256" };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => String(url).includes("/.well-known/jwks") ? Response.json({ keys: [jwk] }) : Response.json({});
  try {
    const identity = await githubActionsIdentity(new Request("https://worker.test", {
      headers: { authorization: `Bearer ${signedOidcToken(privateKey)}` },
    }), {});
    assert.deepEqual(identity, { type: "github-actions", run_id: 40210000000, run_attempt: 1, environment: "aptto-signing" });
    const wrongEnvironment = signedOidcToken(privateKey, { environment: "unprotected" });
    assert.equal(await githubActionsIdentity(new Request("https://worker.test", { headers: { authorization: `Bearer ${wrongEnvironment}` } }), {}), null);
    const missingEnvironment = signedOidcToken(privateKey, { environment: undefined });
    assert.equal(await githubActionsIdentity(new Request("https://worker.test", { headers: { authorization: `Bearer ${missingEnvironment}` } }), {}), null);
    const wrongWorkflow = signedOidcToken(privateKey, { workflow_ref: "apt-to/platform/.github/workflows/package-verification.yml@refs/heads/main" });
    assert.equal(await githubActionsIdentity(new Request("https://worker.test", { headers: { authorization: `Bearer ${wrongWorkflow}` } }), {}), null);
    const wrongAudience = signedOidcToken(privateKey, { aud: "other-service" });
    assert.equal(await githubActionsIdentity(new Request("https://worker.test", { headers: { authorization: `Bearer ${wrongAudience}` } }), {}), null);
    const { privateKey: attackerKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const forged = signedOidcToken(privateKey, {}, attackerKey);
    assert.equal(await githubActionsIdentity(new Request("https://worker.test", { headers: { authorization: `Bearer ${forged}` } }), {}), null);
  } finally { globalThis.fetch = originalFetch; }
});

test("APT snapshot inventory and gated package export require the dedicated signing workflow and verify R2 bytes", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const keyId = "snapshot-export-test";
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: keyId, use: "sig", alg: "RS256" };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => String(url).includes("/.well-known/jwks") ? Response.json({ keys: [jwk] }) : Response.json({});
  const bytes = Buffer.from("private gated package bytes");
  const digest = createHash("sha256").update(bytes).digest("hex");
  const id = "libxml2-2-9-10-aptto1";
  const objectKey = `staging/${id}/${digest}`;
  const gated = {
    id, state: "sponsor-period", repository: "apt-to/packaging-libxml2", tag: "aptto/2.9.10-aptto1",
    source_commit: "c".repeat(40), release_checks_passed: true, sponsor_delay_hours: 168,
    sponsor_publication_complete: true, public_after: new Date(Date.now() + 86400000).toISOString(),
    required_assets: [{ name: "libxml2_amd64.deb", sha256: digest, r2_key: objectKey }],
    source_assets: [{ name: "libxml2_2.9.10.dsc", sha256: "d".repeat(64), r2_key: `staging/${id}/source/${"d".repeat(64)}` }],
  };
  const bucket = new MemorySnapshotBucket({ [`release-state/${id}.json`]: gated });
  bucket.blobs.set(objectKey, {
    size: bytes.length,
    checksums: { sha256: createHash("sha256").update(bytes).digest() },
    customMetadata: { releaseId: id, assetName: "libxml2_amd64.deb" },
    bytes,
  });
  const env = { RELEASES: bucket };
  const workflowClaims = {
    workflow_ref: "apt-to/platform/.github/workflows/repository-snapshot.yml@refs/heads/main",
    event_name: "workflow_dispatch",
    environment: "aptto-index-build",
  };
  const authorization = `Bearer ${signedOidcToken(privateKey, workflowClaims, privateKey, keyId)}`;
  const signerToken = `Bearer ${signedOidcToken(privateKey, { ...workflowClaims, environment: "aptto-signing" }, privateKey, keyId)}`;
  try {
    const inventory = await gateway.fetch(new Request("https://repo.apt.to/internal/repository-snapshots/early/releases", { headers: { authorization } }), env);
    assert.equal(inventory.status, 200);
    assert.deepEqual((await inventory.json()).releases.map((entry) => entry.id), [id]);
    const downloaded = await gateway.fetch(new Request(`https://repo.apt.to/internal/repository-snapshots/early/releases/${id}/assets/libxml2_amd64.deb`, { headers: { authorization } }), env);
    assert.equal(downloaded.status, 200);
    assert.deepEqual(Buffer.from(await downloaded.arrayBuffer()), bytes);
    assert.equal(downloaded.headers.get("cache-control"), "private, no-store");
    const stagingToken = `Bearer ${signedOidcToken(privateKey, {}, privateKey, keyId)}`;
    const denied = await gateway.fetch(new Request("https://repo.apt.to/internal/repository-snapshots/early/releases", { headers: { authorization: stagingToken } }), env);
    assert.equal(denied.status, 401);
    const signerDenied = await gateway.fetch(new Request("https://repo.apt.to/internal/repository-snapshots/early/releases", { headers: { authorization: signerToken } }), env);
    assert.equal(signerDenied.status, 401, "the signing environment cannot access sponsor package bytes");

    bucket.blobs.get(objectKey).customMetadata.assetName = "unexpected.deb";
    const tampered = await gateway.fetch(new Request(`https://repo.apt.to/internal/repository-snapshots/early/releases/${id}/assets/libxml2_amd64.deb`, { headers: { authorization } }), env);
    assert.equal(tampered.status, 502);
  } finally { globalThis.fetch = originalFetch; }
});

test("unsigned snapshot build storage separates index-builder writes from signer reads", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const keyId = "snapshot-build-storage-test";
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: keyId, use: "sig", alg: "RS256" };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => String(url).includes("/.well-known/jwks") ? Response.json({ keys: [jwk] }) : Response.json({});
  const release = {
    id: "pilot", state: "public", repository: "apt-to/packaging-libarchive", tag: "aptto/3.4.0-2ubuntu1.5+aptto1",
    source_commit: "b".repeat(40), release_checks_passed: true, sponsor_delay_hours: 0,
    required_assets: [{ name: "libarchive_amd64.deb", sha256: "a".repeat(64), r2_key: `staging/pilot/${"a".repeat(64)}` }],
  };
  const bucket = new MemorySnapshotBucket({ "release-state/pilot.json": release });
  const env = { RELEASES: bucket };
  const workflowRef = "apt-to/platform/.github/workflows/repository-snapshot.yml@refs/heads/main";
  const builderToken = `Bearer ${signedOidcToken(privateKey, { workflow_ref: workflowRef, event_name: "workflow_dispatch", environment: "aptto-index-build" }, privateKey, keyId)}`;
  const signerToken = `Bearer ${signedOidcToken(privateKey, { workflow_ref: workflowRef, event_name: "workflow_dispatch", environment: "aptto-signing" }, privateKey, keyId)}`;
  const contents = new Map([
    ["dists/focal/Release", "Origin: AptTo\nSuite: focal\n"],
    ["dists/focal/main/binary-amd64/Packages", "Package: libarchive\n"],
    ["dists/focal/main/binary-amd64/Packages.gz", "gzip"],
    ["dists/focal/main/binary-amd64/Packages.xz", "xz"],
    ["dists/focal/main/source/Sources", "Package: libarchive\n"],
    ["dists/focal/main/source/Sources.gz", "gzip source"],
    ["dists/focal/main/source/Sources.xz", "xz source"],
  ]);
  const files = [...contents].map(([path, value]) => ({ path, size: Buffer.byteLength(value), sha256: createHash("sha256").update(value).digest("hex") }));
  const buildId = "focal-test-r40210000000-public";
  const request = (authorization, url, method, body) => new Request(url, {
    method, headers: { authorization, ...(body === undefined ? {} : { "content-length": String(Buffer.byteLength(body)) }) }, body,
  });
  try {
    const register = await gateway.fetch(request(builderToken, "https://repo.apt.to/internal/repository-snapshot-builds/public", "POST", JSON.stringify({ id: buildId, release_ids: ["pilot"], files })), env);
    assert.equal(register.status, 201);
    for (const [path, value] of contents) {
      const upload = await gateway.fetch(request(builderToken, `https://repo.apt.to/internal/repository-snapshot-builds/public/${buildId}/files/${path}`, "PUT", value), env);
      assert.equal(upload.status, 201, path);
    }
    const manifest = await gateway.fetch(request(signerToken, `https://repo.apt.to/internal/repository-snapshot-builds/public/${buildId}`, "GET"), env);
    assert.equal(manifest.status, 200);
    assert.equal((await manifest.json()).files.length, files.length);
    const read = await gateway.fetch(request(signerToken, `https://repo.apt.to/internal/repository-snapshot-builds/public/${buildId}/files/dists/focal/Release`, "GET"), env);
    assert.equal(read.status, 200);
    assert.equal(await read.text(), contents.get("dists/focal/Release"));
    const signerWrite = await gateway.fetch(request(signerToken, `https://repo.apt.to/internal/repository-snapshot-builds/public/${buildId}/files/dists/focal/Release`, "PUT", contents.get("dists/focal/Release")), env);
    assert.equal(signerWrite.status, 401);
    const builderRead = await gateway.fetch(request(builderToken, `https://repo.apt.to/internal/repository-snapshot-builds/public/${buildId}`, "GET"), env);
    assert.equal(builderRead.status, 401);
    const builderActivation = await gateway.fetch(request(builderToken, `https://repo.apt.to/internal/repository-snapshots/public/${buildId}/activate`, "POST", "{}"), env);
    assert.equal(builderActivation.status, 401);
    const builderRegistration = await gateway.fetch(request(builderToken, "https://repo.apt.to/internal/repository-snapshots/public", "POST", JSON.stringify({ id: buildId, release_ids: ["pilot"], files })), env);
    assert.equal(builderRegistration.status, 401);
  } finally { globalThis.fetch = originalFetch; }
});

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
  async get(key) {
    const asset = this.assets.get(key);
    if (asset) return {
      ...asset,
      body: new Response(asset.bytes).body,
      arrayBuffer: async () => asset.bytes.buffer.slice(asset.bytes.byteOffset, asset.bytes.byteOffset + asset.bytes.byteLength),
    };
    return super.get(key);
  }
}

class MemorySponsorBucket extends MemoryBucket {
  constructor(entries, assetKey, assetBytes) {
    super(entries);
    const digest = createHash("sha256").update(assetBytes).digest();
    this.staged = {
      size: assetBytes.length,
      checksums: { sha256: digest.buffer.slice(digest.byteOffset, digest.byteOffset + digest.byteLength) },
      httpMetadata: { contentType: "application/vnd.debian.binary-package" },
      bytes: Buffer.from(assetBytes),
      body: new Response(assetBytes).body,
    };
    this.assetKey = assetKey;
  }
  async head(key) { return key === this.assetKey ? this.staged : null; }
  async get(key, options = {}) {
    if (key === this.assetKey) {
      const { offset, length } = options.range || { offset: 0, length: this.staged.size };
      return { ...this.staged, body: new Response(this.staged.bytes.subarray(offset, offset + length)).body };
    }
    return super.get(key);
  }
}

class MemorySnapshotBucket extends MemoryBucket {
  constructor(entries = {}) {
    super(entries);
    this.blobs = new Map();
  }
  async put(key, body, options) {
    if (!options.sha256) return super.put(key, body, options);
    if (this.blobs.has(key)) return null;
    const bytes = Buffer.from(await new Response(body).arrayBuffer());
    const digest = createHash("sha256").update(bytes).digest();
    if (!digest.equals(Buffer.from(options.sha256))) throw new Error("R2 snapshot checksum validation failed");
    const object = {
      size: bytes.length,
      checksums: { sha256: digest.buffer.slice(digest.byteOffset, digest.byteOffset + digest.byteLength) },
      customMetadata: structuredClone(options.customMetadata),
      httpMetadata: structuredClone(options.httpMetadata),
      bytes,
    };
    this.blobs.set(key, object);
    return object;
  }
  async head(key) { return this.blobs.get(key) || null; }
  async get(key) {
    const object = this.blobs.get(key);
    if (!object) return super.get(key);
    return {
      ...object,
      body: new Response(object.bytes).body,
      arrayBuffer: async () => object.bytes.buffer.slice(object.bytes.byteOffset, object.bytes.byteOffset + object.bytes.byteLength),
    };
  }
  async delete(key) { this.blobs.delete(key); this.entries.delete(key); }
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

test("GitHub webhook signature uses the documented HMAC SHA-256 scheme", async () => {
  const body = new TextEncoder().encode("Hello, World!");
  assert.equal(await gateway.fetch(new Request("https://worker.test/webhooks/github/sponsorship", {
    method: "POST",
    headers: {
      "x-github-event": "sponsorship",
      "x-github-delivery": "12345678-1234-1234-1234-123456789abc",
      "x-hub-signature-256": "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
    },
    body,
  }), { SPONSOR_WEBHOOK_SECRET: "It's a Secret to Everybody", RELEASES: new MemoryBucket() }).then((response) => response.status), 400);
  assert.equal(await verifyGithubSignature("It's a Secret to Everybody", body, "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"), true);
  assert.equal(await verifyGithubSignature("wrong", body, "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"), false);
});

test("sponsor snapshot paginates current GitHub state, applies an explicit tier allowlist, and excludes organization members", async () => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  globalThis.fetch = async (_url, options) => {
    const body = JSON.parse(options.body);
    requests.push(body.variables.after);
    const firstPage = body.variables.after === null;
    return Response.json({ data: { organization: {
      login: "apt-to", hasSponsorsListing: true,
      sponsorshipsAsMaintainer: {
        nodes: firstPage ? [
          { isActive: true, isOneTimePayment: false, sponsorEntity: { __typename: "User", databaseId: 17, login: "alice" }, tier: { id: "tier-early", name: "Early access", isOneTime: false } },
          { isActive: true, isOneTimePayment: false, sponsorEntity: { __typename: "Organization", databaseId: 89, login: "sponsor-org" }, tier: { id: "tier-early", name: "Early access", isOneTime: false } },
          { isActive: true, isOneTimePayment: false, sponsorEntity: { __typename: "User", databaseId: 18, login: "bob" }, tier: { id: "tier-other", name: "Other", isOneTime: false } },
          { isActive: false, isOneTimePayment: false, sponsorEntity: { __typename: "User", databaseId: 19, login: "former" }, tier: { id: "tier-early", name: "Early access", isOneTime: false } },
        ] : [
          { isActive: true, isOneTimePayment: true, sponsorEntity: { __typename: "User", databaseId: 20, login: "carol" }, tier: { id: "tier-early", name: "Early access", isOneTime: true } },
        ],
        pageInfo: firstPage ? { hasNextPage: true, endCursor: "cursor-1" } : { hasNextPage: false, endCursor: null },
      },
    } } });
  };
  try {
    const snapshot = await fetchSponsorSnapshot({ SPONSOR_GRAPHQL_TOKEN: "test-token", SPONSOR_ALLOWED_TIER_IDS: "tier-early" }, new Date("2026-10-25T16:00:00Z"));
    assert.deepEqual(requests, [null, "cursor-1"]);
    assert.deepEqual(snapshot.sponsors.map((sponsor) => sponsor.github_user_id), [17, 20]);
    assert.equal(snapshot.sponsors[1].has_one_time_sponsorship, true);
    assert.deepEqual(snapshot.tier_ids, ["tier-early"]);
  } finally { globalThis.fetch = originalFetch; }
});

test("scheduled sponsor reconciliation persists an authoritative snapshot and consumes webhook markers", async () => {
  const bucket = new MemoryBucket({
    "sponsor-deliveries/delivery-12345678.json": {
      delivery_id: "delivery-12345678", action: "cancelled", sponsor_id: 17,
      received_at: "2026-10-25T15:00:00Z", effect: "reconciliation-required",
    },
  });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({ data: { organization: {
    login: "apt-to", hasSponsorsListing: true,
    sponsorshipsAsMaintainer: {
      nodes: [{ isActive: true, isOneTimePayment: false, sponsorEntity: { __typename: "User", databaseId: 17, login: "alice" }, tier: { id: "tier-early", name: "Early access", isOneTime: false } }],
      pageInfo: { hasNextPage: false, endCursor: null },
    },
  } } });
  try {
    const snapshot = await reconcileSponsors({
      RELEASES: bucket, SPONSOR_GRAPHQL_TOKEN: "test-token", SPONSOR_ALLOWED_TIER_IDS: "tier-early",
    }, new Date("2026-10-25T16:00:00Z"));
    assert.deepEqual(snapshot.sponsors.map((sponsor) => sponsor.github_user_id), [17]);
    const event = await bucket.get("sponsor-deliveries/delivery-12345678.json");
    const record = await event.json();
    assert.equal(record.reconciled_at, snapshot.reconciled_at);
    assert.equal(record.sponsor_active, true);
    assert.equal(record.entitlement_source, "authoritative-snapshot");
    assert.deepEqual((await readFreshSponsorSnapshot(bucket, new Date("2026-10-25T16:30:00Z"))).sponsors.map((sponsor) => sponsor.github_user_id), [17]);
    assert.equal(await readFreshSponsorSnapshot(bucket, new Date("2026-10-25T16:30:00.001Z")), null);
  } finally { globalThis.fetch = originalFetch; }
});

test("failed sponsor refresh leaves the previous snapshot unchanged and unavailable listings fail closed", async () => {
  const oldSnapshot = {
    organization: "apt-to", tier_ids: ["tier-early"],
    sponsors: [{ github_user_id: 17, github_login: "alice", tier_ids: ["tier-early"], has_one_time_sponsorship: false }],
    reconciled_at: "2026-10-25T15:00:00.000Z", valid_until: "2026-10-25T15:30:00.000Z",
    authority: "github-sponsors-graphql-active-only",
  };
  const bucket = new MemoryBucket({ "sponsor-entitlements/current.json": oldSnapshot });
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response("unavailable", { status: 503 });
    await assert.rejects(reconcileSponsors({
      RELEASES: bucket, SPONSOR_GRAPHQL_TOKEN: "test-token", SPONSOR_ALLOWED_TIER_IDS: "tier-early",
    }, new Date("2026-10-25T16:00:00Z")), /returned 503/);
    assert.deepEqual(await (await bucket.get("sponsor-entitlements/current.json")).json(), oldSnapshot);

    globalThis.fetch = async () => Response.json({ data: { organization: {
      login: "apt-to", hasSponsorsListing: false,
      sponsorshipsAsMaintainer: { nodes: [], pageInfo: { hasNextPage: false, endCursor: null } },
    } } });
    await assert.rejects(fetchSponsorSnapshot({
      SPONSOR_GRAPHQL_TOKEN: "test-token", SPONSOR_ALLOWED_TIER_IDS: "tier-early",
    }, new Date("2026-10-25T16:00:00Z")), /listing is unavailable/);
  } finally { globalThis.fetch = originalFetch; }
});

test("sponsor publication starts an exact 168-hour clock only after every private asset passes readback", async () => {
  const digest = createHash("sha256").update("private-package").digest();
  const release = {
    id: "pilot", state: "prepared", repository: "apt-to/packaging-libxml2", tag: "aptto/1.2.3",
    source_commit: "b".repeat(40), sponsor_delay_hours: 168, release_checks_passed: true,
    required_assets: [{ name: "libxml2.deb", sha256: digest.toString("hex"), r2_key: `staging/pilot/${digest.toString("hex")}` }],
    source_assets: [{ name: "libxml2_1.2.3.dsc", sha256: "a".repeat(64), r2_key: `staging/pilot/source/${"a".repeat(64)}` }],
  };
  const bucket = new MemoryAssetBucket(release);
  const key = release.required_assets[0].r2_key;
  bucket.assets.set(key, {
    size: Buffer.byteLength("private-package"),
    checksums: { sha256: digest.buffer.slice(digest.byteOffset, digest.byteOffset + digest.byteLength) },
    customMetadata: { releaseId: "pilot", assetName: "libxml2.deb" },
  });
  const sourceDigest = Buffer.from("a".repeat(64), "hex");
  bucket.assets.set(release.source_assets[0].r2_key, { size: 1, checksums: { sha256: sourceDigest.buffer.slice(sourceDigest.byteOffset, sourceDigest.byteOffset + sourceDigest.byteLength) }, customMetadata: { releaseId: "pilot", assetName: "libxml2_1.2.3.dsc", assetKind: "source" } });
  const started = new Date("2026-10-25T16:00:00.000Z");
  const result = await beginSponsorPublication(new Request("https://worker.test/internal/releases/pilot/publish-sponsor", {
    method: "POST", headers: { authorization: "Bearer admin-secret" },
  }), { RELEASES: bucket, RELEASE_ADMIN_TOKEN: "admin-secret" }, "pilot", started);
  assert.equal(result.status, 201);
  const state = await (await bucket.get("release-state/pilot.json")).json();
  assert.equal(state.sponsor_published_at, started.toISOString());
  assert.equal(state.public_after, new Date(started.getTime() + 168 * 60 * 60 * 1000).toISOString());
  assert.equal(state.sponsor_publication_complete, true);
  const retry = await beginSponsorPublication(new Request("https://worker.test/internal/releases/pilot/publish-sponsor", {
    method: "POST", headers: { authorization: "Bearer admin-secret" },
  }), { RELEASES: bucket, RELEASE_ADMIN_TOKEN: "admin-secret" }, "pilot", new Date(started.getTime() + 1000));
  assert.equal(retry.status, 200);
  assert.equal((await retry.json()).public_after, state.public_after);
});

test("private early asset route requires a fresh sponsor entitlement and serves bytes without shared caching", async () => {
  const token = `aptto_${"a".repeat(64)}`;
  const tokenHash = createHash("sha256").update(token).digest("hex");
  const bytes = Buffer.from("private-package");
  const digest = createHash("sha256").update(bytes).digest("hex");
  const assetKey = `staging/pilot/${digest}`;
  const now = new Date();
  const bucket = new MemorySponsorBucket({
    [`apt-device-tokens/${tokenHash}.json`]: {
      github_user_id: 17, device_label: "workstation", created_at: now.toISOString(),
      expires_at: new Date(now.getTime() + 86400000).toISOString(),
    },
    "sponsor-entitlements/current.json": {
      organization: "apt-to", authority: "github-sponsors-graphql-active-only",
      sponsors: [{ github_user_id: 17, tier_ids: ["tier-early"] }],
      reconciled_at: now.toISOString(), valid_until: new Date(now.getTime() + 1800000).toISOString(),
    },
    "release-state/pilot.json": {
      id: "pilot", state: "sponsor-period", sponsor_delay_hours: 168, sponsor_publication_complete: true,
      public_after: new Date(now.getTime() + 86400000).toISOString(),
      required_assets: [{ name: "libxml2.deb", sha256: digest, r2_key: assetKey }],
    },
  }, assetKey, bytes);
  const url = "https://worker.test/early/releases/pilot/assets/libxml2.deb";
  assert.equal((await gateway.fetch(new Request(url), { RELEASES: bucket })).status, 401);
  const response = await gateway.fetch(new Request(url, {
    headers: { authorization: `Basic ${btoa(`apt:${token}`)}` },
  }), { RELEASES: bucket });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "private-package");
  assert.equal(response.headers.get("cache-control"), "private, no-store");
  assert.equal(response.headers.get("vary"), "Authorization");
  assert.equal(response.headers.get("accept-ranges"), "bytes");
  const anonymousRange = await gateway.fetch(new Request(url, { headers: { range: "bytes=0-1" } }), { RELEASES: bucket });
  assert.equal(anonymousRange.status, 401);
  const ranged = await gateway.fetch(new Request(url, {
    headers: { authorization: `Basic ${btoa(`apt:${token}`)}`, range: "bytes=2-6" },
  }), { RELEASES: bucket });
  assert.equal(ranged.status, 206);
  assert.equal(ranged.headers.get("content-range"), "bytes 2-6/15");
  assert.equal(ranged.headers.get("content-length"), "5");
  assert.equal(await ranged.text(), "ivate");
  const ifRangeMismatch = await gateway.fetch(new Request(url, {
    headers: { authorization: `Basic ${btoa(`apt:${token}`)}`, range: "bytes=2-6", "if-range": '"stale-etag"' },
  }), { RELEASES: bucket });
  assert.equal(ifRangeMismatch.status, 200);
  assert.equal(await ifRangeMismatch.text(), "private-package");
  const suffix = await gateway.fetch(new Request(url, {
    headers: { authorization: `Basic ${btoa(`apt:${token}`)}`, range: "bytes=-4" },
  }), { RELEASES: bucket });
  assert.equal(suffix.status, 206);
  assert.equal(suffix.headers.get("content-range"), "bytes 11-14/15");
  assert.equal(await suffix.text(), "kage");
  const unsatisfiable = await gateway.fetch(new Request(url, {
    headers: { authorization: `Basic ${btoa(`apt:${token}`)}`, range: "bytes=15-" },
  }), { RELEASES: bucket });
  assert.equal(unsatisfiable.status, 416);
  assert.equal(unsatisfiable.headers.get("content-range"), "bytes */15");
  const head = await gateway.fetch(new Request(url, {
    method: "HEAD", headers: { authorization: `Basic ${btoa(`apt:${token}`)}` },
  }), { RELEASES: bucket });
  assert.equal(head.status, 200);
  assert.equal(head.headers.get("content-length"), "15");
  assert.equal(await head.text(), "");
  const stale = await bucket.get("sponsor-entitlements/current.json");
  const staleRecord = await stale.json();
  bucket.entries.set("sponsor-entitlements/current.json", {
    value: { ...staleRecord, valid_until: new Date(now.getTime() - 1).toISOString() }, etag: "stale",
  });
  assert.equal((await gateway.fetch(new Request(url, {
    headers: { authorization: `Basic ${btoa(`apt:${token}`)}` },
  }), { RELEASES: bucket })).status, 401);
});

test("early package URLs continue anonymously through the immutable public release after promotion", async () => {
  const record = {
    id: "libxml2-1-2-3", state: "public", repository: "apt-to/packaging-libxml2", tag: "aptto/1.2.3",
    public_release_id: 901, sponsor_delay_hours: 168,
    required_assets: [{ name: "libxml2_1.2.3_amd64.deb", sha256: "a".repeat(64), r2_key: `staging/release/${"a".repeat(64)}` }],
  };
  const bucket = new MemoryBucket({ "release-state/libxml2-1-2-3.json": record });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    assert.equal(String(url), "https://api.github.com/repos/apt-to/packaging-libxml2/releases/901/assets");
    return Response.json([{ name: "libxml2_1.2.3_amd64.deb", browser_download_url: "https://github.com/apt-to/packaging-libxml2/releases/download/aptto/1.2.3/libxml2_1.2.3_amd64.deb" }]);
  };
  try {
    const response = await gateway.fetch(new Request("https://early.apt.to/early/releases/libxml2-1-2-3/assets/libxml2_1.2.3_amd64.deb"), {
      RELEASES: bucket, GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only",
    });
    assert.equal(response.status, 302);
    assert.equal(response.headers.get("location"), "https://github.com/apt-to/packaging-libxml2/releases/download/aptto/1.2.3/libxml2_1.2.3_amd64.deb");
    assert.equal(response.headers.get("cache-control"), "public, max-age=300");
  } finally { globalThis.fetch = originalFetch; }
});

test("repository pool paths resolve only manifest assets and preserve gated access", async () => {
  const binaryName = "libxml2_1.2.3_amd64.deb";
  const sourceName = "libxml2_1.2.3.dsc";
  const record = {
    id: "libxml2-1-2-3", state: "public", repository: "apt-to/packaging-libxml2", tag: "aptto/1.2.3",
    public_release_id: 901, source_release_id: 902, sponsor_delay_hours: 168,
    required_assets: [{ name: binaryName, sha256: "a".repeat(64), r2_key: `staging/libxml2-1-2-3/${"a".repeat(64)}` }],
    source_assets: [{ name: sourceName, sha256: "b".repeat(64), r2_key: `staging/libxml2-1-2-3/source/${"b".repeat(64)}` }],
  };
  const bucket = new MemoryBucket({ "release-state/libxml2-1-2-3.json": record });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const value = String(url);
    if (value.endsWith("/releases/901/assets")) {
      return Response.json([{ name: binaryName, browser_download_url: `https://github.com/apt-to/packaging-libxml2/releases/download/aptto/1.2.3/${binaryName}` }]);
    }
    if (value.endsWith("/releases/902/assets")) {
      return Response.json([{ name: sourceName, browser_download_url: `https://github.com/apt-to/packaging-libxml2/releases/download/aptto-source/1.2.3/${sourceName}` }]);
    }
    throw new Error(`unexpected GitHub URL ${value}`);
  };
  try {
    const env = { RELEASES: bucket, GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only" };
    const binary = await gateway.fetch(new Request(`https://repo.apt.to/pool/main/l/libxml2/${binaryName}`), env);
    assert.equal(binary.status, 302);
    assert.equal(binary.headers.get("location"), `https://github.com/apt-to/packaging-libxml2/releases/download/aptto/1.2.3/${binaryName}`);
    const source = await gateway.fetch(new Request(`https://repo.apt.to/pool/main/l/libxml2/${sourceName}`), env);
    assert.equal(source.status, 302);
    assert.equal(source.headers.get("location"), `https://github.com/apt-to/packaging-libxml2/releases/download/aptto-source/1.2.3/${sourceName}`);
    const traversal = await gateway.fetch(new Request(`https://repo.apt.to/pool/main/l/libxml2/%2e%2e%2F${binaryName}`), env);
    assert.equal(traversal.status, 400);

    const gated = new MemoryBucket({ "release-state/libxml2-1-2-3.json": {
      ...record, state: "sponsor-period", public_release_id: undefined,
      sponsor_publication_complete: true, public_after: new Date(Date.now() + 86400000).toISOString(),
    } });
    const denied = await gateway.fetch(new Request(`https://early.apt.to/pool/main/l/libxml2/${binaryName}`), { RELEASES: gated });
    assert.equal(denied.status, 401);
    assert.equal(denied.headers.get("cache-control"), "private, no-store");

    const promoted = new MemoryBucket({ "release-state/libxml2-1-2-3.json": {
      ...record, state: "public", public_release_id: 901,
    } });
    const afterPromotion = await gateway.fetch(new Request(`https://repo.apt.to/pool/main/l/libxml2/${binaryName}`), {
      RELEASES: promoted, GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only",
    });
    assert.equal(afterPromotion.status, 302);
    assert.equal(afterPromotion.headers.get("location"), `https://github.com/apt-to/packaging-libxml2/releases/download/aptto/1.2.3/${binaryName}`);
    assert.equal(afterPromotion.headers.get("cache-control"), "public, max-age=300");
  } finally { globalThis.fetch = originalFetch; }
});

test("APT snapshot manifests activate atomically after R2 readback and serve stable dists paths", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const keyId = "snapshot-environment-test";
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: keyId, use: "sig", alg: "RS256" };
  const release = {
    id: "pilot", state: "public", repository: "apt-to/packaging-libarchive", tag: "aptto/3.4.0-2ubuntu1.5+aptto1",
    source_commit: "b".repeat(40), release_checks_passed: true, sponsor_delay_hours: 0,
    required_assets: [{ name: "libarchive_amd64.deb", sha256: "a".repeat(64), r2_key: `staging/pilot/${"a".repeat(64)}` }],
  };
  const bucket = new MemorySnapshotBucket({ "release-state/pilot.json": release });
  const env = { RELEASES: bucket };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => String(url).includes("/.well-known/jwks") ? Response.json({ keys: [jwk] }) : Response.json({});
  const snapshotClaims = {
    workflow_ref: "apt-to/platform/.github/workflows/repository-snapshot.yml@refs/heads/main",
    event_name: "workflow_dispatch",
  };
  const authorization = `Bearer ${signedOidcToken(privateKey, snapshotClaims, privateKey, keyId)}`;
  const stagingAuthorization = `Bearer ${signedOidcToken(privateKey, {}, privateKey, keyId)}`;
  const contents = new Map([
    ["dists/focal/Release", "Origin: AptTo\nSuite: focal\n"],
    ["dists/focal/InRelease", "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nOrigin: AptTo\n"],
    ["dists/focal/Release.gpg", "-----BEGIN PGP SIGNATURE-----\nvalid test fixture\n-----END PGP SIGNATURE-----\n"],
    ["dists/focal/main/binary-amd64/Packages", "Package: libarchive\nVersion: 3.4.0-2ubuntu1.5+aptto1\n"],
    ["dists/focal/main/binary-amd64/Packages.gz", "gzip fixture"],
    ["dists/focal/main/binary-amd64/Packages.xz", "xz fixture"],
    ["dists/focal/main/source/Sources", "Package: libarchive\n"],
    ["dists/focal/main/source/Sources.gz", "gzip source fixture"],
    ["dists/focal/main/source/Sources.xz", "xz source fixture"],
    ["aptto-archive-keyring.gpg", "public key fixture"],
  ]);
  const files = [...contents].map(([path, content]) => ({ path, size: Buffer.byteLength(content), sha256: createHash("sha256").update(content).digest("hex") }));
  try {
    const request = (url, method, body) => new Request(url, {
      method, headers: { authorization, ...(body === undefined ? {} : { "content-length": String(Buffer.byteLength(body)) }) }, body,
    });
    const stagingRequest = (url, method, body) => new Request(url, {
      method, headers: { authorization: stagingAuthorization, ...(body === undefined ? {} : { "content-length": String(Buffer.byteLength(body)) }) }, body,
    });
    const stagingRegistration = await gateway.fetch(stagingRequest("https://repo.apt.to/internal/repository-snapshots/public", "POST", JSON.stringify({ id: "staging-cannot-publish", release_ids: ["pilot"], files })), env);
    assert.equal(stagingRegistration.status, 401, "the artifact staging workflow cannot register repository metadata");
    const registration = await gateway.fetch(request("https://repo.apt.to/internal/repository-snapshots/public", "POST", JSON.stringify({ id: "focal-snapshot-001", release_ids: ["pilot"], files })), env);
    assert.equal(registration.status, 201);
    const replay = await gateway.fetch(request("https://repo.apt.to/internal/repository-snapshots/public", "POST", JSON.stringify({ id: "focal-snapshot-001", release_ids: ["pilot"], files })), env);
    assert.equal(replay.status, 200, "repeated registration of the same immutable manifest is safe");
    bucket.entries.set("release-state/gated.json", {
      value: { ...release, id: "gated", state: "sponsor-period", repository: "apt-to/packaging-libxml2", tag: "aptto/2.9.10+dfsg-5ubuntu0.20.04.10+aptto1", sponsor_delay_hours: 168, sponsor_publication_complete: true, public_after: new Date(Date.now() + 86400000).toISOString() },
      etag: "gated-release",
    });
    const prematurePublic = await gateway.fetch(request("https://repo.apt.to/internal/repository-snapshots/public", "POST", JSON.stringify({ id: "focal-snapshot-gated", release_ids: ["gated"], files })), env);
    assert.equal(prematurePublic.status, 409, "a seven-day release cannot enter the anonymous public index before promotion");
    const beforeUpload = await gateway.fetch(request("https://repo.apt.to/internal/repository-snapshots/public/focal-snapshot-001/activate", "POST", "{}"), env);
    assert.equal(beforeUpload.status, 409);
    for (const [path, content] of contents) {
      const result = await gateway.fetch(request(`https://repo.apt.to/internal/repository-snapshots/public/focal-snapshot-001/files/${path}`, "PUT", content), env);
      assert.equal(result.status, 201, path);
    }
    const stagingUpload = await gateway.fetch(stagingRequest("https://repo.apt.to/internal/repository-snapshots/public/focal-snapshot-001/files/dists/focal/Release", "PUT", contents.get("dists/focal/Release")), env);
    assert.equal(stagingUpload.status, 401, "the artifact staging workflow cannot write repository metadata");
    const stagingActivation = await gateway.fetch(stagingRequest("https://repo.apt.to/internal/repository-snapshots/public/focal-snapshot-001/activate", "POST", "{}"), env);
    assert.equal(stagingActivation.status, 401, "the artifact staging workflow cannot activate repository metadata");
    const activated = await gateway.fetch(request("https://repo.apt.to/internal/repository-snapshots/public/focal-snapshot-001/activate", "POST", "{}"), env);
    assert.equal(activated.status, 201);
    const served = await gateway.fetch(new Request("https://repo.apt.to/dists/focal/InRelease"), env);
    assert.equal(served.status, 200);
    assert.equal(await served.text(), contents.get("dists/focal/InRelease"));
    assert.equal(served.headers.get("cache-control"), "public, max-age=300");
    const keyring = await gateway.fetch(new Request("https://early.apt.to/aptto-archive-keyring.gpg"), env);
    assert.equal(keyring.status, 200, "the public trust anchor remains anonymously available");
    const privateIndex = await gateway.fetch(new Request("https://early.apt.to/dists/focal/InRelease"), env);
    assert.equal(privateIndex.status, 401);
    assert.equal(privateIndex.headers.get("cache-control"), "private, no-store");
    assert.equal((await gateway.fetch(new Request("https://repo.apt.to/dists/focal/unknown"), env)).status, 404);

    const earlyRegistration = await gateway.fetch(request("https://repo.apt.to/internal/repository-snapshots/early", "POST", JSON.stringify({ id: "focal-early-001", release_ids: ["gated"], files })), env);
    assert.equal(earlyRegistration.status, 201);
    for (const [path, content] of contents) {
      const result = await gateway.fetch(request(`https://repo.apt.to/internal/repository-snapshots/early/focal-early-001/files/${path}`, "PUT", content), env);
      assert.equal(result.status, 201, path);
    }
    const expiredRelease = bucket.entries.get("release-state/gated.json");
    expiredRelease.value.public_after = new Date(Date.now() - 1000).toISOString();
    bucket.entries.set("release-state/gated.json", expiredRelease);
    const expiredActivation = await gateway.fetch(request("https://repo.apt.to/internal/repository-snapshots/early/focal-early-001/activate", "POST", "{}"), env);
    assert.equal(expiredActivation.status, 409, "an early snapshot cannot activate after a gated release reaches its public deadline");
  } finally { globalThis.fetch = originalFetch; }
});

test("GitHub OAuth login issues hashed per-device APT credentials that can be listed and revoked", async () => {
  const bucket = new MemoryBucket();
  const env = { RELEASES: bucket, PUBLIC_ORIGIN: "https://apt.to", GITHUB_OAUTH_CLIENT_ID: "client-id", GITHUB_OAUTH_CLIENT_SECRET: "test-client-secret" };
  const login = await gateway.fetch(new Request("https://apt.to/auth/github"), env);
  assert.equal(login.status, 302);
  const authorization = new URL(login.headers.get("location"));
  assert.equal(authorization.searchParams.get("scope"), "read:user");
  assert.equal(authorization.searchParams.get("code_challenge_method"), "S256");
  assert.match(authorization.searchParams.get("code_challenge"), /^[A-Za-z0-9_-]{43}$/);
  const state = authorization.searchParams.get("state");
  const stateCookie = login.headers.get("set-cookie").match(/aptto_oauth_state=([^;,]+)/)[1];
  assert.equal(decodeURIComponent(stateCookie), state);

  const now = new Date();
  bucket.entries.set("sponsor-entitlements/current.json", {
    value: {
      organization: "apt-to", authority: "github-sponsors-graphql-active-only",
      sponsors: [{ github_user_id: 17, tier_ids: ["tier-early"] }],
      reconciled_at: now.toISOString(), valid_until: new Date(now.getTime() + 1800000).toISOString(),
    }, etag: "snapshot",
  });
  const originalFetch = globalThis.fetch;
  let oauthCalls = 0;
  let submittedVerifier;
  globalThis.fetch = async (url, options) => {
    oauthCalls += 1;
    if (String(url).includes("login/oauth/access_token")) {
      submittedVerifier = JSON.parse(options.body).code_verifier;
      return Response.json({ access_token: "transient-oauth-secret", scope: "read:user" });
    }
    if (String(url) === "https://api.github.com/user") return Response.json({ id: 17, login: "alice" });
    throw new Error("unexpected test URL");
  };
  try {
    const callback = await gateway.fetch(new Request(`https://apt.to/auth/github/callback?code=one-time-code&state=${state}`, {
      headers: { cookie: `aptto_oauth_state=${stateCookie}` },
    }), env);
    assert.equal(callback.status, 302);
    assert.equal(callback.headers.get("location"), "https://apt.to/account");
    const callbackCookies = callback.headers.getSetCookie();
    assert.equal(callbackCookies.length, 2);
    const sessionCookie = callbackCookies.find((cookie) => cookie.startsWith("aptto_session=")).match(/aptto_session=([^;,]+)/)[1];
    const stateRecord = await bucket.get(`oauth-states/${createHash("sha256").update(state).digest("hex")}.json`);
    const consumedState = await stateRecord.json();
    assert.equal(consumedState.code_verifier, null);
    assert.ok(consumedState.consumed_at);
    assert.equal(oauthCalls, 2);
    assert.match(submittedVerifier, /^[a-f0-9]{96}$/);

    const tokenResponse = await gateway.fetch(new Request("https://apt.to/api/device-tokens", {
      method: "POST", headers: { origin: "https://apt.to", cookie: `aptto_session=${sessionCookie}`, "content-type": "application/json" },
      body: JSON.stringify({ label: "workstation" }),
    }), env);
    assert.equal(tokenResponse.status, 201);
    const issued = await tokenResponse.json();
    assert.match(issued.token, /^aptto_[a-f0-9]{64}$/);
    const tokenHash = createHash("sha256").update(issued.token).digest("hex");
    assert.ok(bucket.entries.has(`apt-device-tokens/${tokenHash}.json`));
    assert.equal(JSON.stringify([...bucket.entries.values()]).includes(issued.token), false);
    assert.equal(JSON.stringify([...bucket.entries.values()]).includes("transient-oauth-secret"), false);

    const listed = await gateway.fetch(new Request("https://apt.to/api/device-tokens", {
      headers: { cookie: `aptto_session=${sessionCookie}` },
    }), env);
    assert.equal((await listed.json()).devices.length, 1);
    const revoked = await gateway.fetch(new Request(`https://apt.to/api/device-tokens/${tokenHash}/revoke`, {
      method: "POST", headers: { origin: "https://apt.to", cookie: `aptto_session=${sessionCookie}` },
    }), env);
    assert.equal(revoked.status, 200);
    const listedAfterRevoke = await gateway.fetch(new Request("https://apt.to/api/device-tokens", {
      headers: { cookie: `aptto_session=${sessionCookie}` },
    }), env);
    assert.ok((await listedAfterRevoke.json()).devices[0].revoked_at);

    const loggedOut = await gateway.fetch(new Request("https://apt.to/api/logout", {
      method: "POST", headers: { origin: "https://apt.to", cookie: `aptto_session=${sessionCookie}` },
    }), env);
    assert.equal(loggedOut.status, 204);
    const afterLogout = await gateway.fetch(new Request("https://apt.to/api/device-tokens", {
      headers: { cookie: `aptto_session=${sessionCookie}` },
    }), env);
    assert.equal(afterLogout.status, 401);

    const replay = await gateway.fetch(new Request(`https://apt.to/auth/github/callback?code=one-time-code&state=${state}`, {
      headers: { cookie: `aptto_oauth_state=${stateCookie}` },
    }), env);
    assert.equal(replay.status, 400);
    assert.equal(oauthCalls, 2);
  } finally { globalThis.fetch = originalFetch; }
});

test("account status requires a valid session and fails closed when sponsor data is stale", async () => {
  const session = "session-for-account-test";
  const sessionHash = createHash("sha256").update(session).digest("hex");
  const now = new Date();
  const bucket = new MemoryBucket({
    [`apt-sessions/${sessionHash}.json`]: {
      github_user_id: 17, github_login: "alice", expires_at: new Date(now.getTime() + 3600000).toISOString(),
    },
    "sponsor-entitlements/current.json": {
      organization: "apt-to", authority: "github-sponsors-graphql-active-only",
      sponsors: [{ github_user_id: 17 }], valid_until: new Date(now.getTime() + 1800000).toISOString(),
    },
  });
  const anonymous = await gateway.fetch(new Request("https://apt.to/api/me"), { RELEASES: bucket });
  assert.equal(anonymous.status, 401);

  const statusRequest = () => new Request("https://apt.to/api/me", { headers: { cookie: `aptto_session=${session}` } });
  const eligible = await gateway.fetch(statusRequest(), { RELEASES: bucket });
  assert.deepEqual(await eligible.json(), {
    github_login: "alice", sponsorship: "eligible", snapshot_valid_until: new Date(now.getTime() + 1800000).toISOString(),
  });

  const snapshot = bucket.entries.get("sponsor-entitlements/current.json");
  snapshot.value = { ...snapshot.value, valid_until: new Date(now.getTime() - 1).toISOString() };
  const stale = await gateway.fetch(statusRequest(), { RELEASES: bucket });
  assert.equal((await stale.json()).sponsorship, "unavailable");
});

test("Worker serves the account shell through its static assets binding and keeps unknown APIs private", async () => {
  const requested = [];
  const env = { ASSETS: { fetch: async (request) => {
    requested.push(new URL(request.url).pathname);
    return new Response("static", { status: 200 });
  } } };
  const account = await gateway.fetch(new Request("https://apt.to/account"), env);
  assert.equal(account.status, 200);
  assert.deepEqual(requested, ["/account.html"]);
  const home = await gateway.fetch(new Request("https://apt.to/"), env);
  assert.equal(home.status, 200);
  assert.deepEqual(requested, ["/account.html", "/"]);
  const missingApi = await gateway.fetch(new Request("https://apt.to/api/private"), env);
  assert.equal(missingApi.status, 404);
  assert.deepEqual(requested, ["/account.html", "/"]);
});

test("sponsorship cancellation webhook verifies signature and records delivery idempotently without granting or revoking access", async () => {
  const bucket = new MemoryBucket();
  const payload = JSON.stringify({ action: "cancelled", sponsorship: { sponsor: { id: 42 } } });
  const signature = `sha256=${createHmac("sha256", "webhook-secret").update(payload).digest("hex")}`;
  const makeRequest = (sig = signature) => new Request("https://worker.test/webhooks/github/sponsorship", {
    method: "POST",
    headers: { "x-github-event": "sponsorship", "x-github-delivery": "12345678-1234-1234-1234-123456789abc", "x-hub-signature-256": sig },
    body: payload,
  });
  const env = { SPONSOR_WEBHOOK_SECRET: "webhook-secret", RELEASES: bucket };
  assert.equal((await gateway.fetch(makeRequest("sha256=" + "0".repeat(64)), env)).status, 401);
  const accepted = await gateway.fetch(makeRequest(), env);
  assert.equal(accepted.status, 202);
  assert.equal((await accepted.json()).reconciliation_required, true);
  const duplicate = await gateway.fetch(makeRequest(), env);
  assert.equal((await duplicate.json()).duplicate, true);
  const event = await bucket.get("sponsor-deliveries/12345678-1234-1234-1234-123456789abc.json");
  assert.deepEqual(await event.json(), {
    delivery_id: "12345678-1234-1234-1234-123456789abc",
    action: "cancelled",
    sponsor_id: 42,
    received_at: (await event.json()).received_at,
    effect: "reconciliation-required",
  });
});

test("deadline parser requires an explicit timezone", () => {
  assert.equal(parseUtc("2026-11-01T14:00:00Z").toISOString(), "2026-11-01T14:00:00.000Z");
  assert.throws(() => parseUtc("2026-11-01T14:00:00"), /UTC offset/);
});

test("release gate requires the named successful package job and exact tested source commit", async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  let displayTitle = `Verify libxml2 at ${"b".repeat(40)}`;
  let signerLogin = TEST_RELEASE_TAG_SIGNER;
  let annotatedSha = "d".repeat(40);
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
    if (String(url).endsWith("/graphql")) return Response.json({ data: { repository: { object: {
      __typename: "Tag", oid: "d".repeat(40), name: "aptto/1.2.3",
      tagger: { email: "releases@apt.to", user: { login: signerLogin } },
    } } } });
    if (String(url).includes("/compare/aptto%2Ffocal...")) {
      return Response.json({ merge_base_commit: { sha: "b".repeat(40) } });
    }
    return Response.json({ sha: annotatedSha, verification: { verified: true, reason: "valid" }, tagger: { email: "releases@apt.to" }, object: { type: "commit", sha: "b".repeat(40) } });
  };
  try {
    const verified = await verifyPackageRun(
      { GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", APTTO_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER },
      "apt-to/packaging-libxml2", "b".repeat(40), "aptto/1.2.3", 456,
    );
    assert.equal(verified.job_id, 9);
    assert.equal(verified.run_id, 456);
    assert.equal(calls.length, 6);
    annotatedSha = "e".repeat(40);
    await assert.rejects(
      verifyPackageRun({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", APTTO_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER }, "apt-to/packaging-libxml2", "b".repeat(40), "aptto/1.2.3", 456),
      /signed package tag must verify/,
    );
    annotatedSha = "d".repeat(40);
    signerLogin = "unexpected-maintainer";
    await assert.rejects(
      verifyPackageRun({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", APTTO_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER }, "apt-to/packaging-libxml2", "b".repeat(40), "aptto/1.2.3", 456),
      /configured GitHub account/,
    );
    signerLogin = TEST_RELEASE_TAG_SIGNER;
    const savedLogin = signerLogin;
    signerLogin = null;
    await assert.rejects(
      verifyPackageRun({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", APTTO_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER }, "apt-to/packaging-libxml2", "b".repeat(40), "aptto/1.2.3", 456),
      /configured GitHub account/,
    );
    signerLogin = savedLogin;
    displayTitle = `Verify all at ${"b".repeat(40)}`;
    await assert.rejects(
      verifyPackageRun({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", APTTO_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER }, "apt-to/packaging-libxml2", "b".repeat(40), "aptto/1.2.3", 456),
      /successful package-verification dispatch/,
    );
    displayTitle = `Verify libxml2 at ${"b".repeat(40)}`;
    await assert.rejects(
      verifyPackageRun({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", APTTO_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER }, "apt-to/packaging-libxml2", "a".repeat(40), "aptto/1.2.3", 456),
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
    return Response.json({ sha: "d".repeat(40), verification: { verified: true, reason: "valid" }, object: { type: "commit", sha: "e".repeat(40) } });
  };
  try {
    await assert.rejects(
      verifySignedSourceTag({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", APTTO_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER }, "apt-to/packaging-libxml2", "aptto/1.2.3", "b".repeat(40)),
      /point to the tested source commit/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("release-tag verification fails closed without the approved signer account", async () => {
  const originalFetch = globalThis.fetch;
  let requests = 0;
  globalThis.fetch = async () => { requests += 1; return Response.json({}); };
  try {
    await assert.rejects(
      verifySignedSourceTag({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only" }, "apt-to/packaging-libxml2", "aptto/1.2.3", "b".repeat(40)),
      /allowed GitHub release-tag signer is not configured/,
    );
    assert.equal(requests, 0);
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
    if (String(url).endsWith("/graphql")) return Response.json({ data: { repository: { object: {
      __typename: "Tag", oid: "d".repeat(40), name: "aptto/1.2.3",
      tagger: { email: "releases@apt.to", user: { login: TEST_RELEASE_TAG_SIGNER } },
    } } } });
    if (String(url).includes("/git/tags/")) {
      return Response.json({ sha: "d".repeat(40), verification: { verified: true, reason: "valid" }, tagger: { email: "releases@apt.to" }, object: { type: "commit", sha: "b".repeat(40) } });
    }
    return Response.json({ merge_base_commit: { sha: "e".repeat(40) } });
  };
  try {
    await assert.rejects(
      verifySignedSourceTag({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", APTTO_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER }, "apt-to/packaging-libxml2", "aptto/1.2.3", "b".repeat(40)),
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
      sponsor_delay_hours: 168,
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

test("scheduled reconciliation promotes a due sponsor release after missed runs", async () => {
  const bytes = Buffer.from("verified sponsor package bytes");
  const digest = createHash("sha256").update(bytes).digest("hex");
  const deadline = new Date("2026-10-01T12:00:00.000Z");
  const key = "release-state/pilot.json";
  const bucket = new MemoryBucket({ [key]: {
    id: "pilot", state: "sponsor-period", repository: "apt-to/packaging-libxml2", tag: "aptto/2.9.10-aptto1",
    source_commit: "b".repeat(40), release_checks_passed: true, sponsor_delay_hours: 168,
    sponsor_publication_complete: true, public_after: deadline.toISOString(),
    required_assets: [{ name: "libxml2_amd64.deb", sha256: digest, r2_key: `staging/pilot/${digest}` }],
  } });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const target = new URL(String(url));
    if (target.pathname.includes("/git/ref/tags/")) {
      return Response.json({ ref: "refs/tags/aptto/2.9.10-aptto1", object: { type: "tag", sha: "d".repeat(40) } });
    }
    if (target.pathname === "/graphql") return Response.json({ data: { repository: { object: {
      __typename: "Tag", oid: "d".repeat(40), name: "aptto/2.9.10-aptto1",
      tagger: { email: "releases@apt.to", user: { login: TEST_RELEASE_TAG_SIGNER } },
    } } } });
    if (target.pathname.includes("/git/tags/")) {
      return Response.json({ sha: "d".repeat(40), verification: { verified: true, reason: "valid" }, tagger: { email: "releases@apt.to" }, object: { type: "commit", sha: "b".repeat(40) } });
    }
    if (target.pathname.includes("/compare/aptto%2Ffocal...")) return Response.json({ merge_base_commit: { sha: "b".repeat(40) } });
    if (target.pathname.includes("/releases/tags/")) {
      return Response.json({ id: 901, tag_name: "aptto/2.9.10-aptto1", draft: false, immutable: true, assets: [{ name: "libxml2_amd64.deb" }] });
    }
    if (target.pathname.endsWith("/releases/901/assets")) {
      return Response.json([{ name: "libxml2_amd64.deb", url: "https://api.github.com/assets/libxml2_amd64.deb" }]);
    }
    if (target.pathname === "/assets/libxml2_amd64.deb") return new Response(bytes);
    return Response.json({});
  };
  try {
    const failures = await reconcile({ RELEASES: bucket, GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", APTTO_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER }, new Date("2026-10-10T12:00:00.000Z"));
    assert.deepEqual(failures, []);
    const saved = await (await bucket.get(key)).json();
    assert.equal(saved.state, "public");
    assert.equal(saved.public_release_id, 901);
    assert.equal(saved.public_published_at, "2026-10-10T12:00:00.000Z");
    assert.deepEqual(saved.verified_assets, [{ name: "libxml2_amd64.deb", sha256: digest, r2_key: `staging/pilot/${digest}` }]);
  } finally { globalThis.fetch = originalFetch; }
});

test("zero-hour package publication is authenticated and completes synchronously", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: "immediate-release-test", use: "sig", alg: "RS256" };
  const bytes = Buffer.from("public package bytes");
  const digest = createHash("sha256").update(bytes).digest();
  const release = {
    id: "pilot", state: "prepared", repository: "apt-to/packaging-libarchive", tag: "aptto/1.2.3",
    source_commit: "b".repeat(40), staging_run_id: 40210000000, sponsor_delay_hours: 0, release_checks_passed: true,
    required_assets: [{ name: "libarchive.deb", sha256: digest.toString("hex"), r2_key: `staging/pilot/${digest.toString("hex")}` }],
    source_assets: [{ name: "libarchive_1.2.3.dsc", sha256: createHash("sha256").update("source").digest("hex"), r2_key: `staging/pilot/source/${createHash("sha256").update("source").digest("hex")}` }],
  };
  const bucket = new MemoryAssetBucket(release);
  bucket.assets.set(release.required_assets[0].r2_key, {
    size: bytes.length,
    checksums: { sha256: digest.buffer.slice(digest.byteOffset, digest.byteOffset + digest.byteLength) },
    customMetadata: { releaseId: "pilot", assetName: "libarchive.deb" },
    httpMetadata: { contentType: "application/vnd.debian.binary-package" },
    bytes,
  });
  const sourceDigest = createHash("sha256").update("source").digest();
  bucket.assets.set(release.source_assets[0].r2_key, { size: 1, checksums: { sha256: sourceDigest.buffer.slice(sourceDigest.byteOffset, sourceDigest.byteOffset + sourceDigest.byteLength) }, customMetadata: { releaseId: "pilot", assetName: "libarchive_1.2.3.dsc", assetKind: "source" }, bytes: Buffer.from("source") });
  const publishedAssets = new Map();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options = {}) => {
    const target = new URL(String(url));
    if (target.pathname === "/.well-known/jwks") return Response.json({ keys: [jwk] });
    if (target.pathname.endsWith("/git/ref/tags/aptto/1.2.3")) {
      return Response.json({ ref: "refs/tags/aptto/1.2.3", object: { type: "tag", sha: "d".repeat(40) } });
    }
    if (target.pathname === "/graphql") return Response.json({ data: { repository: { object: {
      __typename: "Tag", oid: "d".repeat(40), name: "aptto/1.2.3",
      tagger: { email: "releases@apt.to", user: { login: TEST_RELEASE_TAG_SIGNER } },
    } } } });
    if (target.pathname.includes("/git/tags/")) {
      return Response.json({ sha: "d".repeat(40), verification: { verified: true, reason: "valid" }, tagger: { email: "releases@apt.to" }, object: { type: "commit", sha: "b".repeat(40) } });
    }
    if (target.pathname.includes("/compare/aptto%2Ffocal...")) return Response.json({ merge_base_commit: { sha: "b".repeat(40) } });
    if (target.pathname.endsWith("/releases/tags/aptto%2F1.2.3")) return new Response("not found", { status: 404 });
    if (target.pathname.endsWith("/releases/tags/aptto-source%2F1.2.3")) return new Response("not found", { status: 404 });
    if (target.pathname.includes("/releases/tags/")) return new Response("not found", { status: 404 });
    if (target.hostname === "uploads.github.com") {
      const name = target.searchParams.get("name");
      publishedAssets.set(name, Buffer.from(await new Response(options.body).arrayBuffer()));
      return Response.json({ name }, { status: 201 });
    }
    if (target.pathname.endsWith("/releases/901/assets")) {
      return Response.json([...publishedAssets].map(([name]) => ({ name, url: `https://api.github.com/assets/${name}` })));
    }
    if (target.pathname.endsWith("/releases/901")) return Response.json({ id: 901, tag_name: "aptto-source/1.2.3", draft: false, immutable: true, assets: [...publishedAssets.keys()].map((name) => ({ name })) });
    if (target.pathname.startsWith("/assets/")) {
      const asset = publishedAssets.get(decodeURIComponent(target.pathname.slice("/assets/".length)));
      return asset ? new Response(asset) : new Response("missing", { status: 404 });
    }
    if (target.pathname.endsWith("/immutable-releases")) return Response.json({ enabled: true });
    if (target.pathname.endsWith("/releases/901") && options.method === "PATCH") {
      return Response.json({ id: 901, tag_name: "aptto/1.2.3", draft: false, immutable: true, assets: [...publishedAssets.keys()].map((name) => ({ name })) });
    }
    if (target.pathname.endsWith("/releases") && options.method === "POST") {
      return Response.json({
        id: 901, tag_name: JSON.parse(options.body).tag_name, draft: true, assets: [], owner: { login: "apt-to" }, name: "packaging-libarchive",
        upload_url: "https://uploads.github.com/repos/apt-to/packaging-libarchive/releases/901/assets{?name,label}",
      });
    }
    return Response.json({});
  };
  try {
    const url = "https://apt.to/internal/releases/pilot/publish-now";
    assert.equal((await gateway.fetch(new Request(url, { method: "POST" }), { RELEASES: bucket })).status, 401);
    const token = signedOidcToken(privateKey, {}, privateKey, "immediate-release-test");
    const sourceResponse = await gateway.fetch(new Request("https://apt.to/internal/releases/pilot/publish-sources", {
      method: "POST", headers: { authorization: `Bearer ${token}` },
    }), { RELEASES: bucket, GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", APTTO_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER });
    assert.equal(sourceResponse.status, 200, await sourceResponse.clone().text());
    const response = await gateway.fetch(new Request(url, {
      method: "POST", headers: { authorization: `Bearer ${token}` },
    }), { RELEASES: bucket, GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", APTTO_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER });
    assert.equal(response.status, 200, await response.clone().text());
    const saved = await (await bucket.get("release-state/pilot.json")).json();
    assert.deepEqual(await response.json(), { id: "pilot", state: "public", source_release_tag: "aptto-source/1.2.3", public_published_at: saved.public_published_at });
    assert.deepEqual(publishedAssets.get("libarchive.deb"), bytes);
    assert.equal(saved.state, "public");

    const gatedRecord = { ...release, sponsor_delay_hours: 168, required_assets: [] };
    const gatedBucket = new MemoryAssetBucket(gatedRecord);
    const gatedResponse = await gateway.fetch(new Request("https://apt.to/internal/releases/pilot/publish-now", {
      method: "POST", headers: { authorization: `Bearer ${token}` },
    }), { RELEASES: gatedBucket });
    assert.equal(gatedResponse.status, 409);
    assert.equal((await (await gatedBucket.get("release-state/pilot.json")).json()).state, "prepared");
  } finally { globalThis.fetch = originalFetch; }
});
