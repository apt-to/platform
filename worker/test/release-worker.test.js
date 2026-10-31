import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac, generateKeyPairSync, sign as signJwt } from "node:crypto";
import gateway, { beginSponsorPublication, canonicalAssets, fetchSponsorSnapshot, githubActionsIdentity, hasActiveSponsorship, parseUtc, publishOne, readFreshSponsorSnapshot, reconcile, reconcileSponsors, releaseAssets, requireImmutableReleasesEnabled, updateState, verifyGithubSignature, verifyPackageRun, verifySignedSourceTag } from "../src/index.js";

const TEST_RELEASE_TAG_SIGNER = "getpatched-release-maintainer";

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

class MemoryR2SelfTestBucket {
  constructor({ tamperRead = false, collide = false } = {}) {
    this.objects = new Map();
    this.tamperRead = tamperRead;
    this.collide = collide;
  }
  async put(key, body, options) {
    if (this.collide) {
      this.objects.set(key, {
        size: 8,
        checksums: { sha256: new Uint8Array(32).buffer },
        customMetadata: { purpose: "unrelated-object", nonce: "another-writer" },
        bytes: new TextEncoder().encode("occupied"),
      });
      return null;
    }
    if (options.onlyIf.etagDoesNotMatch === "*" && this.objects.has(key)) return null;
    const bytes = Uint8Array.from(body);
    const metadata = {
      size: bytes.byteLength,
      checksums: { sha256: options.sha256 },
      customMetadata: options.customMetadata,
      httpMetadata: options.httpMetadata,
    };
    this.objects.set(key, { ...metadata, bytes });
    return metadata;
  }
  async head(key) {
    const object = this.objects.get(key);
    if (!object) return null;
    const { bytes, ...metadata } = object;
    return metadata;
  }
  async get(key) {
    const object = this.objects.get(key);
    if (!object) return null;
    let bytes = object.bytes;
    if (this.tamperRead) bytes = Uint8Array.from([...bytes].map((byte, index) => index === 0 ? byte ^ 1 : byte));
    return { ...object, arrayBuffer: async () => bytes.slice().buffer };
  }
  async delete(key) { this.objects.delete(key); }
}

function signedOidcToken(privateKey, overrides = {}, signatureKey = privateKey, keyId = "test-key") {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: keyId })).toString("base64url");
  const now = Math.floor(Date.now() / 1000);
  const claims = Buffer.from(JSON.stringify({
    iss: "https://token.actions.githubusercontent.com", aud: "getpatched-release-gateway",
    exp: now + 120, iat: now, nbf: now - 1, jti: "test-jti-12345678",
    repository: "getpatched/platform", repository_id: "1433070541", repository_owner: "getpatched",
    repository_visibility: "public", event_name: "workflow_run", ref: "refs/heads/main",
    workflow_ref: "getpatched/platform/.github/workflows/private-staging.yml@refs/heads/main",
    runner_environment: "github-hosted", environment: "getpatched-signing", run_id: "40210000000", run_attempt: 1,
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
      headers: { authorization: `Bearer ${signedOidcToken(privateKey, { run_attempt: "1" })}` },
    }), {});
    assert.deepEqual(identity, { type: "github-actions", run_id: 40210000000, run_attempt: 1, environment: "getpatched-signing", workflow: "private-staging" });
    const r2Identity = await githubActionsIdentity(new Request("https://worker.test", {
      headers: { authorization: `Bearer ${signedOidcToken(privateKey, {
        workflow_ref: "getpatched/platform/.github/workflows/r2-storage-self-test.yml@refs/heads/main",
        event_name: "workflow_dispatch", environment: "getpatched-index-build",
      })}` },
    }), {});
    assert.deepEqual(r2Identity, { type: "github-actions", run_id: 40210000000, run_attempt: 1, environment: "getpatched-index-build", workflow: "r2-storage-self-test" });
    const r2WrongEnvironment = signedOidcToken(privateKey, {
      workflow_ref: "getpatched/platform/.github/workflows/r2-storage-self-test.yml@refs/heads/main",
      event_name: "workflow_dispatch", environment: "getpatched-signing",
    });
    assert.equal(await githubActionsIdentity(new Request("https://worker.test", { headers: { authorization: `Bearer ${r2WrongEnvironment}` } }), {}), null);
    const r2WrongEvent = signedOidcToken(privateKey, {
      workflow_ref: "getpatched/platform/.github/workflows/r2-storage-self-test.yml@refs/heads/main",
      event_name: "schedule", environment: "getpatched-index-build",
    });
    assert.equal(await githubActionsIdentity(new Request("https://worker.test", { headers: { authorization: `Bearer ${r2WrongEvent}` } }), {}), null);
    const wrongEnvironment = signedOidcToken(privateKey, { environment: "unprotected" });
    assert.equal(await githubActionsIdentity(new Request("https://worker.test", { headers: { authorization: `Bearer ${wrongEnvironment}` } }), {}), null);
    const missingEnvironment = signedOidcToken(privateKey, { environment: undefined });
    assert.equal(await githubActionsIdentity(new Request("https://worker.test", { headers: { authorization: `Bearer ${missingEnvironment}` } }), {}), null);
    const wrongWorkflow = signedOidcToken(privateKey, { workflow_ref: "getpatched/platform/.github/workflows/package-verification.yml@refs/heads/main" });
    assert.equal(await githubActionsIdentity(new Request("https://worker.test", { headers: { authorization: `Bearer ${wrongWorkflow}` } }), {}), null);
    const wrongAudience = signedOidcToken(privateKey, { aud: "other-service" });
    assert.equal(await githubActionsIdentity(new Request("https://worker.test", { headers: { authorization: `Bearer ${wrongAudience}` } }), {}), null);
    const { privateKey: attackerKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const forged = signedOidcToken(privateKey, {}, attackerKey);
    assert.equal(await githubActionsIdentity(new Request("https://worker.test", { headers: { authorization: `Bearer ${forged}` } }), {}), null);
  } finally { globalThis.fetch = originalFetch; }
});

test("protected R2 self-test writes, verifies and removes its uniquely scoped diagnostic object", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const keyId = "r2-self-test-oidc";
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: keyId, use: "sig", alg: "RS256" };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => String(url).includes("/.well-known/jwks") ? Response.json({ keys: [jwk] }) : Response.json({});
  const workflowClaims = {
    workflow_ref: "getpatched/platform/.github/workflows/r2-storage-self-test.yml@refs/heads/main",
    event_name: "workflow_dispatch", environment: "getpatched-index-build",
  };
  const authorization = `Bearer ${signedOidcToken(privateKey, workflowClaims, privateKey, keyId)}`;
  try {
    const bucket = new MemoryR2SelfTestBucket();
    const result = await gateway.fetch(new Request("https://repo.getpatched.dev/internal/r2-self-test", {
      method: "POST", headers: { authorization },
    }), { RELEASES: bucket });
    assert.equal(result.status, 200);
    const report = await result.json();
    assert.equal(report.ok, true);
    assert.equal(report.operation, "write-read-delete");
    assert.equal(report.run_id, 40210000000);
    assert.equal(report.cleaned, true);
    assert.match(report.sha256, /^[a-f0-9]{64}$/);
    assert.equal(bucket.objects.size, 0, "the temporary diagnostic object is deleted after readback");

    const tamperedBucket = new MemoryR2SelfTestBucket({ tamperRead: true });
    const tampered = await gateway.fetch(new Request("https://repo.getpatched.dev/internal/r2-self-test", {
      method: "POST", headers: { authorization },
    }), { RELEASES: tamperedBucket });
    assert.equal(tampered.status, 502);
    assert.equal((await tampered.json()).cleaned, true);
    assert.equal(tamperedBucket.objects.size, 0, "failed readback is still cleaned up");

    const collisionBucket = new MemoryR2SelfTestBucket({ collide: true });
    const collision = await gateway.fetch(new Request("https://repo.getpatched.dev/internal/r2-self-test", {
      method: "POST", headers: { authorization },
    }), { RELEASES: collisionBucket });
    assert.equal(collision.status, 502);
    const collisionReport = await collision.json();
    assert.equal(collisionReport.stage, "unique-write");
    assert.equal(collisionReport.cleaned, true, "a create-only collision means this self-test wrote nothing");
    assert.equal(collisionReport.object_key, null);
    assert.equal(collisionBucket.objects.size, 1, "the test never deletes an object it did not create");

    const wrongWorkflow = `Bearer ${signedOidcToken(privateKey, {
      ...workflowClaims,
      workflow_ref: "getpatched/platform/.github/workflows/package-verification.yml@refs/heads/main",
    }, privateKey, keyId)}`;
    const denied = await gateway.fetch(new Request("https://repo.getpatched.dev/internal/r2-self-test", {
      method: "POST", headers: { authorization: wrongWorkflow },
    }), { RELEASES: bucket });
    assert.equal(denied.status, 401);
    assert.equal(bucket.objects.size, 0);
    const unavailable = await gateway.fetch(new Request("https://repo.getpatched.dev/internal/r2-self-test", {
      method: "POST", headers: { authorization },
    }), {});
    assert.equal(unavailable.status, 503);
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
  const id = "libxml2-2-9-10-getpatched1";
  const objectKey = `staging/${id}/${digest}`;
  const gated = {
    id, state: "sponsor-period", repository: "getpatched/packaging-libxml2", tag: "getpatched/2.9.10-getpatched1",
    source_commit: "c".repeat(40), release_checks_passed: true, sponsor_delay_hours: 168,
    sponsor_publication_complete: true, public_after: new Date(Date.now() + 86400000).toISOString(),
    required_assets: [{ name: "libxml2_amd64.deb", sha256: digest, r2_key: objectKey }],
    source_assets: [{ name: "libxml2_2.9.10.dsc", sha256: "d".repeat(64), r2_key: `staging/${id}/source/${"d".repeat(64)}` }],
  };
  const debianId = "tiff-4-5-0-getpatched1";
  const debianRelease = {
    ...gated, id: debianId, target_id: "debian-bookworm-amd64", state: "public",
    repository: "getpatched/packaging-tiff", tag: "getpatched/4.5.0-getpatched1", sponsor_delay_hours: 0,
    sponsor_publication_complete: undefined, public_after: undefined,
    required_assets: [{ name: "libtiff-tools_amd64.deb", sha256: digest, r2_key: `staging/${debianId}/${digest}` }],
    source_assets: [{ name: "tiff_4.5.0.dsc", sha256: "e".repeat(64), r2_key: `staging/${debianId}/source/${"e".repeat(64)}` }],
  };
  const jammyId = "libgit2-jammy-public";
  const jammyRelease = {
    ...debianRelease, id: jammyId, target_id: "ubuntu-jammy-amd64",
    repository: "getpatched/packaging-libgit2", tag: "getpatched/jammy-1.1.0+getpatched1",
    required_assets: [{ name: "libgit2_amd64.deb", sha256: digest, r2_key: `staging/${jammyId}/${digest}` }],
    source_assets: [{ name: "libgit2_1.1.0.dsc", sha256: "f".repeat(64), r2_key: `staging/${jammyId}/source/${"f".repeat(64)}` }],
  };
  const bucket = new MemorySnapshotBucket({
    [`release-state/${id}.json`]: gated,
    [`release-state/${debianId}.json`]: debianRelease,
    [`release-state/${jammyId}.json`]: jammyRelease,
    "repository-current/public.json": { id: "focal-20261025T120000-r1-public" },
  });
  bucket.blobs.set(objectKey, {
    size: bytes.length,
    checksums: { sha256: createHash("sha256").update(bytes).digest() },
    customMetadata: { releaseId: id, assetName: "libxml2_amd64.deb" },
    bytes,
  });
  const env = { RELEASES: bucket };
  const workflowClaims = {
    workflow_ref: "getpatched/platform/.github/workflows/repository-snapshot.yml@refs/heads/main",
    event_name: "workflow_dispatch",
    environment: "getpatched-index-build",
  };
  const authorization = `Bearer ${signedOidcToken(privateKey, workflowClaims, privateKey, keyId)}`;
  const signerToken = `Bearer ${signedOidcToken(privateKey, { ...workflowClaims, environment: "getpatched-signing" }, privateKey, keyId)}`;
  try {
    const inventory = await gateway.fetch(new Request("https://repo.getpatched.dev/internal/repository-snapshots/early/releases", { headers: { authorization } }), env);
    assert.equal(inventory.status, 200);
    const focalInventory = await inventory.json();
    assert.deepEqual(focalInventory.releases.map((entry) => entry.id), [id]);
    assert.equal(focalInventory.suite, "focal");
    const bookwormInventoryResponse = await gateway.fetch(new Request("https://repo.getpatched.dev/internal/repository-snapshots/public/releases?suite=bookworm&architecture=amd64", { headers: { authorization } }), env);
    assert.equal(bookwormInventoryResponse.status, 200);
    const bookwormInventory = await bookwormInventoryResponse.json();
    assert.equal(bookwormInventory.suite, "bookworm");
    assert.equal(bookwormInventory.architecture, "amd64");
    assert.deepEqual(bookwormInventory.releases.map((entry) => entry.id), [debianId]);
    assert.equal(bookwormInventory.active_snapshot, null, "a Focal active pointer cannot be reported as Bookworm state");
    const jammyInventoryResponse = await gateway.fetch(new Request("https://repo.getpatched.dev/internal/repository-snapshots/public/releases?suite=jammy&architecture=amd64", { headers: { authorization } }), env);
    assert.equal(jammyInventoryResponse.status, 200);
    const jammyInventory = await jammyInventoryResponse.json();
    assert.equal(jammyInventory.suite, "jammy");
    assert.equal(jammyInventory.architecture, "amd64");
    assert.deepEqual(jammyInventory.releases.map((entry) => entry.id), [jammyId]);
    const unsupportedTarget = await gateway.fetch(new Request("https://repo.getpatched.dev/internal/repository-snapshots/public/releases?suite=bookworm&architecture=arm64", { headers: { authorization } }), env);
    assert.equal(unsupportedTarget.status, 400);
    const downloaded = await gateway.fetch(new Request(`https://repo.getpatched.dev/internal/repository-snapshots/early/releases/${id}/assets/libxml2_amd64.deb`, { headers: { authorization } }), env);
    assert.equal(downloaded.status, 200);
    assert.deepEqual(Buffer.from(await downloaded.arrayBuffer()), bytes);
    assert.equal(downloaded.headers.get("cache-control"), "private, no-store");
    const stagingToken = `Bearer ${signedOidcToken(privateKey, {}, privateKey, keyId)}`;
    const denied = await gateway.fetch(new Request("https://repo.getpatched.dev/internal/repository-snapshots/early/releases", { headers: { authorization: stagingToken } }), env);
    assert.equal(denied.status, 401);
    const signerDenied = await gateway.fetch(new Request("https://repo.getpatched.dev/internal/repository-snapshots/early/releases", { headers: { authorization: signerToken } }), env);
    assert.equal(signerDenied.status, 401, "the signing environment cannot access sponsor package bytes");

    bucket.blobs.get(objectKey).customMetadata.assetName = "unexpected.deb";
    const tampered = await gateway.fetch(new Request(`https://repo.getpatched.dev/internal/repository-snapshots/early/releases/${id}/assets/libxml2_amd64.deb`, { headers: { authorization } }), env);
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
    id: "pilot", state: "public", repository: "getpatched/packaging-libarchive", tag: "getpatched/3.4.0-2ubuntu1.5+getpatched1",
    source_commit: "b".repeat(40), release_checks_passed: true, sponsor_delay_hours: 0,
    required_assets: [{ name: "libarchive_amd64.deb", sha256: "a".repeat(64), r2_key: `staging/pilot/${"a".repeat(64)}` }],
  };
  const bucket = new MemorySnapshotBucket({ "release-state/pilot.json": release });
  const env = { RELEASES: bucket };
  const workflowRef = "getpatched/platform/.github/workflows/repository-snapshot.yml@refs/heads/main";
  const builderToken = `Bearer ${signedOidcToken(privateKey, { workflow_ref: workflowRef, event_name: "workflow_dispatch", environment: "getpatched-index-build" }, privateKey, keyId)}`;
  const signerToken = `Bearer ${signedOidcToken(privateKey, { workflow_ref: workflowRef, event_name: "workflow_dispatch", environment: "getpatched-signing" }, privateKey, keyId)}`;
  const contents = new Map([
    ["dists/focal/Release", "Origin: GetPatched\nSuite: focal\n"],
    ["dists/focal/main/binary-amd64/Packages", "Package: libarchive\n"],
    ["dists/focal/main/binary-amd64/Packages.gz", "gzip"],
    ["dists/focal/main/binary-amd64/Packages.xz", "xz"],
    ["dists/focal/main/source/Sources", "Package: libarchive\n"],
    ["dists/focal/main/source/Sources.gz", "gzip source"],
    ["dists/focal/main/source/Sources.xz", "xz source"],
  ]);
  const files = [...contents].map(([path, value]) => ({ path, size: Buffer.byteLength(value), sha256: createHash("sha256").update(value).digest("hex") }));
  const buildId = "focal-20261025T120000-r40210000000-public";
  const request = (authorization, url, method, body) => new Request(url, {
    method, headers: { authorization, ...(body === undefined ? {} : { "content-length": String(Buffer.byteLength(body)) }) }, body,
  });
  try {
    const register = await gateway.fetch(request(builderToken, "https://repo.getpatched.dev/internal/repository-snapshot-builds/public", "POST", JSON.stringify({ id: buildId, release_ids: ["pilot"], files })), env);
    assert.equal(register.status, 201);
    for (const [path, value] of contents) {
      const upload = await gateway.fetch(request(builderToken, `https://repo.getpatched.dev/internal/repository-snapshot-builds/public/${buildId}/files/${path}`, "PUT", value), env);
      assert.equal(upload.status, 201, path);
    }
    const manifest = await gateway.fetch(request(signerToken, `https://repo.getpatched.dev/internal/repository-snapshot-builds/public/${buildId}`, "GET"), env);
    assert.equal(manifest.status, 200);
    assert.equal((await manifest.json()).files.length, files.length);
    const read = await gateway.fetch(request(signerToken, `https://repo.getpatched.dev/internal/repository-snapshot-builds/public/${buildId}/files/dists/focal/Release`, "GET"), env);
    assert.equal(read.status, 200);
    assert.equal(await read.text(), contents.get("dists/focal/Release"));
    const signerWrite = await gateway.fetch(request(signerToken, `https://repo.getpatched.dev/internal/repository-snapshot-builds/public/${buildId}/files/dists/focal/Release`, "PUT", contents.get("dists/focal/Release")), env);
    assert.equal(signerWrite.status, 401);
    const builderRead = await gateway.fetch(request(builderToken, `https://repo.getpatched.dev/internal/repository-snapshot-builds/public/${buildId}`, "GET"), env);
    assert.equal(builderRead.status, 401);
    const builderActivation = await gateway.fetch(request(builderToken, `https://repo.getpatched.dev/internal/repository-snapshots/public/${buildId}/activate`, "POST", "{}"), env);
    assert.equal(builderActivation.status, 401);
    const builderRegistration = await gateway.fetch(request(builderToken, "https://repo.getpatched.dev/internal/repository-snapshots/public", "POST", JSON.stringify({ id: buildId, release_ids: ["pilot"], files })), env);
    assert.equal(builderRegistration.status, 401);
  } finally { globalThis.fetch = originalFetch; }
});

test("Bookworm snapshot builds require Bookworm indexes and retain target identity for the signer", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const keyId = "bookworm-snapshot-build-test";
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: keyId, use: "sig", alg: "RS256" };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => String(url).includes("/.well-known/jwks") ? Response.json({ keys: [jwk] }) : Response.json({});
  const release = {
    id: "debian-tiff", target_id: "debian-bookworm-amd64", state: "public",
    repository: "getpatched/packaging-tiff", tag: "getpatched/4.5.0-6+deb12u4+getpatched1",
    source_commit: "d".repeat(40), release_checks_passed: true, sponsor_delay_hours: 0,
    required_assets: [{ name: "libtiff-tools_amd64.deb", sha256: "a".repeat(64), r2_key: `staging/debian-tiff/${"a".repeat(64)}` }],
  };
  const bucket = new MemorySnapshotBucket({ "release-state/debian-tiff.json": release });
  const env = { RELEASES: bucket };
  const workflowRef = "getpatched/platform/.github/workflows/repository-snapshot.yml@refs/heads/main";
  const builderToken = `Bearer ${signedOidcToken(privateKey, { workflow_ref: workflowRef, event_name: "workflow_dispatch", environment: "getpatched-index-build" }, privateKey, keyId)}`;
  const signerToken = `Bearer ${signedOidcToken(privateKey, { workflow_ref: workflowRef, event_name: "workflow_dispatch", environment: "getpatched-signing" }, privateKey, keyId)}`;
  const contents = new Map([
    ["dists/bookworm/Release", "Origin: GetPatched\nSuite: bookworm\n"],
    ["dists/bookworm/main/binary-amd64/Packages", "Package: libtiff-tools\n"],
    ["dists/bookworm/main/binary-amd64/Packages.gz", "gzip"],
    ["dists/bookworm/main/binary-amd64/Packages.xz", "xz"],
    ["dists/bookworm/main/source/Sources", "Package: tiff\n"],
    ["dists/bookworm/main/source/Sources.gz", "gzip source"],
    ["dists/bookworm/main/source/Sources.xz", "xz source"],
  ]);
  const files = [...contents].map(([path, value]) => ({ path, size: Buffer.byteLength(value), sha256: createHash("sha256").update(value).digest("hex") }));
  const buildId = "bookworm-amd64-20261025T120000-r502-public";
  const request = (authorization, url, method, body) => new Request(url, {
    method, headers: { authorization, ...(body === undefined ? {} : { "content-length": String(Buffer.byteLength(body)) }) }, body,
  });
  try {
    const register = await gateway.fetch(request(builderToken, "https://repo.getpatched.dev/internal/repository-snapshot-builds/public", "POST",
      JSON.stringify({ id: buildId, suite: "bookworm", architecture: "amd64", release_ids: ["debian-tiff"], files })), env);
    assert.equal(register.status, 201);
    for (const [path, value] of contents) {
      const upload = await gateway.fetch(request(builderToken, `https://repo.getpatched.dev/internal/repository-snapshot-builds/public/${buildId}/files/${path}`, "PUT", value), env);
      assert.equal(upload.status, 201, path);
    }
    const wrongSuite = await gateway.fetch(request(builderToken, `https://repo.getpatched.dev/internal/repository-snapshot-builds/public/${buildId}/files/dists/focal/Release`, "PUT", "focal"), env);
    assert.equal(wrongSuite.status, 400);
    const manifestResponse = await gateway.fetch(request(signerToken, `https://repo.getpatched.dev/internal/repository-snapshot-builds/public/${buildId}`, "GET"), env);
    assert.equal(manifestResponse.status, 200);
    const manifest = await manifestResponse.json();
    assert.equal(manifest.suite, "bookworm");
    assert.equal(manifest.architecture, "amd64");
    const read = await gateway.fetch(request(signerToken, `https://repo.getpatched.dev/internal/repository-snapshot-builds/public/${buildId}/files/dists/bookworm/Release`, "GET"), env);
    assert.equal(read.status, 200);
    assert.equal(await read.text(), contents.get("dists/bookworm/Release"));
  } finally { globalThis.fetch = originalFetch; }
});

test("Jammy snapshot builds require Jammy indexes and retain target identity for the signer", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const keyId = "jammy-snapshot-build-test";
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: keyId, use: "sig", alg: "RS256" };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => String(url).includes("/.well-known/jwks") ? Response.json({ keys: [jwk] }) : Response.json({});
  const release = {
    id: "ubuntu-libgit2-jammy", target_id: "ubuntu-jammy-amd64", state: "public",
    repository: "getpatched/packaging-libgit2", tag: "getpatched/jammy-1.1.0+getpatched1",
    source_commit: "f".repeat(40), release_checks_passed: true, sponsor_delay_hours: 0,
    required_assets: [{ name: "libgit2_amd64.deb", sha256: "a".repeat(64), r2_key: `staging/ubuntu-libgit2-jammy/${"a".repeat(64)}` }],
  };
  const bucket = new MemorySnapshotBucket({ "release-state/ubuntu-libgit2-jammy.json": release });
  const env = { RELEASES: bucket };
  const workflowRef = "getpatched/platform/.github/workflows/repository-snapshot.yml@refs/heads/main";
  const builderToken = `Bearer ${signedOidcToken(privateKey, { workflow_ref: workflowRef, event_name: "workflow_dispatch", environment: "getpatched-index-build" }, privateKey, keyId)}`;
  const signerToken = `Bearer ${signedOidcToken(privateKey, { workflow_ref: workflowRef, event_name: "workflow_dispatch", environment: "getpatched-signing" }, privateKey, keyId)}`;
  const contents = new Map([
    ["dists/jammy/Release", "Origin: GetPatched\nSuite: jammy\n"],
    ["dists/jammy/main/binary-amd64/Packages", "Package: libgit2-1.1\n"],
    ["dists/jammy/main/binary-amd64/Packages.gz", "gzip"],
    ["dists/jammy/main/binary-amd64/Packages.xz", "xz"],
    ["dists/jammy/main/source/Sources", "Package: libgit2\n"],
    ["dists/jammy/main/source/Sources.gz", "gzip source"],
    ["dists/jammy/main/source/Sources.xz", "xz source"],
  ]);
  const files = [...contents].map(([path, value]) => ({ path, size: Buffer.byteLength(value), sha256: createHash("sha256").update(value).digest("hex") }));
  const buildId = "jammy-amd64-20261031T120000-r503-public";
  const request = (authorization, url, method, body) => new Request(url, {
    method, headers: { authorization, ...(body === undefined ? {} : { "content-length": String(Buffer.byteLength(body)) }) }, body,
  });
  try {
    const register = await gateway.fetch(request(builderToken, "https://repo.getpatched.dev/internal/repository-snapshot-builds/public", "POST",
      JSON.stringify({ id: buildId, suite: "jammy", architecture: "amd64", release_ids: [release.id], files })), env);
    assert.equal(register.status, 201);
    for (const [path, value] of contents) {
      const upload = await gateway.fetch(request(builderToken, `https://repo.getpatched.dev/internal/repository-snapshot-builds/public/${buildId}/files/${path}`, "PUT", value), env);
      assert.equal(upload.status, 201, path);
    }
    const wrongSuite = await gateway.fetch(request(builderToken, `https://repo.getpatched.dev/internal/repository-snapshot-builds/public/${buildId}/files/dists/focal/Release`, "PUT", "focal"), env);
    assert.equal(wrongSuite.status, 400);
    const manifestResponse = await gateway.fetch(request(signerToken, `https://repo.getpatched.dev/internal/repository-snapshot-builds/public/${buildId}`, "GET"), env);
    assert.equal(manifestResponse.status, 200);
    const manifest = await manifestResponse.json();
    assert.equal(manifest.suite, "jammy");
    assert.equal(manifest.architecture, "amd64");
    const read = await gateway.fetch(request(signerToken, `https://repo.getpatched.dev/internal/repository-snapshot-builds/public/${buildId}/files/dists/jammy/Release`, "GET"), env);
    assert.equal(read.status, 200);
    assert.equal(await read.text(), contents.get("dists/jammy/Release"));
  } finally { globalThis.fetch = originalFetch; }
});

test("public Bookworm APT paths use the Bookworm pointer and never fall back to Focal", async () => {
  const releaseId = "debian-tiff-public";
  const snapshotId = "bookworm-amd64-20261025T120000-r502-public";
  const contents = new Map([
    ["dists/bookworm/Release", "Origin: GetPatched\nSuite: bookworm\n"],
    ["dists/bookworm/InRelease", "signed bookworm metadata"],
    ["dists/bookworm/Release.gpg", "signature"],
    ["dists/bookworm/main/binary-amd64/Packages", "Package: libtiff-tools\n"],
    ["dists/bookworm/main/binary-amd64/Packages.gz", "gzip"],
    ["dists/bookworm/main/binary-amd64/Packages.xz", "xz"],
    ["dists/bookworm/main/source/Sources", "Package: tiff\n"],
    ["dists/bookworm/main/source/Sources.gz", "source gzip"],
    ["dists/bookworm/main/source/Sources.xz", "source xz"],
    ["getpatched-archive-keyring.gpg", "public key"],
  ]);
  const release = {
    id: releaseId, state: "public", target_id: "debian-bookworm-amd64", sponsor_delay_hours: 0,
    repository: "getpatched/packaging-tiff", tag: "getpatched/4.5.0-6+deb12u4+getpatched1",
    release_checks_passed: true,
    required_assets: [{ name: "libtiff-tools_amd64.deb", sha256: "a".repeat(64), r2_key: `staging/${releaseId}/${"a".repeat(64)}` }],
  };
  const files = [...contents].map(([path, value]) => ({
    path, size: Buffer.byteLength(value), sha256: createHash("sha256").update(value).digest("hex"),
  }));
  const bucket = new MemorySnapshotBucket({
    [`release-state/${releaseId}.json`]: release,
    "repository-current/public.json": { id: "focal-20261025T120000-r40210000000-public" },
    "repository-current/public/bookworm/amd64.json": { id: snapshotId },
    [`repository-snapshots/public/${snapshotId}.json`]: {
      id: snapshotId, channel: "public", suite: "bookworm", architecture: "amd64", release_ids: [releaseId], files,
    },
  });
  for (const file of files) {
    const bytes = Buffer.from(contents.get(file.path));
    const digest = createHash("sha256").update(bytes).digest();
    bucket.blobs.set(`repository-snapshots/public/${snapshotId}/${file.path}`, {
      size: bytes.length,
      checksums: { sha256: digest.buffer.slice(digest.byteOffset, digest.byteOffset + digest.byteLength) },
      customMetadata: { snapshotId, channel: "public", path: file.path },
      bytes,
    });
  }
  const env = { RELEASES: bucket };
  const served = await gateway.fetch(new Request("https://repo.getpatched.dev/dists/bookworm/Release"), env);
  assert.equal(served.status, 200, `response=${JSON.stringify(await served.clone().text())}`);
  assert.equal(await served.text(), contents.get("dists/bookworm/Release"));
  await bucket.delete("repository-current/public/bookworm/amd64.json");
  const noFallback = await gateway.fetch(new Request("https://repo.getpatched.dev/dists/bookworm/Release"), env);
  assert.equal(noFallback.status, 503, "a missing Debian pointer must not serve the active Focal snapshot");
});

test("public Jammy APT paths use the Jammy snapshot and never fall back to Focal", async () => {
  const releaseId = "ubuntu-libgit2-jammy-public";
  const snapshotId = "jammy-amd64-20261031T120000-r1-public";
  const contents = new Map([
    ["dists/jammy/Release", "Origin: GetPatched\nSuite: jammy\n"],
    ["dists/jammy/InRelease", "signed jammy metadata"],
    ["dists/jammy/Release.gpg", "signature"],
    ["dists/jammy/main/binary-amd64/Packages", "Package: libgit2-1.1\n"],
    ["dists/jammy/main/binary-amd64/Packages.gz", "gzip"],
    ["dists/jammy/main/binary-amd64/Packages.xz", "xz"],
    ["dists/jammy/main/source/Sources", "Package: libgit2\n"],
    ["dists/jammy/main/source/Sources.gz", "source gzip"],
    ["dists/jammy/main/source/Sources.xz", "source xz"],
    ["getpatched-archive-keyring.gpg", "public key"],
  ]);
  const release = {
    id: releaseId, state: "public", target_id: "ubuntu-jammy-amd64", sponsor_delay_hours: 0,
    repository: "getpatched/packaging-libgit2", tag: "getpatched/jammy-1.1.0+getpatched1",
    release_checks_passed: true,
    required_assets: [{ name: "libgit2_amd64.deb", sha256: "a".repeat(64), r2_key: `staging/${releaseId}/${"a".repeat(64)}` }],
  };
  const files = [...contents].map(([path, value]) => ({
    path, size: Buffer.byteLength(value), sha256: createHash("sha256").update(value).digest("hex"),
  }));
  const bucket = new MemorySnapshotBucket({
    [`release-state/${releaseId}.json`]: release,
    "repository-current/public.json": { id: "focal-20261025T120000-r40210000000-public" },
    "repository-current/public/jammy/amd64.json": { id: snapshotId },
    [`repository-snapshots/public/${snapshotId}.json`]: {
      id: snapshotId, channel: "public", suite: "jammy", architecture: "amd64", release_ids: [releaseId], files,
    },
  });
  for (const file of files) {
    const bytes = Buffer.from(contents.get(file.path));
    const digest = createHash("sha256").update(bytes).digest();
    bucket.blobs.set(`repository-snapshots/public/${snapshotId}/${file.path}`, {
      size: bytes.length,
      checksums: { sha256: digest.buffer.slice(digest.byteOffset, digest.byteOffset + digest.byteLength) },
      customMetadata: { snapshotId, channel: "public", path: file.path },
      bytes,
    });
  }
  const env = { RELEASES: bucket };
  const served = await gateway.fetch(new Request("https://repo.getpatched.dev/dists/jammy/Release"), env);
  assert.equal(served.status, 200, `response=${JSON.stringify(await served.clone().text())}`);
  assert.equal(await served.text(), contents.get("dists/jammy/Release"));
  await bucket.delete("repository-current/public/jammy/amd64.json");
  const noFallback = await gateway.fetch(new Request("https://repo.getpatched.dev/dists/jammy/Release"), env);
  assert.equal(noFallback.status, 503, "a missing Jammy pointer must not serve the active Focal snapshot");
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
  async list({ prefix, cursor, limit = 1000 }) { return super.list({ prefix, cursor, limit }); }
  async get(key) {
    const asset = this.assets.get(key);
    if (asset) return {
      ...asset,
      body: new Response(asset.bytes).body,
      arrayBuffer: async () => asset.bytes.buffer.slice(asset.bytes.byteOffset, asset.bytes.byteOffset + asset.bytes.byteLength),
    };
    return super.get(key);
  }
  async delete(keys) {
    for (const key of Array.isArray(keys) ? keys : [keys]) {
      this.assets.delete(key);
      this.entries.delete(key);
    }
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
  async list({ prefix = "", cursor, limit = 1000, delimiter } = {}) {
    const objectKeys = new Set([...this.entries.keys(), ...this.blobs.keys()]);
    let keys = [...objectKeys].filter((key) => key.startsWith(prefix) &&
      (!delimiter || !key.slice(prefix.length).includes(delimiter)) && (!cursor || key > cursor)).sort();
    const pageSize = Math.min(limit, this.listPageSize || limit);
    const truncated = keys.length > pageSize;
    keys = keys.slice(0, pageSize);
    return { objects: keys.map((key) => ({ key })), truncated, ...(truncated ? { cursor: keys.at(-1) } : {}) };
  }
  async get(key) {
    const object = this.blobs.get(key);
    if (!object) return super.get(key);
    return {
      ...object,
      body: new Response(object.bytes).body,
      arrayBuffer: async () => object.bytes.buffer.slice(object.bytes.byteOffset, object.bytes.byteOffset + object.bytes.byteLength),
    };
  }
  async delete(keys) {
    for (const key of Array.isArray(keys) ? keys : [keys]) {
      this.blobs.delete(key);
      this.entries.delete(key);
    }
  }
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

test("release registration fails closed on missing, unverified, or invalid package policy", async () => {
  const policyResponse = (releaseAccess, candidateStatus = "development-verified-production-release-pending") => ({
    targets: { "ubuntu-focal-amd64": { sourceBranch: "getpatched/focal" } },
    packages: { libxml2: { targets: { "ubuntu-focal-amd64": { releaseAccess, candidateStatus } } } },
  });
  const makeEnv = (releaseAccess, candidateStatus) => ({
    RELEASES: new MemoryBucket(),
    RELEASE_ADMIN_TOKEN: "secret-test",
    ASSETS: { fetch: async () => Response.json(policyResponse(releaseAccess, candidateStatus)) },
  });
  const registration = {
    id: "libxml2-policy-test", repository: "getpatched/packaging-libxml2",
    tag: "getpatched/ubuntu-focal-amd64/1.2.3", target_id: "ubuntu-focal-amd64",
    source_commit: "a".repeat(40), sponsor_delay_hours: 168,
    early_binary_license_id: "LicenseRef-GetPatched-Early-Binary-1.2",
    public_contribution_spdx: "MIT", verification_run_id: 1,
    required_assets: [{ name: "libxml2.deb", sha256: "a".repeat(64) }],
    source_assets: [{ name: "libxml2.dsc", sha256: "b".repeat(64) }],
  };
  const valid = {
    policy: "sponsor-first", sponsorDelayHours: 168,
    sponsorEligibility: "any-active-individual-github-sponsorship-tier",
    earlyBinaryLicenseId: "LicenseRef-GetPatched-Early-Binary-1.2",
    publicContributionSpdx: "MIT", earlyUse: ["private", "commercial"],
    earlyRedistributionAllowed: false, publicLicenseScope: "getpatched-authored-contributions-only",
  };
  const request = () => new Request("https://worker.test/internal/releases", {
    method: "POST", headers: { authorization: "Bearer secret-test" }, body: JSON.stringify(registration),
  });
  const badConfig = await gateway.fetch(request(), makeEnv({ ...valid, earlyRedistributionAllowed: true }));
  assert.equal(badConfig.status, 503);

  const unverifiedCandidate = await gateway.fetch(request(), makeEnv(valid, "unverified-development-candidate"));
  assert.equal(unverifiedCandidate.status, 422);

  const missingCandidateStatus = await gateway.fetch(request(), makeEnv(valid, null));
  assert.equal(missingCandidateStatus.status, 422);

  const malformedVerifiedPrefix = await gateway.fetch(request(), makeEnv(valid, "development-verified-but-not-approved"));
  assert.equal(malformedVerifiedPrefix.status, 422);

  const badSubmittedLicense = { ...registration, early_binary_license_id: "LicenseRef-Other" };
  const badLicenseResponse = await gateway.fetch(new Request("https://worker.test/internal/releases", {
    method: "POST", headers: { authorization: "Bearer secret-test" }, body: JSON.stringify(badSubmittedLicense),
  }), makeEnv(valid));
  assert.equal(badLicenseResponse.status, 422);
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

test("sponsor snapshot paginates all active sponsorship tiers, including one-time sponsorships only while active", async () => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  globalThis.fetch = async (_url, options) => {
    const body = JSON.parse(options.body);
    requests.push(body.variables.after);
    assert.match(body.query, /sponsorshipsAsMaintainer\(activeOnly: true/);
    const firstPage = body.variables.after === null;
    return Response.json({ data: { organization: {
      login: "getpatched", hasSponsorsListing: true,
      sponsorshipsAsMaintainer: {
        nodes: firstPage ? [
          { isActive: true, isOneTimePayment: false, sponsorEntity: { __typename: "User", databaseId: 17, login: "alice" }, tier: { id: "tier-early", name: "Early access", isOneTime: false } },
          { isActive: true, isOneTimePayment: false, sponsorEntity: { __typename: "Organization", databaseId: 89, login: "sponsor-org" }, tier: { id: "tier-early", name: "Early access", isOneTime: false } },
          { isActive: true, isOneTimePayment: false, sponsorEntity: { __typename: "User", databaseId: 18, login: "bob" }, tier: { id: "tier-other", name: "Other", isOneTime: false } },
          { isActive: false, isOneTimePayment: false, sponsorEntity: { __typename: "User", databaseId: 19, login: "former" }, tier: { id: "tier-early", name: "Early access", isOneTime: false } },
          { isActive: false, isOneTimePayment: true, sponsorEntity: { __typename: "User", databaseId: 21, login: "expired-one-time" }, tier: { id: "tier-early", name: "Early access", isOneTime: true } },
        ] : [
          { isActive: true, isOneTimePayment: true, sponsorEntity: { __typename: "User", databaseId: 20, login: "carol" }, tier: { id: "tier-early", name: "Early access", isOneTime: true } },
        ],
        pageInfo: firstPage ? { hasNextPage: true, endCursor: "cursor-1" } : { hasNextPage: false, endCursor: null },
      },
    } } });
  };
  try {
    const snapshot = await fetchSponsorSnapshot({ SPONSOR_GRAPHQL_TOKEN: "test-token" }, new Date("2026-10-25T16:00:00Z"));
    assert.deepEqual(requests, [null, "cursor-1"]);
    assert.deepEqual(snapshot.sponsors.map((sponsor) => sponsor.github_user_id), [17, 18, 20]);
    assert.equal(snapshot.sponsors[2].has_one_time_sponsorship, true);
    assert.equal(snapshot.tier_policy, "any-active-individual-github-sponsorship-tier");
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
    login: "getpatched", hasSponsorsListing: true,
    sponsorshipsAsMaintainer: {
      nodes: [{ isActive: true, isOneTimePayment: false, sponsorEntity: { __typename: "User", databaseId: 17, login: "alice" }, tier: { id: "tier-early", name: "Early access", isOneTime: false } }],
      pageInfo: { hasNextPage: false, endCursor: null },
    },
  } } });
  try {
    const snapshot = await reconcileSponsors({
      RELEASES: bucket, SPONSOR_GRAPHQL_TOKEN: "test-token",
    }, new Date("2026-10-25T16:00:00Z"));
    assert.deepEqual(snapshot.sponsors.map((sponsor) => sponsor.github_user_id), [17]);
    const event = await bucket.get("sponsor-deliveries/delivery-12345678.json");
    const record = await event.json();
    assert.equal(record.reconciled_at, snapshot.reconciled_at);
    assert.equal(record.sponsor_active, true);
    assert.equal(record.entitlement_source, "authoritative-snapshot");
    assert.deepEqual((await readFreshSponsorSnapshot(bucket, new Date("2026-10-25T16:29:59.999Z"))).sponsors.map((sponsor) => sponsor.github_user_id), [17]);
    assert.equal(await readFreshSponsorSnapshot(bucket, new Date("2026-10-25T16:30:00Z")), null);
  } finally { globalThis.fetch = originalFetch; }
});

test("failed sponsor refresh leaves the previous snapshot unchanged and unavailable listings fail closed", async () => {
  const oldSnapshot = {
    organization: "getpatched",
    sponsors: [{ github_user_id: 17, github_login: "alice", has_one_time_sponsorship: false }],
    reconciled_at: "2026-10-25T15:00:00.000Z", valid_until: "2026-10-25T15:30:00.000Z",
    authority: "github-sponsors-graphql-active-only",
    tier_policy: "any-active-individual-github-sponsorship-tier",
  };
  const bucket = new MemoryBucket({ "sponsor-entitlements/current.json": oldSnapshot });
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response("unavailable", { status: 503 });
    await assert.rejects(reconcileSponsors({
      RELEASES: bucket, SPONSOR_GRAPHQL_TOKEN: "test-token",
    }, new Date("2026-10-25T16:00:00Z")), /returned 503/);
    assert.deepEqual(await (await bucket.get("sponsor-entitlements/current.json")).json(), oldSnapshot);

    globalThis.fetch = async () => Response.json({ data: { organization: {
      login: "getpatched", hasSponsorsListing: false,
      sponsorshipsAsMaintainer: { nodes: [], pageInfo: { hasNextPage: false, endCursor: null } },
    } } });
    await assert.rejects(fetchSponsorSnapshot({
      SPONSOR_GRAPHQL_TOKEN: "test-token",
    }, new Date("2026-10-25T16:00:00Z")), /listing is unavailable/);
  } finally { globalThis.fetch = originalFetch; }
});

test("authoritative inactive sponsor snapshot removes early-access eligibility", async () => {
  const now = new Date("2026-10-25T16:00:00Z");
  const bucket = new MemoryBucket({ "sponsor-entitlements/current.json": {
    organization: "getpatched", tier_ids: ["tier-early"],
    sponsors: [{ github_user_id: 17, github_login: "alice", tier_ids: ["tier-early"], has_one_time_sponsorship: false }],
    reconciled_at: "2026-10-25T15:45:00.000Z", valid_until: "2026-10-25T16:15:00.000Z",
    authority: "github-sponsors-graphql-active-only",
  } });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({ data: { organization: {
    login: "getpatched", hasSponsorsListing: true,
    sponsorshipsAsMaintainer: { nodes: [], pageInfo: { hasNextPage: false, endCursor: null } },
  } } });
  try {
    const snapshot = await reconcileSponsors({
      RELEASES: bucket, SPONSOR_GRAPHQL_TOKEN: "test-token",
    }, now);
    assert.deepEqual(snapshot.sponsors, []);
    assert.deepEqual((await readFreshSponsorSnapshot(bucket, now)).sponsors, []);
  } finally { globalThis.fetch = originalFetch; }
});

test("sponsor publication starts an exact 168-hour clock only after every private asset passes readback", async () => {
  const digest = createHash("sha256").update("private-package").digest();
  const release = {
    id: "pilot", state: "prepared", repository: "getpatched/packaging-libxml2", tag: "getpatched/1.2.3",
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
      organization: "getpatched", authority: "github-sponsors-graphql-active-only",
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
    id: "libxml2-1-2-3", state: "public", repository: "getpatched/packaging-libxml2", tag: "getpatched/1.2.3",
    public_release_id: 901, sponsor_delay_hours: 168,
    required_assets: [{ name: "libxml2_1.2.3_amd64.deb", sha256: "a".repeat(64), r2_key: `staging/release/${"a".repeat(64)}` }],
  };
  const bucket = new MemoryBucket({ "release-state/libxml2-1-2-3.json": record });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    assert.equal(String(url), "https://api.github.com/repos/getpatched/packaging-libxml2/releases/901/assets");
    return Response.json([{ name: "libxml2_1.2.3_amd64.deb", browser_download_url: "https://github.com/getpatched/packaging-libxml2/releases/download/getpatched/1.2.3/libxml2_1.2.3_amd64.deb" }]);
  };
  try {
    const response = await gateway.fetch(new Request("https://early.getpatched.dev/early/releases/libxml2-1-2-3/assets/libxml2_1.2.3_amd64.deb"), {
      RELEASES: bucket, GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only",
    });
    assert.equal(response.status, 302);
    assert.equal(response.headers.get("location"), "https://github.com/getpatched/packaging-libxml2/releases/download/getpatched/1.2.3/libxml2_1.2.3_amd64.deb");
    assert.equal(response.headers.get("cache-control"), "public, max-age=300");
  } finally { globalThis.fetch = originalFetch; }
});

test("repository pool paths resolve only manifest assets and preserve gated access", async () => {
  const binaryName = "libxml2_1.2.3_amd64.deb";
  const sourceName = "libxml2_1.2.3.dsc";
  const record = {
    id: "libxml2-1-2-3", state: "public", repository: "getpatched/packaging-libxml2", tag: "getpatched/1.2.3",
    public_release_id: 901, source_release_id: 902, sponsor_delay_hours: 168,
    required_assets: [{ name: binaryName, sha256: "a".repeat(64), r2_key: `staging/libxml2-1-2-3/${"a".repeat(64)}` }],
    source_assets: [{ name: sourceName, sha256: "b".repeat(64), r2_key: `staging/libxml2-1-2-3/source/${"b".repeat(64)}` }],
  };
  const bucket = new MemoryBucket({ "release-state/libxml2-1-2-3.json": record });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const value = String(url);
    if (value.endsWith("/releases/901/assets")) {
      return Response.json([{ name: binaryName, browser_download_url: `https://github.com/getpatched/packaging-libxml2/releases/download/getpatched/1.2.3/${binaryName}` }]);
    }
    if (value.endsWith("/releases/902/assets")) {
      return Response.json([{ name: sourceName, browser_download_url: `https://github.com/getpatched/packaging-libxml2/releases/download/getpatched-source/1.2.3/${sourceName}` }]);
    }
    throw new Error(`unexpected GitHub URL ${value}`);
  };
  try {
    const env = { RELEASES: bucket, GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only" };
    const binary = await gateway.fetch(new Request(`https://repo.getpatched.dev/pool/main/l/libxml2/${binaryName}`), env);
    assert.equal(binary.status, 302);
    assert.equal(binary.headers.get("location"), `https://github.com/getpatched/packaging-libxml2/releases/download/getpatched/1.2.3/${binaryName}`);
    const source = await gateway.fetch(new Request(`https://repo.getpatched.dev/pool/main/l/libxml2/${sourceName}`), env);
    assert.equal(source.status, 302);
    assert.equal(source.headers.get("location"), `https://github.com/getpatched/packaging-libxml2/releases/download/getpatched-source/1.2.3/${sourceName}`);
    const traversal = await gateway.fetch(new Request(`https://repo.getpatched.dev/pool/main/l/libxml2/%2e%2e%2F${binaryName}`), env);
    assert.equal(traversal.status, 400);

    const gated = new MemoryBucket({ "release-state/libxml2-1-2-3.json": {
      ...record, state: "sponsor-period", public_release_id: undefined,
      sponsor_publication_complete: true, public_after: new Date(Date.now() + 86400000).toISOString(),
    } });
    const denied = await gateway.fetch(new Request(`https://early.getpatched.dev/pool/main/l/libxml2/${binaryName}`), { RELEASES: gated });
    assert.equal(denied.status, 401);
    assert.equal(denied.headers.get("cache-control"), "private, no-store");

    const gatedBytes = Buffer.from("sponsor-only package bytes");
    const gatedDigest = createHash("sha256").update(gatedBytes).digest("hex");
    const gatedKey = `staging/libxml2-1-2-3/${gatedDigest}`;
    const now = new Date();
    const sponsorToken = `getpatched_${"c".repeat(64)}`;
    const sponsorTokenHash = createHash("sha256").update(sponsorToken).digest("hex");
    const sponsorBucket = new MemorySponsorBucket({
      "release-state/libxml2-1-2-3.json": {
        ...record,
        state: "sponsor-period",
        public_release_id: undefined,
        sponsor_publication_complete: true,
        public_after: new Date(now.getTime() + 86400000).toISOString(),
        required_assets: [{ name: binaryName, sha256: gatedDigest, r2_key: gatedKey }],
      },
      [`apt-device-tokens/${sponsorTokenHash}.json`]: {
        github_user_id: 17, expires_at: new Date(now.getTime() + 86400000).toISOString(),
      },
      "sponsor-entitlements/current.json": {
        organization: "getpatched", authority: "github-sponsors-graphql-active-only",
        sponsors: [{ github_user_id: 17, tier_ids: ["tier-early"] }],
        reconciled_at: now.toISOString(), valid_until: new Date(now.getTime() + 1800000).toISOString(),
      },
    }, gatedKey, gatedBytes);
    const sponsorAuthorization = `Basic ${btoa(`apt:${sponsorToken}`)}`;
    const publicChannelEarlyBinary = await gateway.fetch(new Request(
      `https://repo.getpatched.dev/pool/main/l/libxml2/${binaryName}`,
      { headers: { authorization: sponsorAuthorization } },
    ), { RELEASES: sponsorBucket, GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only" });
    assert.equal(publicChannelEarlyBinary.status, 404, "a valid sponsor credential must not expose a gated package from the public channel");
    const earlyChannelBinary = await gateway.fetch(new Request(
      `https://early.getpatched.dev/pool/main/l/libxml2/${binaryName}`,
      { headers: { authorization: sponsorAuthorization } },
    ), { RELEASES: sponsorBucket });
    assert.equal(earlyChannelBinary.status, 200, "the same gated package remains available from the authenticated early channel");
    assert.equal(await earlyChannelBinary.text(), "sponsor-only package bytes");

    const promoted = new MemoryBucket({ "release-state/libxml2-1-2-3.json": {
      ...record, state: "public", public_release_id: 901,
    } });
    const afterPromotion = await gateway.fetch(new Request(`https://repo.getpatched.dev/pool/main/l/libxml2/${binaryName}`), {
      RELEASES: promoted, GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only",
    });
    assert.equal(afterPromotion.status, 302);
    assert.equal(afterPromotion.headers.get("location"), `https://github.com/getpatched/packaging-libxml2/releases/download/getpatched/1.2.3/${binaryName}`);
    assert.equal(afterPromotion.headers.get("cache-control"), "public, max-age=300");
  } finally { globalThis.fetch = originalFetch; }
});

test("identical original source tarballs shared by successive releases resolve unambiguously", async () => {
  const name = "libarchive_3.4.0.orig.tar.gz";
  const digest = "b".repeat(64);
  const records = [1, 2].map((revision) => ({
    id: `libarchive-getpatched${revision}`, state: "public", repository: "getpatched/packaging-libarchive",
    tag: `getpatched/3.4.0-2ubuntu1.5+getpatched${revision}`, source_release_id: 900 + revision, sponsor_delay_hours: 0,
    required_assets: [{ name: `libarchive13_getpatched${revision}_amd64.deb`, sha256: "a".repeat(64), r2_key: `staging/libarchive-getpatched${revision}/binary` }],
    source_assets: [{ name, sha256: digest, r2_key: `staging/libarchive-getpatched${revision}/source` }],
  }));
  const bucket = new MemoryBucket(Object.fromEntries(records.map((record) => [`release-state/${record.id}.json`, record])));
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const releaseId = String(url).match(/\/releases\/(\d+)\/assets$/)?.[1];
    if (!["901", "902"].includes(releaseId)) throw new Error(`Unexpected GitHub request: ${String(url)}`);
    return Response.json([{ name, browser_download_url: `https://github.com/getpatched/packaging-libarchive/releases/download/source/${name}` }]);
  };
  try {
    const response = await gateway.fetch(new Request(`https://repo.getpatched.dev/pool/main/l/libarchive/${name}`), {
      RELEASES: bucket, GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only",
    });
    assert.equal(response.status, 302);
  } finally { globalThis.fetch = originalFetch; }
});

test("old by-hash indexes remain served from a retained eligible snapshot after activation", async () => {
  const oldId = "focal-20261025T180000-r1-public";
  const newId = "focal-20261025T190000-r2-public";
  const path = `dists/focal/main/binary-amd64/Packages/by-hash/SHA256/${"a".repeat(64)}`;
  const bytes = Buffer.from("old index bytes");
  const digest = createHash("sha256").update(bytes).digest("hex");
  const entries = {
    "repository-current/public.json": { id: newId },
    [`repository-snapshots/public/${newId}.json`]: { id: newId, channel: "public", release_ids: [], files: [] },
    [`repository-snapshots/public/${oldId}.json`]: { id: oldId, channel: "public", release_ids: [], files: [{ path, size: bytes.length, sha256: "a".repeat(64), content_type: "text/plain; charset=utf-8" }] },
  };
  const bucket = new MemoryAssetBucket(null);
  bucket.entries = new Map(Object.entries(entries).map(([key, value]) => [key, { value, etag: `etag-${key}` }]));
  const objectKey = `repository-snapshots/public/${oldId}/${path}`;
  bucket.assets.set(objectKey, { size: bytes.length, checksums: { sha256: Buffer.from("a".repeat(64), "hex") }, body: bytes });
  const originalGet = bucket.get.bind(bucket);
  bucket.get = async (key) => {
    const asset = bucket.assets.get(key);
    if (asset) return { ...asset, body: new Response(asset.body).body };
    return originalGet(key);
  };
  const response = await gateway.fetch(new Request(`https://repo.getpatched.dev/${path}`), { RELEASES: bucket });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), bytes.toString());
});

test("APT snapshot manifests activate atomically after R2 readback and serve stable dists paths", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const keyId = "snapshot-environment-test";
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: keyId, use: "sig", alg: "RS256" };
  const release = {
    id: "pilot", state: "public", repository: "getpatched/packaging-libarchive", tag: "getpatched/3.4.0-2ubuntu1.5+getpatched1",
    source_commit: "b".repeat(40), release_checks_passed: true, sponsor_delay_hours: 0,
    required_assets: [{ name: "libarchive_amd64.deb", sha256: "a".repeat(64), r2_key: `staging/pilot/${"a".repeat(64)}` }],
  };
  const bucket = new MemorySnapshotBucket({ "release-state/pilot.json": release });
  const env = { RELEASES: bucket };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => String(url).includes("/.well-known/jwks") ? Response.json({ keys: [jwk] }) : Response.json({});
  const snapshotClaims = {
    workflow_ref: "getpatched/platform/.github/workflows/repository-snapshot.yml@refs/heads/main",
    event_name: "workflow_dispatch",
  };
  const authorization = `Bearer ${signedOidcToken(privateKey, snapshotClaims, privateKey, keyId)}`;
  const builderAuthorization = `Bearer ${signedOidcToken(privateKey, { ...snapshotClaims, environment: "getpatched-index-build" }, privateKey, keyId)}`;
  const stagingAuthorization = `Bearer ${signedOidcToken(privateKey, {}, privateKey, keyId)}`;
    const builderReleaseAuthorization = `Bearer ${signedOidcToken(privateKey, { ...snapshotClaims, environment: "getpatched-index-build" }, privateKey, keyId)}`;
  const firstId = "focal-20261025T120000-r101-public";
  const contents = new Map([
    ["dists/focal/Release", "Origin: GetPatched\nSuite: focal\n"],
    ["dists/focal/InRelease", "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nOrigin: GetPatched\n"],
    ["dists/focal/Release.gpg", "-----BEGIN PGP SIGNATURE-----\nvalid test fixture\n-----END PGP SIGNATURE-----\n"],
    ["dists/focal/main/binary-amd64/Packages", "Package: libarchive\nVersion: 3.4.0-2ubuntu1.5+getpatched1\n"],
    ["dists/focal/main/binary-amd64/Packages.gz", "gzip fixture"],
    ["dists/focal/main/binary-amd64/Packages.xz", "xz fixture"],
    ["dists/focal/main/source/Sources", "Package: libarchive\n"],
    ["dists/focal/main/source/Sources.gz", "gzip source fixture"],
    ["dists/focal/main/source/Sources.xz", "xz source fixture"],
    ["getpatched-archive-keyring.gpg", "public key fixture"],
  ]);
  const files = [...contents].map(([path, content]) => ({ path, size: Buffer.byteLength(content), sha256: createHash("sha256").update(content).digest("hex") }));
  try {
    const request = (url, method, body) => new Request(url, {
      method, headers: { authorization, ...(body === undefined ? {} : { "content-length": String(Buffer.byteLength(body)) }) }, body,
    });
    const stagingRequest = (url, method, body) => new Request(url, {
      method, headers: { authorization: stagingAuthorization, ...(body === undefined ? {} : { "content-length": String(Buffer.byteLength(body)) }) }, body,
    });
    const stagingRegistration = await gateway.fetch(stagingRequest("https://repo.getpatched.dev/internal/repository-snapshots/public", "POST", JSON.stringify({ id: "staging-cannot-publish", release_ids: ["pilot"], files })), env);
    assert.equal(stagingRegistration.status, 401, "the artifact staging workflow cannot register repository metadata");
    const builderReleaseRegistration = await gateway.fetch(new Request("https://repo.getpatched.dev/internal/releases", {
      method: "POST", headers: { authorization: builderReleaseAuthorization, "content-length": "2" }, body: "{}",
    }), env);
    assert.equal(builderReleaseRegistration.status, 401, "the index builder cannot register package releases");
    const registration = await gateway.fetch(request("https://repo.getpatched.dev/internal/repository-snapshots/public", "POST", JSON.stringify({ id: firstId, release_ids: ["pilot"], files })), env);
    assert.equal(registration.status, 201);
    const replay = await gateway.fetch(request("https://repo.getpatched.dev/internal/repository-snapshots/public", "POST", JSON.stringify({ id: firstId, release_ids: ["pilot"], files })), env);
    assert.equal(replay.status, 200, "repeated registration of the same immutable manifest is safe");
    bucket.entries.set("release-state/gated.json", {
      value: { ...release, id: "gated", state: "sponsor-period", repository: "getpatched/packaging-libxml2", tag: "getpatched/2.9.10+dfsg-5ubuntu0.20.04.10+getpatched1", sponsor_delay_hours: 168, sponsor_publication_complete: true, public_after: new Date(Date.now() + 86400000).toISOString() },
      etag: "gated-release",
    });
    const prematurePublic = await gateway.fetch(request("https://repo.getpatched.dev/internal/repository-snapshots/public", "POST", JSON.stringify({ id: "focal-20261025T130000-r102-public", release_ids: ["gated"], files })), env);
    assert.equal(prematurePublic.status, 409, "a seven-day release cannot enter the anonymous public index before promotion");
    const beforeUpload = await gateway.fetch(request(`https://repo.getpatched.dev/internal/repository-snapshots/public/${firstId}/activate`, "POST", "{}"), env);
    assert.equal(beforeUpload.status, 409);
    for (const [path, content] of contents) {
      const result = await gateway.fetch(request(`https://repo.getpatched.dev/internal/repository-snapshots/public/${firstId}/files/${path}`, "PUT", content), env);
      assert.equal(result.status, 201, path);
    }
    const stagingUpload = await gateway.fetch(stagingRequest(`https://repo.getpatched.dev/internal/repository-snapshots/public/${firstId}/files/dists/focal/Release`, "PUT", contents.get("dists/focal/Release")), env);
    assert.equal(stagingUpload.status, 401, "the artifact staging workflow cannot write repository metadata");
    const stagingActivation = await gateway.fetch(stagingRequest(`https://repo.getpatched.dev/internal/repository-snapshots/public/${firstId}/activate`, "POST", "{}"), env);
    assert.equal(stagingActivation.status, 401, "the artifact staging workflow cannot activate repository metadata");
    const activated = await gateway.fetch(request(`https://repo.getpatched.dev/internal/repository-snapshots/public/${firstId}/activate`, "POST", "{}"), env);
    assert.equal(activated.status, 201);
    assert.deepEqual(bucket.entries.get("repository-history/public.json").value.snapshot_ids, [firstId]);
    const inventoryAfterActivation = await gateway.fetch(new Request("https://repo.getpatched.dev/internal/repository-snapshots/public/releases", { headers: { authorization: builderAuthorization } }), env);
    assert.equal(inventoryAfterActivation.status, 200);
    assert.deepEqual((await inventoryAfterActivation.json()).active_snapshot, { id: firstId, release_ids: ["pilot"], healthy: true });
    const activeReleaseObject = bucket.blobs.get(`repository-snapshots/public/${firstId}/dists/focal/Release`);
    activeReleaseObject.customMetadata.path = "tampered";
    const unhealthyInventory = await gateway.fetch(new Request("https://repo.getpatched.dev/internal/repository-snapshots/public/releases", { headers: { authorization: builderAuthorization } }), env);
    assert.equal((await unhealthyInventory.json()).active_snapshot.healthy, false, "a corrupted active snapshot must be rebuilt rather than treated as unchanged");
    activeReleaseObject.customMetadata.path = "dists/focal/Release";
    const served = await gateway.fetch(new Request("https://repo.getpatched.dev/dists/focal/InRelease"), env);
    assert.equal(served.status, 200);
    assert.equal(await served.text(), contents.get("dists/focal/InRelease"));
    assert.equal(served.headers.get("cache-control"), "public, max-age=300");

    const secondId = "focal-20261025T120100-r102-public";
    const secondRegistration = await gateway.fetch(request("https://repo.getpatched.dev/internal/repository-snapshots/public", "POST", JSON.stringify({ id: secondId, release_ids: ["pilot"], files })), env);
    assert.equal(secondRegistration.status, 201);
    for (const [path, content] of contents) {
      const uploaded = await gateway.fetch(request(`https://repo.getpatched.dev/internal/repository-snapshots/public/${secondId}/files/${path}`, "PUT", content), env);
      assert.equal(uploaded.status, 201, path);
    }
    const secondActivation = await gateway.fetch(request(`https://repo.getpatched.dev/internal/repository-snapshots/public/${secondId}/activate`, "POST", "{}"), env);
    assert.equal(secondActivation.status, 201);
    assert.equal(bucket.entries.get("repository-current/public.json").value.id, secondId);
    assert.deepEqual(bucket.entries.get("repository-history/public.json").value.snapshot_ids, [secondId, firstId]);
    const rollback = await gateway.fetch(request(`https://repo.getpatched.dev/internal/repository-snapshots/public/${firstId}/activate`, "POST", "{}"), env);
    assert.equal(rollback.status, 201);
    assert.equal((await rollback.json()).id, firstId);
    assert.equal(bucket.entries.get("repository-current/public.json").value.id, firstId);
    assert.deepEqual(bucket.entries.get("repository-history/public.json").value.snapshot_ids, [firstId, secondId]);
    const restored = await gateway.fetch(new Request("https://repo.getpatched.dev/dists/focal/InRelease"), env);
    assert.equal(await restored.text(), contents.get("dists/focal/InRelease"));

    const keyring = await gateway.fetch(new Request("https://early.getpatched.dev/getpatched-archive-keyring.gpg"), env);
    assert.equal(keyring.status, 200, "the public trust anchor remains anonymously available");
    const privateIndex = await gateway.fetch(new Request("https://early.getpatched.dev/dists/focal/InRelease"), env);
    assert.equal(privateIndex.status, 401);
    assert.equal(privateIndex.headers.get("cache-control"), "private, no-store");
    assert.equal((await gateway.fetch(new Request("https://repo.getpatched.dev/dists/focal/unknown"), env)).status, 404);

    const expiredEarlyId = "focal-20261025T120200-r103-early";
    const earlyRegistration = await gateway.fetch(request("https://repo.getpatched.dev/internal/repository-snapshots/early", "POST", JSON.stringify({ id: expiredEarlyId, release_ids: ["gated"], files })), env);
    assert.equal(earlyRegistration.status, 201);
    for (const [path, content] of contents) {
      const result = await gateway.fetch(request(`https://repo.getpatched.dev/internal/repository-snapshots/early/${expiredEarlyId}/files/${path}`, "PUT", content), env);
      assert.equal(result.status, 201, path);
    }
    const expiredRelease = bucket.entries.get("release-state/gated.json");
    expiredRelease.value.public_after = new Date(Date.now() - 1000).toISOString();
    bucket.entries.set("release-state/gated.json", expiredRelease);
    const expiredActivation = await gateway.fetch(request(`https://repo.getpatched.dev/internal/repository-snapshots/early/${expiredEarlyId}/activate`, "POST", "{}"), env);
    assert.equal(expiredActivation.status, 409, "an early snapshot cannot activate after a gated release reaches its public deadline");
  } finally { globalThis.fetch = originalFetch; }
});

test("protected retention keeps the active snapshot and five rollback snapshots while deleting older objects", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const keyId = "snapshot-retention-test";
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: keyId, use: "sig", alg: "RS256" };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => String(url).includes("/.well-known/jwks") ? Response.json({ keys: [jwk] }) : Response.json({});
  const claims = {
    workflow_ref: "getpatched/platform/.github/workflows/repository-snapshot.yml@refs/heads/main",
    event_name: "schedule", environment: "getpatched-signing",
  };
  const signerAuthorization = `Bearer ${signedOidcToken(privateKey, claims, privateKey, keyId)}`;
  const bucket = new MemorySnapshotBucket({ "release-state/pilot.json": {
    id: "pilot", state: "public", repository: "getpatched/packaging-libarchive", tag: "getpatched/1.2.3",
    source_commit: "b".repeat(40), sponsor_delay_hours: 0, release_checks_passed: true,
    required_assets: [{ name: "libarchive.deb", sha256: "a".repeat(64), r2_key: `staging/pilot/${"a".repeat(64)}` }],
  } });
  bucket.listPageSize = 2;
  const paths = [
    "dists/focal/Release", "dists/focal/InRelease", "dists/focal/Release.gpg",
    "dists/focal/main/binary-amd64/Packages", "dists/focal/main/binary-amd64/Packages.gz", "dists/focal/main/binary-amd64/Packages.xz",
    "dists/focal/main/source/Sources", "dists/focal/main/source/Sources.gz", "dists/focal/main/source/Sources.xz",
    "getpatched-archive-keyring.gpg",
  ];
  const files = paths.map((path) => ({ path, size: 1, sha256: createHash("sha256").update("x").digest("hex") }));
  const ids = Array.from({ length: 8 }, (_, index) => `focal-202610${String(17 + index).padStart(2, "0")}T000000-r${100 + index}-public`);
  ids.forEach((id, index) => {
    bucket.entries.set(`repository-snapshots/public/${id}.json`, {
      value: { id, channel: "public", suite: "focal", architecture: "amd64", release_ids: ["pilot"], files, created_at: new Date(Date.UTC(2026, 9, 17 + index)).toISOString() },
      etag: `snapshot-${index}`,
    });
    for (const file of files) {
      const digest = createHash("sha256").update("x").digest();
      bucket.blobs.set(`repository-snapshots/public/${id}/${file.path}`, {
        bytes: Buffer.from("x"), size: 1, checksums: { sha256: digest.buffer.slice(digest.byteOffset, digest.byteOffset + digest.byteLength) },
        customMetadata: { snapshotId: id, channel: "public", path: file.path },
      });
    }
  });
  bucket.entries.set("repository-history/public.json", {
    value: { channel: "public", snapshot_ids: [ids[0], ids[7], ids[6], ids[5], ids[4], ids[3]], updated_at: "2026-10-24T00:00:00.000Z" },
    etag: "snapshot-history",
  });
  const buildFiles = [
    "dists/focal/Release", "dists/focal/main/binary-amd64/Packages", "dists/focal/main/binary-amd64/Packages.gz",
    "dists/focal/main/binary-amd64/Packages.xz", "dists/focal/main/source/Sources", "dists/focal/main/source/Sources.gz",
    "dists/focal/main/source/Sources.xz",
  ].map((path) => ({ path, size: 1, sha256: createHash("sha256").update("x").digest("hex") }));
  const buildIdAt = (timestamp, run) => {
    const iso = new Date(timestamp).toISOString();
    return `focal-${iso.slice(0, 10).replaceAll("-", "")}T${iso.slice(11, 19).replaceAll(":", "")}-r${run}-public`;
  };
  const staleBuildAt = Date.now() - 48 * 60 * 60 * 1000;
  const freshBuildAt = Date.now() - 12 * 60 * 60 * 1000;
  const staleBuildId = buildIdAt(staleBuildAt, 200);
  const freshBuildId = buildIdAt(freshBuildAt, 201);
  for (const [id, createdAt] of [[staleBuildId, new Date(staleBuildAt).toISOString()], [freshBuildId, new Date(freshBuildAt).toISOString()]]) {
    bucket.entries.set(`repository-snapshot-builds/public/${id}.json`, {
      value: { id, channel: "public", release_ids: ["pilot"], files: buildFiles, created_at: createdAt },
      etag: `build-${id}`,
    });
    for (const file of buildFiles) bucket.blobs.set(`repository-snapshot-builds/public/${id}/${file.path}`, { bytes: Buffer.from("x") });
  }
  bucket.entries.set("repository-current/public.json", { value: { id: ids[0], channel: "public" }, etag: "active" });
  const debianOrphanId = "bookworm-amd64-20261001T000000-r88-public";
  const debianStaleBuildId = "bookworm-amd64-20261001T000000-r89-public";
  bucket.entries.set(`repository-snapshots/public/${debianOrphanId}.json`, {
    value: { id: debianOrphanId, channel: "public", suite: "bookworm", architecture: "amd64", release_ids: [], files: [] }, etag: "debian-orphan",
  });
  bucket.blobs.set(`repository-snapshots/public/${debianOrphanId}/orphan`, { bytes: Buffer.from("orphan") });
  bucket.entries.set(`repository-snapshot-builds/public/${debianStaleBuildId}.json`, {
    value: { id: debianStaleBuildId, channel: "public", suite: "bookworm", architecture: "amd64", release_ids: [], files: [] }, etag: "debian-stale-build",
  });
  bucket.blobs.set(`repository-snapshot-builds/public/${debianStaleBuildId}/orphan`, { bytes: Buffer.from("orphan") });
  const env = { RELEASES: bucket };
  try {
    const unauthorized = await gateway.fetch(new Request("https://repo.getpatched.dev/internal/repository-snapshots/retention", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ channels: ["public"] }),
    }), env);
    assert.equal(unauthorized.status, 401, "only the protected signing workflow may prune immutable snapshots");
    const activeObject = bucket.blobs.get(`repository-snapshots/public/${ids[0]}/${files[0].path}`);
    activeObject.customMetadata.path = "tampered";
    const refused = await gateway.fetch(new Request("https://repo.getpatched.dev/internal/repository-snapshots/retention", {
      method: "POST", headers: { authorization: signerAuthorization, "content-type": "application/json" }, body: JSON.stringify({ channels: ["public"] }),
    }), env);
    assert.equal(refused.status, 503, "a damaged active snapshot stops all retention deletes");
    assert.equal(bucket.entries.has(`repository-snapshots/public/${ids[1]}.json`), true);
    activeObject.customMetadata.path = files[0].path;
    const retained = await gateway.fetch(new Request("https://repo.getpatched.dev/internal/repository-snapshots/retention", {
      method: "POST", headers: { authorization: signerAuthorization, "content-type": "application/json" }, body: JSON.stringify({ channels: ["public"] }),
    }), env);
    assert.equal(retained.status, 200, await retained.clone().text());
    const result = await retained.json();
    assert.equal(result.channels.public.deleted_snapshots, 3);
    assert.equal(result.channels.public.deleted_builds, 2);
    assert.equal(bucket.entries.has(`repository-snapshots/public/${debianOrphanId}.json`), false, "Debian orphan snapshots are included in target-specific retention");
    assert.equal(bucket.blobs.has(`repository-snapshots/public/${debianOrphanId}/orphan`), false);
    assert.equal(bucket.entries.has(`repository-snapshot-builds/public/${debianStaleBuildId}.json`), false, "Debian stale builds are included in target-specific retention");
    assert.equal(bucket.entries.has(`repository-snapshot-builds/public/${staleBuildId}.json`), false, "stale unsigned build manifests are pruned");
    assert.equal(bucket.blobs.has(`repository-snapshot-builds/public/${staleBuildId}/${buildFiles[0].path}`), false);
    assert.equal(bucket.entries.has(`repository-snapshot-builds/public/${freshBuildId}.json`), true, "the newest build is retained during its recovery window");
    assert.equal(bucket.entries.has(`repository-snapshots/public/${ids[0]}.json`), true, "the active snapshot remains even when old");
    assert.equal(bucket.entries.has(`repository-snapshots/public/${ids[1]}.json`), false);
    assert.equal(bucket.entries.has(`repository-snapshots/public/${ids[2]}.json`), false);
    for (const id of ids.slice(3)) assert.equal(bucket.entries.has(`repository-snapshots/public/${id}.json`), true, "the five newest non-active rollback snapshots remain");
    assert.equal(bucket.blobs.has(`repository-snapshots/public/${ids[1]}/${files[0].path}`), false, "pruning removes old immutable snapshot bytes");

    const historical = bucket.entries.get(`repository-snapshots/public/${ids[7]}.json`);
    historical.value.release_ids = ["withdrawn-release"];
    bucket.entries.set(`repository-snapshots/public/${ids[7]}.json`, historical);
    const afterRevocation = await gateway.fetch(new Request("https://repo.getpatched.dev/internal/repository-snapshots/retention", {
      method: "POST", headers: { authorization: signerAuthorization, "content-type": "application/json" }, body: JSON.stringify({ channels: ["public"] }),
    }), env);
    assert.equal(afterRevocation.status, 200, await afterRevocation.clone().text());
    const pruned = await afterRevocation.json();
    assert.equal(pruned.channels.public.retained_snapshots, 5, "a history entry whose referenced release is missing is removed from the rollback set");
    assert.equal(pruned.channels.public.deleted_snapshots, 1);
    assert.equal(bucket.entries.has(`repository-snapshots/public/${ids[7]}.json`), false);
    assert.equal(bucket.blobs.has(`repository-snapshots/public/${ids[7]}/${files[0].path}`), false, "payload is removed before its manifest");
  } finally { globalThis.fetch = originalFetch; }
});

test("GitHub OAuth login issues hashed per-device APT credentials that can be listed and revoked", async () => {
  const bucket = new MemoryBucket();
  const env = { RELEASES: bucket, PUBLIC_ORIGIN: "https://getpatched.dev", GITHUB_OAUTH_CLIENT_ID: "client-id", GITHUB_OAUTH_CLIENT_SECRET: "test-client-secret" };
  const login = await gateway.fetch(new Request("https://getpatched.dev/auth/github"), env);
  assert.equal(login.status, 302);
  const authorization = new URL(login.headers.get("location"));
  assert.equal(authorization.searchParams.get("scope"), "read:user");
  assert.equal(authorization.searchParams.get("code_challenge_method"), "S256");
  assert.match(authorization.searchParams.get("code_challenge"), /^[A-Za-z0-9_-]{43}$/);
  const state = authorization.searchParams.get("state");
  const stateCookie = login.headers.get("set-cookie").match(/getpatched_oauth_state=([^;,]+)/)[1];
  assert.equal(decodeURIComponent(stateCookie), state);

  const now = new Date();
  bucket.entries.set("sponsor-entitlements/current.json", {
    value: {
      organization: "getpatched", authority: "github-sponsors-graphql-active-only",
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
    const callback = await gateway.fetch(new Request(`https://getpatched.dev/auth/github/callback?code=one-time-code&state=${state}`, {
      headers: { cookie: `aptto_oauth_state=${stateCookie}` },
    }), env);
    assert.equal(callback.status, 302);
    assert.equal(callback.headers.get("location"), "https://getpatched.dev/account");
    const callbackCookies = callback.headers.getSetCookie();
    assert.equal(callbackCookies.length, 3);
    const sessionCookie = callbackCookies.find((cookie) => cookie.startsWith("getpatched_session=")).match(/getpatched_session=([^;,]+)/)[1];
    const legacySessionCookie = `aptto_session=${sessionCookie}`;
    const stateRecord = await bucket.get(`oauth-states/${createHash("sha256").update(state).digest("hex")}.json`);
    const consumedState = await stateRecord.json();
    assert.equal(consumedState.code_verifier, null);
    assert.ok(consumedState.consumed_at);
    assert.equal(oauthCalls, 2);
    assert.match(submittedVerifier, /^[a-f0-9]{96}$/);

    const missingLicenseResponse = await gateway.fetch(new Request("https://getpatched.dev/api/device-tokens", {
      method: "POST", headers: { origin: "https://getpatched.dev", cookie: legacySessionCookie, "content-type": "application/json" },
      body: JSON.stringify({ label: "workstation" }),
    }), env);
    assert.equal(missingLicenseResponse.status, 400);
    const tokenResponse = await gateway.fetch(new Request("https://getpatched.dev/api/device-tokens", {
      method: "POST", headers: { origin: "https://getpatched.dev", cookie: legacySessionCookie, "content-type": "application/json" },
      body: JSON.stringify({ label: "workstation", earlyBinaryLicenseId: "LicenseRef-GetPatched-Early-Binary-1.2" }),
    }), env);
    assert.equal(tokenResponse.status, 201);
    const issued = await tokenResponse.json();
    assert.match(issued.token, /^getpatched_[a-f0-9]{64}$/);
    const tokenHash = createHash("sha256").update(issued.token).digest("hex");
    assert.ok(bucket.entries.has(`apt-device-tokens/${tokenHash}.json`));
    const tokenRecord = await (await bucket.get(`apt-device-tokens/${tokenHash}.json`)).json();
    assert.equal(tokenRecord.early_binary_license_id, "LicenseRef-GetPatched-Early-Binary-1.2");
    assert.ok(tokenRecord.early_binary_terms_accepted_at);
    assert.equal(JSON.stringify([...bucket.entries.values()]).includes(issued.token), false);
    assert.equal(JSON.stringify([...bucket.entries.values()]).includes("transient-oauth-secret"), false);

    const listed = await gateway.fetch(new Request("https://getpatched.dev/api/device-tokens", {
      headers: { cookie: legacySessionCookie },
    }), env);
    assert.equal((await listed.json()).devices.length, 1);
    const revoked = await gateway.fetch(new Request(`https://getpatched.dev/api/device-tokens/${tokenHash}/revoke`, {
      method: "POST", headers: { origin: "https://getpatched.dev", cookie: legacySessionCookie },
    }), env);
    assert.equal(revoked.status, 200);
    const listedAfterRevoke = await gateway.fetch(new Request("https://getpatched.dev/api/device-tokens", {
      headers: { cookie: legacySessionCookie },
    }), env);
    assert.ok((await listedAfterRevoke.json()).devices[0].revoked_at);

    const loggedOut = await gateway.fetch(new Request("https://getpatched.dev/api/logout", {
      method: "POST", headers: { origin: "https://getpatched.dev", cookie: legacySessionCookie },
    }), env);
    assert.equal(loggedOut.status, 204);
    assert.ok(loggedOut.headers.getSetCookie().some((cookie) => cookie.startsWith("aptto_session=;")));
    const afterLogout = await gateway.fetch(new Request("https://getpatched.dev/api/device-tokens", {
      headers: { cookie: legacySessionCookie },
    }), env);
    assert.equal(afterLogout.status, 401);

    const replay = await gateway.fetch(new Request(`https://getpatched.dev/auth/github/callback?code=one-time-code&state=${state}`, {
      headers: { cookie: `getpatched_oauth_state=${stateCookie}` },
    }), env);
    assert.equal(replay.status, 400);
    assert.equal(oauthCalls, 2);
  } finally { globalThis.fetch = originalFetch; }
});

test("account status reports when GitHub sign-in is not configured", async () => {
  const response = await gateway.fetch(new Request("https://getpatched.dev/api/me"), { RELEASES: new MemoryBucket() });
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: "GitHub sign-in is not configured" });
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
      organization: "getpatched", authority: "github-sponsors-graphql-active-only",
      sponsors: [{ github_user_id: 17 }], valid_until: new Date(now.getTime() + 1800000).toISOString(),
    },
  });
  const env = {
    RELEASES: bucket,
    GITHUB_OAUTH_CLIENT_ID: "test-client-id",
    GITHUB_OAUTH_CLIENT_SECRET: "test-client-secret",
    PUBLIC_ORIGIN: "https://getpatched.dev",
  };
  const anonymous = await gateway.fetch(new Request("https://getpatched.dev/api/me"), env);
  assert.equal(anonymous.status, 401);

  const statusRequest = () => new Request("https://getpatched.dev/api/me", { headers: { cookie: `getpatched_session=${session}` } });
  const eligible = await gateway.fetch(statusRequest(), env);
  assert.deepEqual(await eligible.json(), {
    github_login: "alice", sponsorship: "eligible", snapshot_valid_until: new Date(now.getTime() + 1800000).toISOString(),
  });

  const snapshot = bucket.entries.get("sponsor-entitlements/current.json");
  snapshot.value = { ...snapshot.value, valid_until: new Date(now.getTime() - 1).toISOString() };
  const stale = await gateway.fetch(statusRequest(), env);
  assert.equal((await stale.json()).sponsorship, "unavailable");
});

test("Worker serves the account shell through the clean asset URL and keeps unknown APIs private", async () => {
  const requested = [];
  const env = { ASSETS: { fetch: async (request) => {
    const pathname = new URL(request.url).pathname;
    requested.push(pathname);
    if (pathname.endsWith(".html")) {
      return new Response(null, { status: 307, headers: { location: pathname.slice(0, -5) } });
    }
    const assetPath = pathname === "/account" ? "/account.html" : pathname;
    return new Response(assetPath, { status: 200 });
  } } };
  const account = await gateway.fetch(new Request("https://getpatched.dev/account"), env);
  assert.equal(account.status, 200);
  assert.equal(await account.text(), "/account.html");
  assert.deepEqual(requested, ["/account"]);
  const home = await gateway.fetch(new Request("https://getpatched.dev/"), env);
  assert.equal(home.status, 200);
  assert.deepEqual(requested, ["/account", "/"]);
  const missingApi = await gateway.fetch(new Request("https://getpatched.dev/api/private"), env);
  assert.equal(missingApi.status, 404);
  assert.deepEqual(requested, ["/account", "/"]);
});

test("signed cancellation immediately revokes cached sponsor access; a later active-only snapshot can restore it", async () => {
  const now = new Date();
  const snapshot = {
    organization: "getpatched", authority: "github-sponsors-graphql-active-only",
    sponsors: [{ github_user_id: 42, github_login: "alice" }],
    reconciled_at: new Date(now.getTime() - 60_000).toISOString(),
    valid_until: new Date(now.getTime() + 600_000).toISOString(),
  };
  const bucket = new MemoryBucket({ "sponsor-entitlements/current.json": snapshot });
  const payload = JSON.stringify({ action: "cancelled", sponsorship: { sponsor: { id: 42 } } });
  const signature = `sha256=${createHmac("sha256", "webhook-secret").update(payload).digest("hex")}`;
  const makeRequest = (sig = signature) => new Request("https://worker.test/webhooks/github/sponsorship", {
    method: "POST",
    headers: { "x-github-event": "sponsorship", "x-github-delivery": "12345678-1234-1234-1234-123456789abc", "x-hub-signature-256": sig },
    body: payload,
  });
  const env = { SPONSOR_WEBHOOK_SECRET: "webhook-secret", RELEASES: bucket };
  assert.equal(await hasActiveSponsorship(bucket, snapshot, 42), true);
  assert.equal((await gateway.fetch(makeRequest("sha256=" + "0".repeat(64)), env)).status, 401);
  assert.equal(await hasActiveSponsorship(bucket, snapshot, 42), true);
  const accepted = await gateway.fetch(makeRequest(), env);
  assert.equal(accepted.status, 202);
  assert.equal((await accepted.json()).reconciliation_required, true);
  assert.equal(await hasActiveSponsorship(bucket, snapshot, 42), false);
  const duplicate = await gateway.fetch(makeRequest(), env);
  assert.equal((await duplicate.json()).duplicate, true);
  const renewedSnapshot = { ...snapshot, reconciled_at: new Date(Date.now() + 1_000).toISOString() };
  assert.equal(await hasActiveSponsorship(bucket, renewedSnapshot, 42), true);
  const event = await bucket.get("sponsor-deliveries/12345678-1234-1234-1234-123456789abc.json");
  assert.deepEqual(await event.json(), {
    delivery_id: "12345678-1234-1234-1234-123456789abc",
    action: "cancelled",
    sponsor_id: 42,
    received_at: (await event.json()).received_at,
    effect: "early-access-revoked",
  });
  const revocation = await bucket.get("sponsor-revocations/42.json");
  assert.equal((await revocation.json()).reason, "github-sponsorship-cancelled");
});

test("deadline parser requires an explicit timezone", () => {
  assert.equal(parseUtc("2026-11-01T14:00:00Z").toISOString(), "2026-11-01T14:00:00.000Z");
  assert.throws(() => parseUtc("2026-11-01T14:00:00"), /UTC offset/);
});

test("release gate requires the named successful package job and exact tested source commit", async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  const authorizations = new Map();
  let displayTitle = `Verify libxml2 on ubuntu-focal-amd64 at ${"b".repeat(40)}`;
  let signerLogin = TEST_RELEASE_TAG_SIGNER;
  let annotatedSha = "d".repeat(40);
  globalThis.fetch = async (url, options = {}) => {
    calls.push(String(url));
    authorizations.set(String(url), options.headers?.authorization);
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
    if (String(url).endsWith("/git/ref/tags/getpatched/1.2.3")) {
      return Response.json({ ref: "refs/tags/getpatched/1.2.3", object: { type: "tag", sha: "d".repeat(40) } });
    }
    if (String(url).endsWith("/graphql")) return Response.json({ data: { repository: { object: {
      __typename: "Tag", oid: "d".repeat(40), name: "getpatched/1.2.3",
      tagger: { email: "releases@getpatched.dev", user: { login: signerLogin } },
    } } } });
    if (String(url).includes("/compare/getpatched%2Ffocal...")) {
      return Response.json({ merge_base_commit: { sha: "b".repeat(40) } });
    }
    return Response.json({ sha: annotatedSha, verification: { verified: true, reason: "valid" }, tagger: { email: "releases@getpatched.dev" }, object: { type: "commit", sha: "b".repeat(40) } });
  };
  try {
    const verified = await verifyPackageRun(
      { GITHUB_API: "https://api.github.com", GITHUB_ACTIONS_TOKEN: "actions-only", GITHUB_RELEASE_TOKEN: "release-only", GETPATCHED_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER },
      "getpatched/packaging-libxml2", "b".repeat(40), "getpatched/1.2.3", 456,
    );
    assert.equal(verified.job_id, 9);
    assert.equal(verified.run_id, 456);
    assert.equal(calls.length, 6);
    assert.equal(authorizations.get("https://api.github.com/repos/getpatched/platform/actions/runs/456"), "Bearer actions-only");
    assert.equal(authorizations.get("https://api.github.com/repos/getpatched/platform/actions/runs/456/jobs?per_page=100"), "Bearer actions-only");
    assert.equal(authorizations.get("https://api.github.com/repos/getpatched/packaging-libxml2/git/ref/tags/getpatched/1.2.3"), "Bearer release-only");
    assert.equal(authorizations.get("https://api.github.com/graphql"), "Bearer release-only");
    await assert.rejects(
      verifyPackageRun({ GITHUB_API: "https://api.github.com", GITHUB_RELEASE_TOKEN: "release-only", GETPATCHED_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER }, "getpatched/packaging-libxml2", "b".repeat(40), "getpatched/1.2.3", 456),
      /GitHub actions token is not configured/,
    );
    annotatedSha = "e".repeat(40);
    await assert.rejects(
      verifyPackageRun({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", GETPATCHED_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER }, "getpatched/packaging-libxml2", "b".repeat(40), "getpatched/1.2.3", 456),
      /signed package tag must verify/,
    );
    annotatedSha = "d".repeat(40);
    signerLogin = "unexpected-maintainer";
    await assert.rejects(
      verifyPackageRun({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", GETPATCHED_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER }, "getpatched/packaging-libxml2", "b".repeat(40), "getpatched/1.2.3", 456),
      /configured GitHub account/,
    );
    signerLogin = TEST_RELEASE_TAG_SIGNER;
    const savedLogin = signerLogin;
    signerLogin = null;
    await assert.rejects(
      verifyPackageRun({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", GETPATCHED_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER }, "getpatched/packaging-libxml2", "b".repeat(40), "getpatched/1.2.3", 456),
      /configured GitHub account/,
    );
    signerLogin = savedLogin;
    displayTitle = `Verify all at ${"b".repeat(40)}`;
    await assert.rejects(
      verifyPackageRun({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", GETPATCHED_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER }, "getpatched/packaging-libxml2", "b".repeat(40), "getpatched/1.2.3", 456),
      /successful package-verification dispatch/,
    );
    displayTitle = `Verify libxml2 at ${"b".repeat(40)}`;
    await assert.rejects(
      verifyPackageRun({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", GETPATCHED_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER }, "getpatched/packaging-libxml2", "a".repeat(40), "getpatched/1.2.3", 456),
      /successful package-verification dispatch/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("signed source tag must point to the tested commit", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).endsWith("/git/ref/tags/getpatched/1.2.3")) {
      return Response.json({ ref: "refs/tags/getpatched/1.2.3", object: { type: "tag", sha: "d".repeat(40) } });
    }
    if (String(url).includes("/compare/getpatched%2Ffocal...")) {
      return Response.json({ merge_base_commit: { sha: "e".repeat(40) } });
    }
    return Response.json({ sha: "d".repeat(40), verification: { verified: true, reason: "valid" }, object: { type: "commit", sha: "e".repeat(40) } });
  };
  try {
    await assert.rejects(
      verifySignedSourceTag({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", GETPATCHED_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER }, "getpatched/packaging-libxml2", "getpatched/1.2.3", "b".repeat(40)),
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
      verifySignedSourceTag({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only" }, "getpatched/packaging-libxml2", "getpatched/1.2.3", "b".repeat(40)),
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
    if (String(url).endsWith("/git/ref/tags/getpatched/1.2.3")) {
      return Response.json({ ref: "refs/tags/getpatched/1.2.3", object: { type: "tag", sha: "d".repeat(40) } });
    }
    if (String(url).endsWith("/graphql")) return Response.json({ data: { repository: { object: {
      __typename: "Tag", oid: "d".repeat(40), name: "getpatched/1.2.3",
      tagger: { email: "releases@getpatched.dev", user: { login: TEST_RELEASE_TAG_SIGNER } },
    } } } });
    if (String(url).includes("/git/tags/")) {
      return Response.json({ sha: "d".repeat(40), verification: { verified: true, reason: "valid" }, tagger: { email: "releases@getpatched.dev" }, object: { type: "commit", sha: "b".repeat(40) } });
    }
    return Response.json({ merge_base_commit: { sha: "e".repeat(40) } });
  };
  try {
    await assert.rejects(
      verifySignedSourceTag({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", GETPATCHED_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER }, "getpatched/packaging-libxml2", "getpatched/1.2.3", "b".repeat(40)),
      /reachable from getpatched\/focal/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Debian source tag ancestry is checked against its configured target branch", async () => {
  const originalFetch = globalThis.fetch;
  let comparisonSha = "b".repeat(40);
  let comparisonUrl;
  globalThis.fetch = async (url) => {
    const value = String(url);
    if (value.endsWith("/git/ref/tags/getpatched/1.2.3")) {
      return Response.json({ ref: "refs/tags/getpatched/1.2.3", object: { type: "tag", sha: "d".repeat(40) } });
    }
    if (value.endsWith("/graphql")) return Response.json({ data: { repository: { object: {
      __typename: "Tag", oid: "d".repeat(40), name: "getpatched/1.2.3",
      tagger: { email: "releases@getpatched.dev", user: { login: TEST_RELEASE_TAG_SIGNER } },
    } } } });
    if (value.includes("/git/tags/")) {
      return Response.json({ sha: "d".repeat(40), verification: { verified: true, reason: "valid" },
        tagger: { email: "releases@getpatched.dev" }, object: { type: "commit", sha: "b".repeat(40) } });
    }
    comparisonUrl = value;
    return Response.json({ merge_base_commit: { sha: comparisonSha } });
  };
  const env = { GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", GETPATCHED_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER };
  try {
    await verifySignedSourceTag(env, "getpatched/packaging-tiff", "getpatched/1.2.3", "b".repeat(40), "getpatched/debian-bookworm");
    assert.match(comparisonUrl, /compare\/getpatched%2Fdebian-bookworm\.\.\./);
    comparisonSha = "e".repeat(40);
    await assert.rejects(
      verifySignedSourceTag(env, "getpatched/packaging-tiff", "getpatched/1.2.3", "b".repeat(40), "getpatched/debian-bookworm"),
      /reachable from getpatched\/debian-bookworm/,
    );
  } finally { globalThis.fetch = originalFetch; }
});

test("public releases require repository-level immutable-release enforcement", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({ enabled: false });
  try {
    await assert.rejects(
      requireImmutableReleasesEnabled({ GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only" }, "getpatched/packaging-libxml2"),
      /must be enabled/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("public state audits fail closed if GitHub reports a mutable release", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({ draft: false, immutable: false, tag_name: "getpatched/1.2.3", assets: [] });
  const bucket = new MemoryBucket({
    "release-state/pilot.json": {
      id: "pilot", state: "public", repository: "getpatched/packaging-libxml2", tag: "getpatched/1.2.3",
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

test("public release staging copies remain for 30 days and are deleted after an immutable GitHub audit", async () => {
  const binaryBytes = Buffer.from("published binary");
  const sourceBytes = Buffer.from("published source");
  const binaryHash = createHash("sha256").update(binaryBytes).digest("hex");
  const sourceHash = createHash("sha256").update(sourceBytes).digest("hex");
  const record = {
    id: "pilot", state: "public", repository: "getpatched/packaging-libxml2", tag: "getpatched/2.9.10-getpatched1",
    source_commit: "b".repeat(40), public_release_id: 901, source_release_id: 902,
    source_release_tag: "getpatched-source/2.9.10-getpatched1", sponsor_delay_hours: 168,
    public_published_at: "2026-01-01T00:00:00.000Z", staging_cleanup_after: "2026-01-31T00:00:00.000Z",
    required_assets: [{ name: "libxml2.deb", sha256: binaryHash, r2_key: `staging/pilot/${binaryHash}` }],
    source_assets: [{ name: "libxml2.dsc", sha256: sourceHash, r2_key: `staging/pilot/source/${sourceHash}` }],
    verified_assets: [{ name: "libxml2.deb", sha256: binaryHash, r2_key: `staging/pilot/${binaryHash}` }],
  };
  const bucket = new MemoryAssetBucket(record);
  bucket.assets.set(record.required_assets[0].r2_key, { bytes: binaryBytes });
  bucket.assets.set(record.source_assets[0].r2_key, { bytes: sourceBytes });
  const originalFetch = globalThis.fetch;
  let sourceTampered = false;
  globalThis.fetch = async (url) => {
    const target = new URL(String(url));
    if (target.pathname.includes("/git/ref/tags/")) return Response.json({ ref: "refs/tags/getpatched/2.9.10-getpatched1", object: { type: "tag", sha: "d".repeat(40) } });
    if (target.pathname === "/graphql") return Response.json({ data: { repository: { object: {
      __typename: "Tag", oid: "d".repeat(40), name: "getpatched/2.9.10-getpatched1", tagger: { email: "releases@getpatched.dev", user: { login: TEST_RELEASE_TAG_SIGNER } },
    } } } });
    if (target.pathname.includes("/git/tags/")) return Response.json({ sha: "d".repeat(40), verification: { verified: true, reason: "valid" }, tagger: { email: "releases@getpatched.dev" }, object: { type: "commit", sha: record.source_commit } });
    if (target.pathname.includes("/compare/getpatched%2Ffocal...")) return Response.json({ merge_base_commit: { sha: record.source_commit } });
    if (target.pathname.endsWith("/releases/901")) return Response.json({ id: 901, tag_name: record.tag, draft: false, immutable: true, assets: [{ name: "libxml2.deb" }] });
    if (target.pathname.endsWith("/releases/902")) return Response.json({ id: 902, tag_name: record.source_release_tag, draft: false, immutable: true, assets: [{ name: "libxml2.dsc" }] });
    if (target.pathname.endsWith("/releases/901/assets")) return Response.json([{ name: "libxml2.deb", url: "https://api.github.com/assets/libxml2.deb" }]);
    if (target.pathname.endsWith("/releases/902/assets")) return Response.json([{ name: "libxml2.dsc", url: "https://api.github.com/assets/libxml2.dsc" }]);
    if (target.pathname === "/assets/libxml2.deb") return new Response(binaryBytes);
    if (target.pathname === "/assets/libxml2.dsc") return new Response(sourceTampered ? Buffer.from("altered source") : sourceBytes);
    return Response.json({});
  };
  try {
    const env = { RELEASES: bucket, GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", GETPATCHED_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER };
    await publishOne(env, "release-state/pilot.json", new Date("2026-01-30T23:59:59.999Z"));
    assert.equal(bucket.assets.has(record.required_assets[0].r2_key), true, "copies are still available immediately before the recovery deadline");
    sourceTampered = true;
    await assert.rejects(publishOne(env, "release-state/pilot.json", new Date("2026-01-31T00:00:00.000Z")), /source asset libxml2.dsc failed integrity audit/);
    assert.equal(bucket.assets.has(record.required_assets[0].r2_key), true, "a failed public source audit preserves binary recovery data");
    assert.equal(bucket.assets.has(record.source_assets[0].r2_key), true, "a failed public source audit preserves source recovery data");
    sourceTampered = false;
    await publishOne(env, "release-state/pilot.json", new Date("2026-01-31T00:00:00.000Z"));
    assert.equal(bucket.assets.has(record.required_assets[0].r2_key), false, "binary copy is deleted at the documented deadline");
    assert.equal(bucket.assets.has(record.source_assets[0].r2_key), false, "source copy is deleted after the public source asset audit");
  } finally { globalThis.fetch = originalFetch; }
});

test("prepared seven-day releases cannot bypass the private sponsor publication transition", async () => {
  const bucket = new MemoryBucket({
    "release-state/pilot.json": {
      id: "pilot", state: "prepared", repository: "getpatched/packaging-libxml2", tag: "getpatched/1.2.3",
      sponsor_delay_hours: 168, release_checks_passed: true,
      required_assets: [{ name: "libxml2.deb", sha256: "a".repeat(64), r2_key: "staging/libxml2" }],
    },
  });
  await assert.rejects(publishOne({ RELEASES: bucket }, "release-state/pilot.json", new Date()), /complete private sponsor publication before reconciliation/);
  assert.equal((await (await bucket.get("release-state/pilot.json")).json()).state, "prepared");
});

test("prepared releases are not reconciled until the immutable source release is recorded", async () => {
  const record = {
    id: "pilot", state: "prepared", repository: "getpatched/packaging-libarchive", tag: "getpatched/1.2.3+getpatched1",
    source_commit: "b".repeat(40), release_checks_passed: true, sponsor_delay_hours: 0,
    required_assets: [{ name: "libarchive.deb", sha256: "a".repeat(64), r2_key: "staging/pilot/binary" }],
    source_assets: [{ name: "libarchive.dsc", sha256: "c".repeat(64), r2_key: "staging/pilot/source" }],
  };
  const bucket = new MemoryBucket({ "release-state/pilot.json": record });
  const originalFetch = globalThis.fetch;
  let requests = 0;
  globalThis.fetch = async () => { requests += 1; throw new Error("must wait for source publication"); };
  try {
    await publishOne({ RELEASES: bucket, GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only" }, "release-state/pilot.json", new Date());
    assert.equal(requests, 0);
    assert.equal((await (await bucket.get("release-state/pilot.json")).json()).state, "prepared");
  } finally { globalThis.fetch = originalFetch; }
});

test("sponsor promotion stays closed before 168 hours and catches up after a missed cron window", async () => {
  const bytes = Buffer.from("verified sponsor package bytes");
  const digest = createHash("sha256").update(bytes).digest("hex");
  const deadline = new Date("2026-10-01T12:00:00.000Z");
  const key = "release-state/pilot.json";
  const originalFetch = globalThis.fetch;
  try {
    const missedCronOffsetMs = 8 * 24 * 60 * 60 * 1000;
    for (const [offsetMs, expectedState] of [
      [-1, "sponsor-period"],
      [0, "public"],
      [1, "public"],
      [missedCronOffsetMs, "public"],
    ]) {
      const bucket = new MemoryBucket({ [key]: {
        id: "pilot", state: "sponsor-period", repository: "getpatched/packaging-libxml2", tag: "getpatched/2.9.10-getpatched1",
        source_commit: "b".repeat(40), release_checks_passed: true, sponsor_delay_hours: 168, source_release_id: 902,
        sponsor_publication_complete: true, public_after: deadline.toISOString(),
        required_assets: [{ name: "libxml2_amd64.deb", sha256: digest, r2_key: `staging/pilot/${digest}` }],
      } });
      let packageAssetDownloads = 0;
      globalThis.fetch = async (url) => {
        const target = new URL(String(url));
        if (target.pathname.includes("/git/ref/tags/")) {
          return Response.json({ ref: "refs/tags/getpatched/2.9.10-getpatched1", object: { type: "tag", sha: "d".repeat(40) } });
        }
        if (target.pathname === "/graphql") return Response.json({ data: { repository: { object: {
          __typename: "Tag", oid: "d".repeat(40), name: "getpatched/2.9.10-getpatched1",
          tagger: { email: "releases@getpatched.dev", user: { login: TEST_RELEASE_TAG_SIGNER } },
        } } } });
        if (target.pathname.includes("/git/tags/")) {
          return Response.json({ sha: "d".repeat(40), verification: { verified: true, reason: "valid" }, tagger: { email: "releases@getpatched.dev" }, object: { type: "commit", sha: "b".repeat(40) } });
        }
        if (target.pathname.includes("/compare/getpatched%2Ffocal...")) return Response.json({ merge_base_commit: { sha: "b".repeat(40) } });
        if (target.pathname.includes("/releases/tags/")) {
          return Response.json({ id: 901, tag_name: "getpatched/2.9.10-getpatched1", draft: false, immutable: true, assets: [{ name: "libxml2_amd64.deb" }] });
        }
        if (target.pathname.endsWith("/releases/901/assets")) {
          return Response.json([{ name: "libxml2_amd64.deb", url: "https://api.github.com/assets/libxml2_amd64.deb" }]);
        }
        if (target.pathname === "/assets/libxml2_amd64.deb") {
          packageAssetDownloads += 1;
          return new Response(bytes);
        }
        return Response.json({});
      };
      const now = new Date(deadline.getTime() + offsetMs);
      const failures = await reconcile({ RELEASES: bucket, GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", GETPATCHED_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER }, now);
      assert.deepEqual(failures, [], `reconciliation should succeed at ${offsetMs} ms from deadline`);
      const saved = await (await bucket.get(key)).json();
      assert.equal(saved.state, expectedState, `release state at ${offsetMs} ms from deadline`);
      if (offsetMs < 0) {
        assert.equal(packageAssetDownloads, 0, "private package bytes must not be fetched for public publication before the deadline");
        assert.equal(saved.public_release_id, undefined);
      } else {
        assert.equal(saved.public_release_id, 901);
        assert.equal(packageAssetDownloads, 1, "eligible release bytes are fetched and verified exactly once");
        assert.equal(saved.public_published_at, now.toISOString());
        assert.deepEqual(saved.verified_assets, [{ name: "libxml2_amd64.deb", sha256: digest, r2_key: `staging/pilot/${digest}` }]);
      }
    }
  } finally { globalThis.fetch = originalFetch; }
});

test("zero-hour package publication is authenticated and completes synchronously", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: "immediate-release-test", use: "sig", alg: "RS256" };
  const bytes = Buffer.from("public package bytes");
  const digest = createHash("sha256").update(bytes).digest();
  const release = {
    id: "pilot", state: "prepared", repository: "getpatched/packaging-libarchive", tag: "getpatched/1.2.3",
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
    if (target.pathname.endsWith("/git/ref/tags/getpatched/1.2.3")) {
      return Response.json({ ref: "refs/tags/getpatched/1.2.3", object: { type: "tag", sha: "d".repeat(40) } });
    }
    if (target.pathname === "/graphql") return Response.json({ data: { repository: { object: {
      __typename: "Tag", oid: "d".repeat(40), name: "getpatched/1.2.3",
      tagger: { email: "releases@getpatched.dev", user: { login: TEST_RELEASE_TAG_SIGNER } },
    } } } });
    if (target.pathname.includes("/git/tags/")) {
      return Response.json({ sha: "d".repeat(40), verification: { verified: true, reason: "valid" }, tagger: { email: "releases@getpatched.dev" }, object: { type: "commit", sha: "b".repeat(40) } });
    }
    if (target.pathname.includes("/compare/getpatched%2Ffocal...")) return Response.json({ merge_base_commit: { sha: "b".repeat(40) } });
    if (target.pathname.endsWith("/releases/tags/getpatched%2F1.2.3")) return new Response("not found", { status: 404 });
    if (target.pathname.endsWith("/releases/tags/getpatched-source%2F1.2.3")) return new Response("not found", { status: 404 });
    if (target.pathname.includes("/releases/tags/")) return new Response("not found", { status: 404 });
    if (target.hostname === "uploads.github.com") {
      const name = target.searchParams.get("name");
      publishedAssets.set(name, Buffer.from(await new Response(options.body).arrayBuffer()));
      return Response.json({ name }, { status: 201 });
    }
    if (target.pathname.endsWith("/releases/901/assets")) {
      return Response.json([...publishedAssets].map(([name]) => ({ name, url: `https://api.github.com/assets/${name}` })));
    }
    if (target.pathname.endsWith("/releases/901")) return Response.json({ id: 901, tag_name: "getpatched-source/1.2.3", draft: false, immutable: true, assets: [...publishedAssets.keys()].map((name) => ({ name })) });
    if (target.pathname.startsWith("/assets/")) {
      const asset = publishedAssets.get(decodeURIComponent(target.pathname.slice("/assets/".length)));
      return asset ? new Response(asset) : new Response("missing", { status: 404 });
    }
    if (target.pathname.endsWith("/immutable-releases")) return Response.json({ enabled: true });
    if (target.pathname.endsWith("/releases/901") && options.method === "PATCH") {
      return Response.json({ id: 901, tag_name: "getpatched/1.2.3", draft: false, immutable: true, assets: [...publishedAssets.keys()].map((name) => ({ name })) });
    }
    if (target.pathname.endsWith("/releases") && options.method === "POST") {
      return Response.json({
        id: 901, tag_name: JSON.parse(options.body).tag_name, draft: true, assets: [], owner: { login: "getpatched" }, name: "packaging-libarchive",
        upload_url: "https://uploads.github.com/repos/getpatched/packaging-libarchive/releases/901/assets{?name,label}",
      });
    }
    return Response.json({});
  };
  try {
    const url = "https://getpatched.dev/internal/releases/pilot/publish-now";
    assert.equal((await gateway.fetch(new Request(url, { method: "POST" }), { RELEASES: bucket })).status, 401);
    const token = signedOidcToken(privateKey, {}, privateKey, "immediate-release-test");
    const sourceResponse = await gateway.fetch(new Request("https://getpatched.dev/internal/releases/pilot/publish-sources", {
      method: "POST", headers: { authorization: `Bearer ${token}` },
    }), { RELEASES: bucket, GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", GETPATCHED_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER });
    assert.equal(sourceResponse.status, 200, await sourceResponse.clone().text());
    const response = await gateway.fetch(new Request(url, {
      method: "POST", headers: { authorization: `Bearer ${token}` },
    }), { RELEASES: bucket, GITHUB_API: "https://api.github.com", GITHUB_TOKEN: "test-only", GETPATCHED_RELEASE_TAG_SIGNER: TEST_RELEASE_TAG_SIGNER });
    assert.equal(response.status, 200, await response.clone().text());
    const saved = await (await bucket.get("release-state/pilot.json")).json();
    assert.deepEqual(await response.json(), { id: "pilot", state: "public", source_release_tag: "getpatched-source/1.2.3", public_published_at: saved.public_published_at });
    assert.deepEqual(publishedAssets.get("libarchive.deb"), bytes);
    assert.equal(saved.state, "public");

    const gatedRecord = { ...release, sponsor_delay_hours: 168, required_assets: [] };
    const gatedBucket = new MemoryAssetBucket(gatedRecord);
    const gatedResponse = await gateway.fetch(new Request("https://getpatched.dev/internal/releases/pilot/publish-now", {
      method: "POST", headers: { authorization: `Bearer ${token}` },
    }), { RELEASES: gatedBucket });
    assert.equal(gatedResponse.status, 409);
    assert.equal((await (await gatedBucket.get("release-state/pilot.json")).json()).state, "prepared");
  } finally { globalThis.fetch = originalFetch; }
});
