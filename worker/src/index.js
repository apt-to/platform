import { handleSecurityPage, notFoundJson } from "./security-pages.js";

const STATE_PREFIX = "release-state/";
const MAX_RETRIES = 5;
const MAX_RELEASE_ASSET_BYTES = 64 * 1024 * 1024;
const MAX_REGISTRATION_BYTES = 64 * 1024;
const MAX_SNAPSHOT_FILES = 256;
const SNAPSHOT_ROLLBACK_RETENTION = 5;
const MAX_RETENTION_MANIFESTS = 10000;
const SNAPSHOT_BUILD_RECOVERY_MS = 24 * 60 * 60 * 1000;
const MAX_RETENTION_DELETIONS_PER_CHANNEL = 50;
const PUBLIC_RELEASE_STAGING_RECOVERY_MS = 30 * 24 * 60 * 60 * 1000;
const SNAPSHOT_ID_PATTERN = /^focal-([0-9]{4})([0-9]{2})([0-9]{2})T([0-9]{2})([0-9]{2})([0-9]{2})-r[0-9]{1,20}-(public|early)$/;
const REPOSITORY_TARGETS = {
  focal: { amd64: "ubuntu-focal-amd64" },
  bookworm: { amd64: "debian-bookworm-amd64" },
  trixie: { amd64: "debian-trixie-amd64" },
};
const MAX_SNAPSHOT_BYTES = 128 * 1024 * 1024;
const MAX_SPONSOR_WEBHOOK_BYTES = 256 * 1024;
const SPONSOR_ENTITLEMENTS_KEY = "sponsor-entitlements/current.json";
const SPONSOR_SNAPSHOT_MAX_AGE_MS = 30 * 60 * 1000;
const OIDC_ISSUER = "https://token.actions.githubusercontent.com";
const OIDC_AUDIENCE = "getpatched-release-gateway";
let oidcKeys;

function base64urlBytes(text) {
  const value = text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "=");
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

async function githubActionsIdentity(request, env) {
  const auth = request.headers.get("authorization") || "";
  if (env.RELEASE_ADMIN_TOKEN && auth === `Bearer ${env.RELEASE_ADMIN_TOKEN}`) return { type: "admin" };
  if (!auth.startsWith("Bearer ")) return null;
  try {
    const token = auth.slice(7);
    if (token.length > 8192) return null;
    const [encodedHeader, encodedClaims, encodedSignature, extra] = token.split(".");
    if (!encodedHeader || !encodedClaims || !encodedSignature || extra !== undefined) return null;
    const header = JSON.parse(new TextDecoder().decode(base64urlBytes(encodedHeader)));
    const claims = JSON.parse(new TextDecoder().decode(base64urlBytes(encodedClaims)));
    if (header.alg !== "RS256" || typeof header.kid !== "string") return null;
    if (!oidcKeys) {
      const response = await fetch(`${OIDC_ISSUER}/.well-known/jwks`);
      if (!response.ok) return null;
      oidcKeys = (await response.json()).keys || [];
    }
    let jwk = oidcKeys.find((candidate) => candidate.kid === header.kid && candidate.kty === "RSA" && candidate.use === "sig");
    if (!jwk) {
      const response = await fetch(`${OIDC_ISSUER}/.well-known/jwks`);
      if (!response.ok) return null;
      oidcKeys = (await response.json()).keys || [];
      jwk = oidcKeys.find((candidate) => candidate.kid === header.kid && candidate.kty === "RSA" && candidate.use === "sig");
    }
    if (!jwk) return null;
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    if (!await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, base64urlBytes(encodedSignature), new TextEncoder().encode(`${encodedHeader}.${encodedClaims}`))) return null;
    const now = Math.floor(Date.now() / 1000);
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    const stagingWorkflow = claims.workflow_ref === "getpatched/platform/.github/workflows/private-staging.yml@refs/heads/main" && claims.event_name === "workflow_run";
    const snapshotWorkflow = claims.workflow_ref === "getpatched/platform/.github/workflows/repository-snapshot.yml@refs/heads/main" &&
      ["workflow_run", "schedule", "workflow_dispatch"].includes(claims.event_name);
    const r2SelfTestWorkflow = claims.workflow_ref === "getpatched/platform/.github/workflows/r2-storage-self-test.yml@refs/heads/main" &&
      claims.event_name === "workflow_dispatch";
    const runAttempt = typeof claims.run_attempt === "string" && /^\d+$/.test(claims.run_attempt) ? Number(claims.run_attempt) : claims.run_attempt;
    if (claims.iss !== OIDC_ISSUER || audiences.length !== 1 || audiences[0] !== OIDC_AUDIENCE || !Number.isSafeInteger(claims.exp) || claims.exp <= now ||
        !Number.isSafeInteger(claims.iat) || claims.iat > now + 60 || claims.repository !== "getpatched/platform" || claims.repository_id !== "1433070541" ||
        claims.repository_owner !== "getpatched" || claims.repository_visibility !== "public" || !(stagingWorkflow || snapshotWorkflow || r2SelfTestWorkflow) ||
        claims.ref !== "refs/heads/main" ||
        claims.runner_environment !== "github-hosted" ||
        (stagingWorkflow ? claims.environment !== "getpatched-signing" :
          r2SelfTestWorkflow ? claims.environment !== "getpatched-index-build" :
            !["getpatched-index-build", "getpatched-signing"].includes(claims.environment)) ||
        !/^\d+$/.test(String(claims.run_id || "")) || !Number.isSafeInteger(runAttempt) || runAttempt < 1 ||
        (claims.nbf !== undefined && (!Number.isSafeInteger(claims.nbf) || claims.nbf > now + 60)) || typeof claims.jti !== "string" || !claims.jti) return null;
    return {
      type: "github-actions",
      run_id: Number(claims.run_id),
      run_attempt: runAttempt,
      environment: claims.environment,
      workflow: stagingWorkflow ? "private-staging" : r2SelfTestWorkflow ? "r2-storage-self-test" : "repository-snapshot",
    };
  } catch { return null; }
}

async function verifyR2Binding(request, env) {
  const identity = await githubActionsIdentity(request, env);
  if (!identity || identity.type !== "github-actions" || identity.workflow !== "r2-storage-self-test" ||
      identity.environment !== "getpatched-index-build") {
    return json({ error: "protected R2 self-test workflow identity required" }, 401);
  }
  if (!env.RELEASES) return json({ error: "release storage is unavailable" }, 503);

  const nonce = crypto.randomUUID();
  const key = `diagnostics/r2-self-test/${identity.run_id}-${identity.run_attempt}-${nonce}.bin`;
  const bytes = new TextEncoder().encode(`GetPatched R2 self-test\nrun=${identity.run_id}\nattempt=${identity.run_attempt}\nnonce=${nonce}\n`);
  const digest = await sha256Hex(bytes);
  let writeAttempted = false;
  let writeRejected = false;
  let failureStage = null;
  let readBackOk = false;
  let cleanupOk = false;
  let cleanupObjectKey = null;

  try {
    writeAttempted = true;
    const stored = await env.RELEASES.put(key, bytes, {
      onlyIf: { etagDoesNotMatch: "*" },
      sha256: checksumBuffer(digest),
      httpMetadata: { contentType: "application/octet-stream" },
      customMetadata: { purpose: "r2-storage-self-test", nonce, runId: String(identity.run_id) },
    });
    if (!stored) {
      writeRejected = true;
      failureStage = "unique-write";
    }
    else {
      const metadata = await env.RELEASES.head(key);
      const object = await env.RELEASES.get(key);
      const responseBytes = object ? await object.arrayBuffer() : null;
      if (!metadata || !object || metadata.size !== bytes.byteLength || checksumHex(metadata.checksums?.sha256) !== digest ||
          metadata.customMetadata?.nonce !== nonce || !responseBytes || responseBytes.byteLength !== bytes.byteLength ||
          await sha256Hex(responseBytes) !== digest) {
        failureStage = "readback";
      } else readBackOk = true;
    }
  } catch {
    failureStage ||= "write-readback";
  } finally {
    if (writeAttempted) {
      try {
        const metadata = await env.RELEASES.head(key);
        if (!metadata) cleanupOk = true;
        else if (metadata.customMetadata?.nonce === nonce) {
          await env.RELEASES.delete(key);
          const remaining = await env.RELEASES.head(key);
          cleanupOk = !remaining;
          if (remaining?.customMetadata?.nonce === nonce) cleanupObjectKey = key;
        } else if (writeRejected) cleanupOk = true;
        else failureStage ||= "cleanup";
      } catch {
        failureStage ||= "cleanup";
        try {
          const remaining = await env.RELEASES.head(key);
          cleanupOk = !remaining;
          if (remaining?.customMetadata?.nonce === nonce) cleanupObjectKey = key;
        } catch { /* Keep cleanup failed when R2 cannot confirm object state. */ }
      }
    }
  }

  if (!readBackOk || !cleanupOk) return json({
    error: "R2 storage self-test failed",
    stage: failureStage || (!cleanupOk ? "cleanup" : "readback"),
    cleaned: cleanupOk,
    object_key: cleanupObjectKey,
  }, 502);
  return json({ ok: true, operation: "write-read-delete", bytes: bytes.byteLength, sha256: digest, run_id: identity.run_id, cleaned: true });
}

function requestError(message, status) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

function parseUtc(value) {
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || !/(Z|[+-]\d\d:\d\d)$/.test(value)) {
    throw new Error("timestamps must include a valid UTC offset");
  }
  return parsed;
}

function canonicalAssets(assets) {
  if (!Array.isArray(assets) || assets.length === 0) throw new Error("assets must be a non-empty array");
  const names = new Set();
  return assets.map((asset) => {
    if (!asset || typeof asset.name !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._+~-]*$/.test(asset.name)) {
      throw new Error("asset names must be safe basenames");
    }
    if (names.has(asset.name)) throw new Error("asset names must be unique");
    names.add(asset.name);
    if (!/^[a-f0-9]{64}$/.test(asset.sha256)) throw new Error("asset sha256 must be lowercase hex");
    if (typeof asset.r2_key !== "string" || !asset.r2_key.startsWith("staging/")) {
      throw new Error("asset must point to a private staging object");
    }
    return { name: asset.name, sha256: asset.sha256, r2_key: asset.r2_key };
  }).sort((a, b) => a.name.localeCompare(b.name));
}

function releaseAssets(assets, id) {
  stateKey(id);
  if (!Array.isArray(assets)) throw new Error("assets must be a non-empty array");
  return canonicalAssets(assets.map((asset) => ({
    ...asset,
    r2_key: `staging/${id}/${asset?.sha256}`,
  })));
}

function sourceReleaseTag(record) {
  return `getpatched-source/${record.tag.slice("getpatched/".length)}`;
}

function checksumBuffer(hex) {
  return Uint8Array.from(hex.match(/.{2}/g), (pair) => Number.parseInt(pair, 16)).buffer;
}

function checksumHex(value) {
  if (!value) return null;
  return [...new Uint8Array(value)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function repositoryTarget(suite, architecture) {
  if (!Object.hasOwn(REPOSITORY_TARGETS, suite) || !Object.hasOwn(REPOSITORY_TARGETS[suite], architecture)) {
    throw requestError("unsupported repository suite and architecture", 400);
  }
  return { suite, architecture, targetId: REPOSITORY_TARGETS[suite][architecture] };
}

function repositoryCurrentKey(channel, target) {
  if (!["public", "early"].includes(channel)) throw requestError("invalid repository channel", 400);
  return target.suite === "focal" && target.architecture === "amd64"
    ? `repository-current/${channel}.json`
    : `repository-current/${channel}/${target.suite}/${target.architecture}.json`;
}

function validSnapshotId(id, channel, suite, architecture) {
  const channelPattern = channel === "public" || channel === "early" ? channel : "(?!)";
  const prefix = suite === "focal" && architecture === "amd64" ? "focal-" : `${suite}-${architecture}-`;
  return typeof id === "string" && new RegExp(`^${prefix}([0-9]{8})T([0-9]{6})-r[0-9]{1,20}-${channelPattern}$`).test(id);
}

function snapshotKey(channel, id) {
  if (!['public', 'early'].includes(channel) || !/^[A-Za-z0-9][A-Za-z0-9-]{2,79}$/.test(id)) {
    throw requestError("invalid repository snapshot identity", 400);
  }
  return `repository-snapshots/${channel}/${id}.json`;
}

function snapshotBuildKey(channel, id) {
  if (!['public', 'early'].includes(channel) || !/^[A-Za-z0-9][A-Za-z0-9-]{2,79}$/.test(id)) {
    throw requestError("invalid repository snapshot build identity", 400);
  }
  return `repository-snapshot-builds/${channel}/${id}.json`;
}

function snapshotBuildFilePath(value, suite = "focal") {
  if (!Object.hasOwn(REPOSITORY_TARGETS, suite)) return false;
  const root = `dists/${suite}`;
  return typeof value === "string" && value.length <= 512 &&
    new RegExp(`^${root}/(?:[A-Za-z0-9][A-Za-z0-9._+~-]*/)*[A-Za-z0-9][A-Za-z0-9._+~-]*$`).test(value) &&
    ![`${root}/InRelease`, `${root}/Release.gpg`].includes(value);
}

function canonicalSnapshotBuildFiles(files, suite = "focal", architecture = "amd64") {
  const target = repositoryTarget(suite, architecture);
  if (!Array.isArray(files) || files.length < 7 || files.length > MAX_SNAPSHOT_FILES) throw requestError(`snapshot build must contain ${suite} indexes`, 400);
  const seen = new Set();
  let total = 0;
  const normalized = files.map((file) => {
    if (!file || !snapshotBuildFilePath(file.path, suite) || seen.has(file.path) || !/^[a-f0-9]{64}$/.test(file.sha256) ||
        !Number.isSafeInteger(file.size) || file.size <= 0 || file.size > MAX_RELEASE_ASSET_BYTES) {
      throw requestError("snapshot build file path, size or SHA-256 is invalid", 400);
    }
    total += file.size;
    if (total > MAX_SNAPSHOT_BYTES) throw requestError("snapshot build exceeds the 128 MiB limit", 413);
    seen.add(file.path);
    return { path: file.path, size: file.size, sha256: file.sha256, content_type: snapshotContentType(file.path) };
  }).sort((a, b) => a.path.localeCompare(b.path));
  const required = [
    `dists/${suite}/Release`,
    `dists/${suite}/main/binary-${target.architecture}/Packages`, `dists/${suite}/main/binary-${target.architecture}/Packages.gz`, `dists/${suite}/main/binary-${target.architecture}/Packages.xz`,
    `dists/${suite}/main/source/Sources`, `dists/${suite}/main/source/Sources.gz`, `dists/${suite}/main/source/Sources.xz`,
  ];
  if (required.some((path) => !seen.has(path))) throw requestError(`snapshot build is missing required ${suite} indexes`, 400);
  return normalized;
}

function snapshotFilePath(value, suite = "focal") {
  if (typeof value !== "string" || value.length > 512) return false;
  if (value === "getpatched-archive-keyring.gpg") return true;
  if (!Object.hasOwn(REPOSITORY_TARGETS, suite)) return false;
  const root = `dists/${suite}`;
  return new RegExp(`^${root}/(?:[A-Za-z0-9][A-Za-z0-9._+~-]*/)*[A-Za-z0-9][A-Za-z0-9._+~-]*$`).test(value) ||
    new RegExp(`^${root}/(?:[A-Za-z0-9][A-Za-z0-9._+~-]*/)*[A-Za-z0-9][A-Za-z0-9._+~-]*/by-hash/SHA256/[a-f0-9]{64}$`).test(value);
}

function snapshotContentType(path) {
  if (path === "getpatched-archive-keyring.gpg") return "application/pgp-keys";
  if (path.endsWith(".gz")) return "application/gzip";
  if (path.endsWith(".xz")) return "application/x-xz";
  if (path.endsWith(".gpg")) return "application/pgp-signature";
  return "text/plain; charset=utf-8";
}

function canonicalSnapshotFiles(files, suite = "focal", architecture = "amd64") {
  const target = repositoryTarget(suite, architecture);
  if (!Array.isArray(files) || files.length < 10 || files.length > MAX_SNAPSHOT_FILES) {
    throw requestError(`snapshot must contain signed ${suite} indexes and the public archive key`, 400);
  }
  const seen = new Set();
  let total = 0;
  const normalized = files.map((file) => {
    if (!file || !snapshotFilePath(file.path, suite) || seen.has(file.path)) throw requestError("snapshot file path is invalid or duplicated", 400);
    if (!/^[a-f0-9]{64}$/.test(file.sha256) || !Number.isSafeInteger(file.size) || file.size <= 0 || file.size > MAX_RELEASE_ASSET_BYTES) {
      throw requestError("snapshot file size or SHA-256 is invalid", 400);
    }
    const contentType = snapshotContentType(file.path);
    if (file.content_type !== undefined && file.content_type !== contentType) throw requestError("snapshot content type is not allowed for this path", 400);
    total += file.size;
    if (total > MAX_SNAPSHOT_BYTES) throw requestError("snapshot exceeds the 128 MiB limit", 413);
    seen.add(file.path);
    return { path: file.path, sha256: file.sha256, size: file.size, content_type: contentType };
  }).sort((a, b) => a.path.localeCompare(b.path));
  const required = [
    `dists/${suite}/Release`, `dists/${suite}/InRelease`, `dists/${suite}/Release.gpg`,
    `dists/${suite}/main/binary-${target.architecture}/Packages`, `dists/${suite}/main/binary-${target.architecture}/Packages.gz`, `dists/${suite}/main/binary-${target.architecture}/Packages.xz`,
    `dists/${suite}/main/source/Sources`, `dists/${suite}/main/source/Sources.gz`, `dists/${suite}/main/source/Sources.xz`,
    "getpatched-archive-keyring.gpg",
  ];
  if (required.some((path) => !seen.has(path))) throw requestError(`snapshot is missing signed ${suite} indexes or the public archive key`, 400);
  return normalized;
}

async function snapshotEligibilityError(env, channel, releaseIds, now = Date.now(), suite = "focal", architecture = "amd64") {
  const target = repositoryTarget(suite, architecture);
  for (const id of releaseIds) {
    let releaseKey;
    try { releaseKey = stateKey(id); }
    catch { return "snapshot references an invalid release id"; }
    const release = (await readRecord(env.RELEASES, releaseKey))?.record;
    if (!release) return `snapshot release is missing: ${id}`;
    try { assertRelease(release); }
    catch (error) { return String(error.message || error); }
    if ((release.target_id || "ubuntu-focal-amd64") !== target.targetId) return `release does not match the ${suite}/${architecture} repository target: ${id}`;
    const allowed = channel === "public" ? release.state === "public" :
      release.state === "public" || (release.state === "sponsor-period" && release.sponsor_publication_complete === true && Date.parse(release.public_after) > now);
    if (!allowed || release.release_checks_passed !== true) return `release is not eligible for the ${channel} repository snapshot: ${id}`;
  }
  return null;
}

async function activeSnapshotHealth(env, channel, activeId, suite = "focal", architecture = "amd64") {
  if (!activeId) return null;
  let key;
  try { key = snapshotKey(channel, activeId); } catch { return null; }
  const snapshot = (await readRecord(env.RELEASES, key))?.record;
  if (!snapshot || snapshot.id !== activeId || snapshot.channel !== channel ||
      (snapshot.suite || "focal") !== suite || (snapshot.architecture || "amd64") !== architecture || !Array.isArray(snapshot.release_ids)) return null;
  let files;
  try { files = canonicalSnapshotFiles(snapshot.files, suite, architecture); } catch { return null; }
  if (await snapshotEligibilityError(env, channel, snapshot.release_ids, Date.now(), suite, architecture)) return { id: activeId, release_ids: snapshot.release_ids, healthy: false };
  for (const file of files) {
    const object = await env.RELEASES.head(`repository-snapshots/${channel}/${activeId}/${file.path}`);
    if (!object || object.size !== file.size || checksumHex(object.checksums?.sha256) !== file.sha256 ||
        object.customMetadata?.snapshotId !== activeId || object.customMetadata?.channel !== channel || object.customMetadata?.path !== file.path) {
      return { id: activeId, release_ids: snapshot.release_ids, healthy: false };
    }
  }
  return { id: activeId, release_ids: snapshot.release_ids, healthy: true };
}

async function listRetentionManifests(bucket, prefix) {
  const keys = [];
  let cursor;
  do {
    const page = await bucket.list({ prefix, delimiter: "/", cursor, limit: 1000 });
    if (!page || !Array.isArray(page.objects) || typeof page.truncated !== "boolean") throw new Error("R2 returned an invalid retention listing");
    for (const object of page.objects) {
      if (typeof object.key === "string" && object.key.endsWith(".json")) keys.push(object.key);
    }
    if (keys.length > MAX_RETENTION_MANIFESTS) throw new Error("retention manifest inventory exceeds its safety limit");
    if (!page.truncated) break;
    if (typeof page.cursor !== "string" || !page.cursor || page.cursor === cursor) throw new Error("R2 retention listing returned an invalid cursor");
    cursor = page.cursor;
  } while (cursor);
  return keys;
}

async function deleteR2Prefix(bucket, prefix) {
  const keys = [];
  let cursor;
  do {
    const page = await bucket.list({ prefix, cursor, limit: 1000 });
    if (!page || !Array.isArray(page.objects) || typeof page.truncated !== "boolean") throw new Error("R2 returned an invalid cleanup listing");
    for (const object of page.objects) {
      if (typeof object.key !== "string" || !object.key.startsWith(prefix)) throw new Error("R2 cleanup listing escaped its exact object prefix");
      keys.push(object.key);
    }
    if (keys.length > 1000) throw new Error("cleanup object prefix exceeds the R2 delete batch safety limit");
    if (!page.truncated) break;
    if (typeof page.cursor !== "string" || !page.cursor || page.cursor === cursor) throw new Error("R2 cleanup listing returned an invalid cursor");
    cursor = page.cursor;
  } while (cursor);
  if (keys.length) await bucket.delete(keys);
  return keys.length;
}

async function deleteRepositorySnapshot(env, channel, id) {
  const prefix = `repository-snapshots/${channel}/${id}/`;
  const deletedFiles = await deleteR2Prefix(env.RELEASES, prefix);
  await env.RELEASES.delete(snapshotKey(channel, id));
  return deletedFiles + 1;
}

async function deleteRepositorySnapshotBuild(env, channel, id) {
  const prefix = `repository-snapshot-builds/${channel}/${id}/`;
  const deletedFiles = await deleteR2Prefix(env.RELEASES, prefix);
  await env.RELEASES.delete(snapshotBuildKey(channel, id));
  return deletedFiles + 1;
}

function snapshotTimestampFromId(id, suite, architecture) {
  const prefix = suite === "focal" && architecture === "amd64" ? "focal-" : `${suite}-${architecture}-`;
  const match = typeof id === "string"
    ? new RegExp(`^${prefix}([0-9]{4})([0-9]{2})([0-9]{2})T([0-9]{2})([0-9]{2})([0-9]{2})-r[0-9]{1,20}-(?:public|early)$`).exec(id)
    : null;
  if (!match) return null;
  const value = `${match[1]}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}Z`;
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value.replace("Z", ".000Z")) return null;
  return timestamp;
}

function validRetainedSnapshot(snapshot, channel, id, suite = "focal", architecture = "amd64") {
  if (!snapshot || snapshot.id !== id || snapshot.channel !== channel || !Array.isArray(snapshot.release_ids) ||
      !snapshot.release_ids.length || snapshot.release_ids.length > 32 || new Set(snapshot.release_ids).size !== snapshot.release_ids.length ||
      snapshot.release_ids.some((releaseId) => typeof releaseId !== "string" || !/^[a-z0-9][a-z0-9-]{1,100}$/.test(releaseId)) ||
      (snapshot.suite || "focal") !== suite || (snapshot.architecture || "amd64") !== architecture) return false;
  try { canonicalSnapshotFiles(snapshot.files, suite, architecture); } catch { return false; }
  return true;
}

async function pruneRepositorySnapshotTarget(env, channel, suite, architecture) {
  const now = Date.now();
  const target = repositoryTarget(suite, architecture);
  const pointer = (await readRecord(env.RELEASES, repositoryCurrentKey(channel, target)))?.record;
  const activeId = pointer?.id ?? null;
  if (activeId !== null && !validSnapshotId(activeId, channel, suite, architecture)) {
    throw new Error(`active ${channel} ${suite}/${architecture} snapshot pointer is invalid`);
  }
  const manifestPrefix = `repository-snapshots/${channel}/`;
  const manifestKeys = await listRetentionManifests(env.RELEASES, manifestPrefix);
  const allIds = new Set();
  for (const key of manifestKeys) {
    const match = key.match(/^repository-snapshots\/(public|early)\/([A-Za-z0-9][A-Za-z0-9-]{2,79})\.json$/);
    if (!match || match[1] !== channel) throw new Error("snapshot retention found an invalid manifest key");
    if (validSnapshotId(match[2], channel, suite, architecture)) allIds.add(match[2]);
  }
  if (activeId && !allIds.has(activeId)) throw new Error("active snapshot manifest is missing; retention stopped");

  let activeSnapshot = null;
  if (activeId) {
    activeSnapshot = (await readRecord(env.RELEASES, snapshotKey(channel, activeId)))?.record;
    if (!validRetainedSnapshot(activeSnapshot, channel, activeId, suite, architecture)) throw new Error("active snapshot manifest is invalid; retention stopped");
    if (await snapshotEligibilityError(env, channel, activeSnapshot.release_ids, now, suite, architecture)) throw new Error("active snapshot is no longer eligible; retention stopped");
    for (const file of canonicalSnapshotFiles(activeSnapshot.files, suite, architecture)) {
      const object = await env.RELEASES.head(`repository-snapshots/${channel}/${activeId}/${file.path}`);
      if (!object || object.size !== file.size || checksumHex(object.checksums?.sha256) !== file.sha256 ||
          object.customMetadata?.snapshotId !== activeId || object.customMetadata?.channel !== channel || object.customMetadata?.path !== file.path) {
        throw new Error("active snapshot failed readback; retention stopped");
      }
    }
  }

  const historyKey = snapshotHistoryKey(channel, suite, architecture);
  const history = (await readRecord(env.RELEASES, historyKey))?.record;
  if (history && (history.channel !== channel || (history.suite || "focal") !== suite || (history.architecture || "amd64") !== architecture ||
      !Array.isArray(history.snapshot_ids) || history.snapshot_ids.length > SNAPSHOT_ROLLBACK_RETENTION + 1 ||
      new Set(history.snapshot_ids).size !== history.snapshot_ids.length || history.snapshot_ids.some((id) =>
        !validSnapshotId(id, channel, suite, architecture)))) {
    throw new Error("repository snapshot activation history is invalid; retention stopped");
  }
  if (activeId) {
    try { await recordSnapshotActivation(env, channel, activeId, null, suite, architecture); }
    catch { throw new Error("repository snapshot activation history could not be reconciled; retention stopped"); }
  }
  const updatedHistory = (await readRecord(env.RELEASES, historyKey))?.record;
  const retainedIds = new Set(activeId ? [activeId] : []);
  for (const id of updatedHistory?.snapshot_ids || []) {
    if (id === activeId || !allIds.has(id)) continue;
    const snapshot = (await readRecord(env.RELEASES, snapshotKey(channel, id)))?.record;
    if (!validRetainedSnapshot(snapshot, channel, id, suite, architecture) ||
        await snapshotEligibilityError(env, channel, snapshot.release_ids, now, suite, architecture)) continue;
    retainedIds.add(id);
  }

  const candidates = [...allIds].filter((id) => !retainedIds.has(id)).sort();
  const snapshotBatch = candidates.slice(0, MAX_RETENTION_DELETIONS_PER_CHANNEL);
  let deletedObjects = 0;
  for (const id of snapshotBatch) deletedObjects += await deleteRepositorySnapshot(env, channel, id);

  const buildPrefix = `repository-snapshot-builds/${channel}/`;
  const buildManifestKeys = await listRetentionManifests(env.RELEASES, buildPrefix);
  const buildIds = [];
  for (const key of buildManifestKeys) {
    const match = key.match(/^repository-snapshot-builds\/(public|early)\/([A-Za-z0-9][A-Za-z0-9-]{2,79})\.json$/);
    if (!match || match[1] !== channel) throw new Error("snapshot retention found an invalid build manifest key");
    if (!validSnapshotId(match[2], channel, suite, architecture)) continue;
    const timestamp = snapshotTimestampFromId(match[2], suite, architecture);
    if (timestamp === null || timestamp > now + 5 * 60 * 1000) buildIds.push({ id: match[2], timestamp: null });
    else buildIds.push({ id: match[2], timestamp });
  }
  buildIds.sort((a, b) => (b.timestamp ?? -1) - (a.timestamp ?? -1) || b.id.localeCompare(a.id));
  const newestBuild = buildIds.find((build) => build.timestamp !== null && build.timestamp > now - SNAPSHOT_BUILD_RECOVERY_MS);
  const expiredBuilds = buildIds.filter((build) => build !== newestBuild).sort((a, b) => (a.timestamp ?? -1) - (b.timestamp ?? -1) || a.id.localeCompare(b.id));
  const buildBatch = expiredBuilds.slice(0, MAX_RETENTION_DELETIONS_PER_CHANNEL);
  for (const build of buildBatch) deletedObjects += await deleteRepositorySnapshotBuild(env, channel, build.id);

  return {
    retained_snapshots: retainedIds.size,
    deleted_snapshots: snapshotBatch.length,
    pending_snapshots: candidates.length - snapshotBatch.length,
    retained_builds: newestBuild ? 1 : 0,
    deleted_builds: buildBatch.length,
    pending_builds: expiredBuilds.length - buildBatch.length,
    deleted_objects: deletedObjects,
  };
}

async function pruneRepositorySnapshotChannel(env, channel) {
  const results = [];
  for (const [suite, architectures] of Object.entries(REPOSITORY_TARGETS)) {
    for (const architecture of Object.keys(architectures)) {
      results.push(await pruneRepositorySnapshotTarget(env, channel, suite, architecture));
    }
  }
  return results.reduce((total, result) => Object.fromEntries(
    Object.keys(result).map((key) => [key, (total[key] || 0) + result[key]]),
  ), {});
}

async function pruneRepositorySnapshots(request, env) {
  if (!await snapshotPublisherIdentity(request, env)) return json({ error: "protected snapshot signer identity required" }, 401);
  if (!env.RELEASES) return json({ error: "release storage is unavailable" }, 503);
  let body;
  try { body = await readBoundedJson(request, 4096); }
  catch (error) { return json({ error: String(error.message || error) }, error.status || 400); }
  if (!body || !Array.isArray(body.channels) || !body.channels.length || body.channels.length > 2 ||
      new Set(body.channels).size !== body.channels.length || body.channels.some((channel) => !["public", "early"].includes(channel))) {
    return json({ error: "retention requires unique public and/or early channels" }, 400);
  }
  const results = {};
  try {
    for (const channel of body.channels) results[channel] = await pruneRepositorySnapshotChannel(env, channel);
  } catch (error) {
    return json({ error: String(error.message || error) }, 503);
  }
  return json({ channels: results, rollback_snapshots_kept_per_channel: SNAPSHOT_ROLLBACK_RETENTION });
}

async function snapshotPublisherIdentity(request, env) {
  const identity = await githubActionsIdentity(request, env);
  if (!identity || identity.type !== "github-actions" || identity.environment !== "getpatched-signing") return null;
  const claims = await githubActionsClaims(request, env);
  return claims?.workflow_ref === "getpatched/platform/.github/workflows/repository-snapshot.yml@refs/heads/main" ? identity : null;
}

async function snapshotBuilderIdentity(request, env) {
  const identity = await githubActionsIdentity(request, env);
  if (!identity || identity.type !== "github-actions" || identity.environment !== "getpatched-index-build") return null;
  const claims = await githubActionsClaims(request, env);
  return claims?.workflow_ref === "getpatched/platform/.github/workflows/repository-snapshot.yml@refs/heads/main" ? identity : null;
}

async function githubActionsClaims(request, env) {
  const auth = request.headers.get("authorization") || "";
  if (!auth.startsWith("Bearer ")) return null;
  try {
    const encoded = auth.slice(7).split(".")[1];
    return JSON.parse(new TextDecoder().decode(base64urlBytes(encoded)));
  } catch { return null; }
}

async function listSnapshotReleases(request, env, channel) {
  if (!await snapshotBuilderIdentity(request, env)) return json({ error: "protected snapshot builder identity required" }, 401);
  if (!env.RELEASES) return json({ error: "release storage is unavailable" }, 503);
  let target;
  try {
    const url = new URL(request.url);
    target = repositoryTarget(url.searchParams.get("suite") || "focal", url.searchParams.get("architecture") || "amd64");
  } catch (error) { return json({ error: String(error.message || error) }, error.status || 400); }
  let cursor;
  const releases = [];
  do {
    const page = await env.RELEASES.list({ prefix: STATE_PREFIX, cursor, limit: 1000 });
    for (const item of page.objects) {
      const loaded = await readRecord(env.RELEASES, item.key);
      const record = loaded?.record;
      if (!record || !["public", "sponsor-period"].includes(record.state)) continue;
      if ((record.target_id || "ubuntu-focal-amd64") !== target.targetId) continue;
      try { assertRelease(record); } catch { return json({ error: "stored release state failed validation" }, 503); }
      if (record.release_checks_passed !== true || (channel === "public" && record.state !== "public")) continue;
      if (channel === "early" && record.state === "sponsor-period" &&
          (record.sponsor_publication_complete !== true || Date.parse(record.public_after) <= Date.now())) continue;
      const required = canonicalAssets(record.required_assets);
      const source = record.source_assets?.length ? canonicalAssets(record.source_assets) : [];
      releases.push({
        id: record.id, state: record.state, repository: record.repository, tag: record.tag, source_commit: record.source_commit,
        public_release_id: record.public_release_id ?? null, source_release_id: record.source_release_id ?? null,
        public_after: record.public_after ?? null,
        required_assets: required.map(({ name, sha256 }) => ({ name, sha256 })),
        source_assets: source.map(({ name, sha256 }) => ({ name, sha256 })),
      });
      if (releases.length > 32) return json({ error: `too many releases for one ${target.suite} snapshot` }, 413);
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  releases.sort((a, b) => a.id.localeCompare(b.id));
  const activePointer = (await readRecord(env.RELEASES, repositoryCurrentKey(channel, target)))?.record;
  const activeSnapshot = await activeSnapshotHealth(env, channel, activePointer?.id, target.suite, target.architecture);
  return json({ channel, suite: target.suite, architecture: target.architecture, releases, active_snapshot: activeSnapshot });
}

async function readSnapshotReleaseAsset(request, env, channel, id, name) {
  if (!await snapshotBuilderIdentity(request, env)) return json({ error: "protected snapshot builder identity required" }, 401);
  let key;
  try { key = stateKey(id); } catch { return json({ error: "invalid release id" }, 400); }
  if (!/^[A-Za-z0-9][A-Za-z0-9._+~-]*$/.test(name)) return json({ error: "invalid asset name" }, 400);
  const loaded = await readRecord(env.RELEASES, key);
  if (!loaded) return json({ error: "release not found" }, 404);
  const record = loaded.record;
  try { assertRelease(record); } catch { return json({ error: "stored release state failed validation" }, 503); }
  const eligible = record.release_checks_passed === true && (channel === "public" ? record.state === "public" :
    record.state === "public" || (record.state === "sponsor-period" && record.sponsor_publication_complete === true && Date.parse(record.public_after) > Date.now()));
  if (!eligible) return json({ error: "release is not eligible for the requested repository channel" }, 409);
  if (record.state !== "sponsor-period") return json({ error: "private snapshot export is only available for gated releases" }, 409);
  const asset = canonicalAssets(record.required_assets).find((candidate) => candidate.name === name);
  if (!asset) return json({ error: "asset is not in the release manifest" }, 404);
  const object = await env.RELEASES.get(asset.r2_key);
  if (!object || !Number.isSafeInteger(object.size) || object.size <= 0 || object.size > MAX_RELEASE_ASSET_BYTES ||
      checksumHex(object.checksums?.sha256) !== asset.sha256 || object.customMetadata?.releaseId !== id || object.customMetadata?.assetName !== name) {
    return json({ error: "private asset failed stored identity or checksum verification" }, 502);
  }
  return new Response(request.method === "HEAD" ? null : object.body, { headers: {
    "content-type": "application/vnd.debian.binary-package", "content-length": String(object.size),
    "cache-control": "private, no-store", "x-content-type-options": "nosniff",
  } });
}

async function registerRepositorySnapshotBuild(request, env, channel) {
  if (!await snapshotBuilderIdentity(request, env)) return json({ error: "protected snapshot builder identity required" }, 401);
  let body;
  try { body = await readBoundedJson(request, MAX_REGISTRATION_BYTES); }
  catch (error) { return json({ error: String(error.message || error) }, error.status || 400); }
  let target;
  try { target = repositoryTarget(body.suite || "focal", body.architecture || "amd64"); }
  catch (error) { return json({ error: String(error.message || error) }, error.status || 400); }
  if (!validSnapshotId(body.id, channel, target.suite, target.architecture)) return json({ error: "snapshot build ID does not match its target and channel" }, 400);
  let key;
  try { key = snapshotBuildKey(channel, body.id); }
  catch (error) { return json({ error: String(error.message || error) }, error.status || 400); }
  if (!Array.isArray(body.release_ids) || body.release_ids.length === 0 || body.release_ids.length > 32 ||
      new Set(body.release_ids).size !== body.release_ids.length) return json({ error: "snapshot build must name unique release ids" }, 400);
  let files;
  try { files = canonicalSnapshotBuildFiles(body.files, target.suite, target.architecture); }
  catch (error) { return json({ error: String(error.message || error) }, error.status || 400); }
  const ineligibility = await snapshotEligibilityError(env, channel, body.release_ids, Date.now(), target.suite, target.architecture);
  if (ineligibility) return json({ error: ineligibility }, 409);
  const record = { id: body.id, channel, suite: target.suite, architecture: target.architecture,
    release_ids: [...body.release_ids].sort(), files, created_at: new Date().toISOString() };
  const prior = await readRecord(env.RELEASES, key);
  if (prior && JSON.stringify({ ...prior.record, created_at: undefined }) === JSON.stringify({ ...record, created_at: undefined })) return json({ id: body.id, channel, replay: true }, 200);
  if (prior) return json({ error: "snapshot build id is immutable and already registered" }, 409);
  const saved = await writeRecord(env.RELEASES, key, record, null);
  return saved ? json({ id: body.id, channel, files: files.length }, 201) : json({ error: "snapshot build id already exists" }, 409);
}

async function uploadRepositorySnapshotBuildFile(request, env, channel, id, encodedPath) {
  if (!await snapshotBuilderIdentity(request, env)) return json({ error: "protected snapshot builder identity required" }, 401);
  let path;
  try { path = decodeURIComponent(encodedPath); }
  catch { return json({ error: "invalid snapshot build path encoding" }, 400); }
  let key;
  try { key = snapshotBuildKey(channel, id); }
  catch (error) { return json({ error: String(error.message || error) }, error.status || 400); }
  const build = (await readRecord(env.RELEASES, key))?.record;
  if (!build) return json({ error: "snapshot build is not registered" }, 404);
  const suite = build.suite || "focal";
  const architecture = build.architecture || "amd64";
  if (!snapshotBuildFilePath(path, suite)) return json({ error: "invalid snapshot build file path" }, 400);
  const ineligibility = await snapshotEligibilityError(env, channel, build.release_ids, Date.now(), suite, architecture);
  if (ineligibility) return json({ error: ineligibility }, 409);
  const file = build.files.find((candidate) => candidate.path === path);
  if (!file) return json({ error: "file is not in the immutable snapshot build manifest" }, 404);
  const length = Number(request.headers.get("content-length"));
  if (!Number.isSafeInteger(length) || length !== file.size || !request.body) return json({ error: "file content length must match the snapshot build manifest" }, 400);
  const objectKey = `repository-snapshot-builds/${channel}/${id}/${path}`;
  const stored = await env.RELEASES.put(objectKey, request.body, {
    onlyIf: { etagDoesNotMatch: "*" }, sha256: checksumBuffer(file.sha256),
    httpMetadata: { contentType: file.content_type },
    customMetadata: { snapshotBuildId: id, channel, path, sha256: file.sha256 },
  });
  if (stored && stored.size === file.size && checksumHex(stored.checksums?.sha256) === file.sha256) return json({ path, sha256: file.sha256, stored: true }, 201);
  const existing = await env.RELEASES.head(objectKey);
  if (existing?.size === file.size && checksumHex(existing.checksums?.sha256) === file.sha256 &&
      existing.customMetadata?.snapshotBuildId === id && existing.customMetadata?.channel === channel && existing.customMetadata?.path === path) {
    return json({ path, sha256: file.sha256, stored: true, replay: true }, 200);
  }
  return json({ error: "snapshot build object already exists with different content or failed checksum validation" }, 409);
}

async function readRepositorySnapshotBuild(request, env, channel, id, encodedPath) {
  if (!await snapshotPublisherIdentity(request, env)) return json({ error: "protected snapshot signer identity required" }, 401);
  let path;
  try { path = decodeURIComponent(encodedPath); }
  catch { return json({ error: "invalid snapshot build path encoding" }, 400); }
  let key;
  try { key = snapshotBuildKey(channel, id); }
  catch (error) { return json({ error: String(error.message || error) }, error.status || 400); }
  const build = (await readRecord(env.RELEASES, key))?.record;
  if (!build) return json({ error: "snapshot build is not available" }, 404);
  const suite = build.suite || "focal";
  const architecture = build.architecture || "amd64";
  const ineligibility = await snapshotEligibilityError(env, channel, build.release_ids, Date.now(), suite, architecture);
  if (ineligibility) return json({ error: "snapshot build release set is no longer eligible" }, 409);
  if (path === "manifest.json") return json(build);
  if (!snapshotBuildFilePath(path, suite)) return json({ error: "invalid snapshot build file path" }, 400);
  const file = build.files.find((candidate) => candidate.path === path);
  if (!file) return json({ error: "file is not in the snapshot build manifest" }, 404);
  const objectKey = `repository-snapshot-builds/${channel}/${id}/${path}`;
  const metadata = await env.RELEASES.head(objectKey);
  if (!metadata || metadata.size !== file.size || checksumHex(metadata.checksums?.sha256) !== file.sha256 ||
      metadata.customMetadata?.snapshotBuildId !== id || metadata.customMetadata?.channel !== channel || metadata.customMetadata?.path !== path) {
    return json({ error: "snapshot build file failed R2 readback verification" }, 502);
  }
  const object = request.method === "HEAD" ? metadata : await env.RELEASES.get(objectKey);
  if (!object || object.size !== file.size || checksumHex(object.checksums?.sha256) !== file.sha256) return json({ error: "snapshot build file failed R2 integrity verification" }, 502);
  return new Response(request.method === "HEAD" ? null : object.body, { headers: {
    "content-type": file.content_type, "content-length": String(file.size), "cache-control": "private, no-store",
    "x-content-type-options": "nosniff",
  } });
}

async function discardRepositorySnapshotBuild(env, channel, id) {
  const key = snapshotBuildKey(channel, id);
  const build = (await readRecord(env.RELEASES, key))?.record;
  if (!build) return true;
  try {
    await Promise.all(build.files.map((file) => env.RELEASES.delete(`repository-snapshot-builds/${channel}/${id}/${file.path}`)));
    await env.RELEASES.delete(key);
    return true;
  } catch { return false; }
}

function snapshotHistoryKey(channel, suite = "focal", architecture = "amd64") {
  if (!["public", "early"].includes(channel)) throw new Error("invalid repository snapshot channel");
  const target = repositoryTarget(suite, architecture);
  return target.suite === "focal" && target.architecture === "amd64"
    ? `repository-history/${channel}.json`
    : `repository-history/${channel}/${suite}/${architecture}.json`;
}

async function recordSnapshotActivation(env, channel, id, previousId = null, suite = "focal", architecture = "amd64") {
  const key = snapshotHistoryKey(channel, suite, architecture);
  for (let attempt = 0; attempt < MAX_RETRIES; attempt += 1) {
    const loaded = await readRecord(env.RELEASES, key);
    const previous = loaded?.record;
    if (previous && (previous.channel !== channel || (previous.suite || "focal") !== suite || (previous.architecture || "amd64") !== architecture ||
        !Array.isArray(previous.snapshot_ids) || previous.snapshot_ids.length > SNAPSHOT_ROLLBACK_RETENTION + 1 ||
        new Set(previous.snapshot_ids).size !== previous.snapshot_ids.length || previous.snapshot_ids.some((value) =>
          !validSnapshotId(value, channel, suite, architecture)))) {
      throw new Error("repository snapshot activation history is invalid");
    }
    const ordered = [id, previousId, ...(previous?.snapshot_ids || [])]
      .filter(Boolean).filter((value, index, values) => values.indexOf(value) === index)
      .slice(0, SNAPSHOT_ROLLBACK_RETENTION + 1);
    const next = { channel, suite, architecture, snapshot_ids: ordered, updated_at: new Date().toISOString() };
    const saved = await writeRecord(env.RELEASES, key, next, loaded?.etag || null);
    if (saved) return next;
  }
  throw new Error("repository snapshot activation history changed concurrently; retry activation");
}

async function registerRepositorySnapshot(request, env, channel) {
  if (!await snapshotPublisherIdentity(request, env)) return json({ error: "protected snapshot workflow identity required" }, 401);
  let body;
  try { body = await readBoundedJson(request, MAX_REGISTRATION_BYTES); }
  catch (error) { return json({ error: String(error.message || error) }, error.status || 400); }
  let target;
  try { target = repositoryTarget(body.suite || "focal", body.architecture || "amd64"); }
  catch (error) { return json({ error: String(error.message || error) }, error.status || 400); }
  if (!validSnapshotId(body.id, channel, target.suite, target.architecture)) return json({ error: "snapshot ID does not match its target and channel" }, 400);
  let key;
  try { key = snapshotKey(channel, body.id); }
  catch (error) { return json({ error: String(error.message || error) }, error.status || 400); }
  if (!Array.isArray(body.release_ids) || body.release_ids.length === 0 || body.release_ids.length > 32 ||
      new Set(body.release_ids).size !== body.release_ids.length) return json({ error: "snapshot must name unique verified release ids" }, 400);
  let files;
  try { files = canonicalSnapshotFiles(body.files, target.suite, target.architecture); }
  catch (error) { return json({ error: String(error.message || error) }, error.status || 400); }
  const ineligibility = await snapshotEligibilityError(env, channel, body.release_ids, Date.now(), target.suite, target.architecture);
  if (ineligibility) return json({ error: ineligibility }, 409);
  const snapshot = { id: body.id, channel, suite: target.suite, architecture: target.architecture,
    release_ids: [...body.release_ids].sort(), files, created_at: new Date().toISOString() };
  const prior = await readRecord(env.RELEASES, key);
  if (prior && JSON.stringify({ ...prior.record, created_at: undefined }) === JSON.stringify({ ...snapshot, created_at: undefined })) return json({ id: body.id, channel, replay: true }, 200);
  if (prior) return json({ error: "snapshot id is immutable and already registered" }, 409);
  const saved = await writeRecord(env.RELEASES, key, snapshot, null);
  return saved ? json({ id: body.id, channel, files: files.length }, 201) : json({ error: "snapshot id already exists" }, 409);
}

async function uploadRepositorySnapshotFile(request, env, channel, id, encodedPath) {
  if (!await snapshotPublisherIdentity(request, env)) return json({ error: "protected snapshot workflow identity required" }, 401);
  let path;
  try { path = decodeURIComponent(encodedPath); }
  catch { return json({ error: "invalid snapshot file path encoding" }, 400); }
  let key;
  try { key = snapshotKey(channel, id); }
  catch (error) { return json({ error: String(error.message || error) }, error.status || 400); }
  const snapshot = (await readRecord(env.RELEASES, key))?.record;
  if (!snapshot) return json({ error: "repository snapshot is not registered" }, 404);
  const suite = snapshot.suite || "focal";
  const architecture = snapshot.architecture || "amd64";
  if (!snapshotFilePath(path, suite)) return json({ error: "invalid snapshot file path" }, 400);
  const ineligibility = await snapshotEligibilityError(env, channel, snapshot.release_ids, Date.now(), suite, architecture);
  if (ineligibility) return json({ error: ineligibility }, 409);
  const file = snapshot.files.find((candidate) => candidate.path === path);
  if (!file) return json({ error: "file is not in the immutable snapshot manifest" }, 404);
  const length = Number(request.headers.get("content-length"));
  if (!Number.isSafeInteger(length) || length !== file.size || !request.body) return json({ error: "file content length must match the verified snapshot manifest" }, 400);
  const objectKey = `repository-snapshots/${channel}/${id}/${path}`;
  let stored;
  try {
    stored = await env.RELEASES.put(objectKey, request.body, {
      onlyIf: { etagDoesNotMatch: "*" }, sha256: checksumBuffer(file.sha256),
      httpMetadata: { contentType: file.content_type },
      customMetadata: { snapshotId: id, channel, path, sha256: file.sha256 },
    });
  } catch {
    return json({ error: "R2 rejected the snapshot object checksum or upload" }, 422);
  }
  if (stored && stored.size === file.size && checksumHex(stored.checksums?.sha256) === file.sha256) return json({ path, sha256: file.sha256, stored: true }, 201);
  const existing = await env.RELEASES.head(objectKey);
  if (existing?.size === file.size && checksumHex(existing.checksums?.sha256) === file.sha256 &&
      existing.customMetadata?.snapshotId === id && existing.customMetadata?.channel === channel && existing.customMetadata?.path === path) {
    return json({ path, sha256: file.sha256, stored: true, replay: true }, 200);
  }
  return json({ error: "snapshot object already exists with different content or failed R2 checksum validation" }, 409);
}

async function activateRepositorySnapshot(request, env, channel, id) {
  if (!await snapshotPublisherIdentity(request, env)) return json({ error: "protected snapshot workflow identity required" }, 401);
  let key;
  try { key = snapshotKey(channel, id); }
  catch (error) { return json({ error: String(error.message || error) }, error.status || 400); }
  const snapshot = (await readRecord(env.RELEASES, key))?.record;
  if (!snapshot) return json({ error: "repository snapshot is not registered" }, 404);
  const suite = snapshot.suite || "focal";
  const architecture = snapshot.architecture || "amd64";
  if (!validSnapshotId(id, channel, suite, architecture)) return json({ error: "snapshot ID does not match its repository target and channel" }, 400);
  let normalizedFiles;
  try { normalizedFiles = canonicalSnapshotFiles(snapshot.files, suite, architecture); }
  catch (error) { return json({ error: String(error.message || error) }, error.status || 400); }
  const ineligibility = await snapshotEligibilityError(env, channel, snapshot.release_ids, Date.now(), suite, architecture);
  if (ineligibility) return json({ error: ineligibility }, 409);
  for (const file of normalizedFiles) {
    const objectKey = `repository-snapshots/${channel}/${id}/${file.path}`;
    const object = await env.RELEASES.head(objectKey);
    if (!object || object.size !== file.size || checksumHex(object.checksums?.sha256) !== file.sha256 ||
        object.customMetadata?.snapshotId !== id || object.customMetadata?.channel !== channel || object.customMetadata?.path !== file.path) {
      return json({ error: `snapshot upload is incomplete or failed readback: ${file.path}` }, 409);
    }
  }
  const target = repositoryTarget(suite, architecture);
  const currentKey = repositoryCurrentKey(channel, target);
  const active = await readRecord(env.RELEASES, currentKey);
  if (active?.record.id === id) {
    try { await recordSnapshotActivation(env, channel, id, null, suite, architecture); }
    catch (error) { return json({ error: String(error.message || error) }, 503); }
    const cleanupPending = !await discardRepositorySnapshotBuild(env, channel, id);
    return json({ id, channel, active: true, replay: true, cleanup_pending: cleanupPending }, 200);
  }
  const next = { id, channel, activated_at: new Date().toISOString() };
  const saved = await writeRecord(env.RELEASES, currentKey, next, active?.etag || null);
  if (!saved) return json({ error: "repository pointer changed concurrently; retry activation" }, 409);
  try { await recordSnapshotActivation(env, channel, id, active?.record.id || null, suite, architecture); }
  catch (error) { return json({ error: String(error.message || error), active: true, history_update_pending: true }, 503); }
  const cleanupPending = !await discardRepositorySnapshotBuild(env, channel, id);
  return json({ id, channel, active: true, cleanup_pending: cleanupPending }, 201);
}

async function serveRepositoryFile(request, env, channel, path) {
  const requestedSuite = path.startsWith("dists/") ? path.split("/", 3)[1] : "focal";
  let target;
  try {
    // This APT path currently contains suite but not architecture. amd64 is
    // the only published architecture for these suite-specific streams.
    target = repositoryTarget(requestedSuite || "focal", "amd64");
  } catch { return json({ error: "invalid repository metadata path" }, 400); }
  if (!snapshotFilePath(path, target.suite)) return json({ error: "invalid repository metadata path" }, 400);
  const keyring = path === "getpatched-archive-keyring.gpg";
  if (channel === "early" && !keyring && !await deviceTokenUser(request, env)) return new Response("sponsor authentication required", {
    status: 401,
    headers: { "www-authenticate": 'Basic realm="getpatched.dev early repository"', "cache-control": "private, no-store", vary: "Authorization" },
  });
  const selectedChannel = keyring ? "public" : channel;
  const selectedTarget = repositoryTarget(target.suite, target.architecture);
  const active = (await readRecord(env.RELEASES, repositoryCurrentKey(selectedChannel, selectedTarget)))?.record;
  if (!active) return json({ error: "repository snapshot is not available" }, 503);
  const snapshot = (await readRecord(env.RELEASES, snapshotKey(selectedChannel, active.id)))?.record;
  if (!snapshot || (snapshot.suite || "focal") !== target.suite || (snapshot.architecture || "amd64") !== target.architecture) return json({ error: "repository snapshot is not available" }, 503);
  const ineligibility = await snapshotEligibilityError(env, selectedChannel, snapshot.release_ids, Date.now(), target.suite, target.architecture);
  if (ineligibility) return json({ error: "repository snapshot is unavailable pending release promotion" }, 503);
  let sourceSnapshot = snapshot;
  let file = snapshot.files.find((candidate) => candidate.path === path);
  if (!file && path.includes("/by-hash/SHA256/")) {
    const hash = path.slice(path.lastIndexOf("/") + 1);
    const hashPattern = /^[a-f0-9]{64}$/;
    if (!hashPattern.test(hash)) return json({ error: "invalid repository metadata path" }, 400);
    let cursor;
    let found = false;
    do {
      const pages = await env.RELEASES.list({ prefix: `repository-snapshots/${selectedChannel}/`, cursor, limit: 1000 });
      for (const item of pages.objects) {
        const prefix = `repository-snapshots/${selectedChannel}/`;
        if (!item.key.startsWith(prefix) || !item.key.endsWith(".json")) continue;
        const id = item.key.slice(prefix.length, -5);
        if (id === active.id || !/^[A-Za-z0-9][A-Za-z0-9-]{2,79}$/.test(id)) continue;
        const candidate = (await readRecord(env.RELEASES, snapshotKey(selectedChannel, id)))?.record;
        if (!candidate || (candidate.suite || "focal") !== target.suite || (candidate.architecture || "amd64") !== target.architecture ||
            await snapshotEligibilityError(env, selectedChannel, candidate.release_ids, Date.now(), target.suite, target.architecture)) continue;
        const oldFile = candidate.files?.find((entry) => entry.path === path);
        if (oldFile && oldFile.sha256 === hash) { sourceSnapshot = candidate; file = oldFile; found = true; break; }
      }
      cursor = found || !pages.truncated ? undefined : pages.cursor;
    } while (cursor);
  }
  if (!file) return json({ error: "repository file not found" }, 404);
  const objectKey = `repository-snapshots/${selectedChannel}/${sourceSnapshot.id}/${path}`;
  const metadata = await env.RELEASES.head(objectKey);
  if (!metadata || metadata.size !== file.size || checksumHex(metadata.checksums?.sha256) !== file.sha256) return json({ error: "repository file failed integrity verification" }, 502);
  const object = request.method === "HEAD" ? metadata : await env.RELEASES.get(objectKey);
  if (!object || object.size !== file.size || checksumHex(object.checksums?.sha256) !== file.sha256) return json({ error: "repository file failed integrity verification" }, 502);
  const headers = new Headers({
    "content-type": file.content_type,
    "content-length": String(file.size),
    "cache-control": channel === "early" ? "private, no-store" : (path.includes("/by-hash/") ? "public, max-age=31536000, immutable" : "public, max-age=300"),
    "x-content-type-options": "nosniff",
  });
  if (channel === "early") headers.set("vary", "Authorization");
  return new Response(request.method === "HEAD" ? null : object.body, { headers });
}

async function readRecord(bucket, key) {
  const object = await bucket.get(key);
  if (!object) return null;
  return { record: await object.json(), etag: object.etag };
}

async function readBoundedJson(request, maxBytes) {
  const declaredHeader = request.headers.get("content-length");
  if (declaredHeader !== null) {
    const declared = Number(declaredHeader);
    if (!Number.isSafeInteger(declared) || declared < 0) throw requestError("invalid content-length", 400);
    if (declared > maxBytes) throw requestError("request body exceeds the allowed size", 413);
  }
  if (!request.body) throw requestError("JSON request body is required", 400);
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw requestError("request body exceeds the allowed size", 413);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try { return JSON.parse(new TextDecoder().decode(bytes)); }
  catch { throw requestError("request body must be valid JSON", 400); }
}

function constantTimeEqual(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}

async function verifyGithubSignature(secret, rawBody, signature) {
  if (typeof secret !== "string" || !secret || typeof signature !== "string" || !/^sha256=[a-f0-9]{64}$/.test(signature)) return false;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, rawBody));
  const expected = `sha256=${[...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
  return constantTimeEqual(expected, signature);
}

async function acceptSponsorWebhook(request, env, context) {
  if (!env.SPONSOR_WEBHOOK_SECRET) return json({ error: "sponsor webhook is not configured" }, 503);
  if (request.headers.get("x-github-event") !== "sponsorship") return json({ error: "unsupported webhook event" }, 400);
  const delivery = request.headers.get("x-github-delivery");
  if (!delivery || !/^[0-9a-f-]{16,80}$/i.test(delivery)) return json({ error: "invalid delivery id" }, 400);
  let bytes;
  try {
    const declaredHeader = request.headers.get("content-length");
    if (declaredHeader !== null && (!Number.isSafeInteger(Number(declaredHeader)) || Number(declaredHeader) < 0 || Number(declaredHeader) > MAX_SPONSOR_WEBHOOK_BYTES)) {
      throw requestError("invalid or oversized webhook content-length", Number(declaredHeader) > MAX_SPONSOR_WEBHOOK_BYTES ? 413 : 400);
    }
    if (!request.body) throw requestError("webhook body is required", 400);
    const reader = request.body.getReader();
    const chunks = [];
    let total = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > MAX_SPONSOR_WEBHOOK_BYTES) {
          await reader.cancel();
          throw requestError("webhook body exceeds the allowed size", 413);
        }
        chunks.push(value);
      }
    } finally { reader.releaseLock(); }
    bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    if (!await verifyGithubSignature(env.SPONSOR_WEBHOOK_SECRET, bytes, request.headers.get("x-hub-signature-256"))) {
      return json({ error: "invalid webhook signature" }, 401);
    }
    let payload;
    try { payload = JSON.parse(new TextDecoder().decode(bytes)); }
    catch { throw requestError("webhook body must be valid JSON", 400); }
    const supportedActions = new Set(["created", "cancelled", "pending_cancellation", "tier_changed"]);
    if (!supportedActions.has(payload.action) || !Number.isSafeInteger(payload.sponsorship?.sponsor?.id)) {
      return json({ error: "unsupported or incomplete sponsorship event" }, 422);
    }
    const receivedAt = new Date().toISOString();
    // GitHub emits `cancelled` after a recurring sponsorship's final billing
    // cycle ends. Persist a deny marker before acknowledging the event so a
    // cached sponsor snapshot cannot keep early binary access alive if the
    // follow-up GraphQL reconciliation fails.
    if (payload.action === "cancelled") {
      try {
        await recordSponsorRevocation(env.RELEASES, payload.sponsorship.sponsor.id, delivery, receivedAt);
      } catch {
        return json({ error: "sponsor access revocation could not be persisted; retry delivery" }, 503);
      }
    }
    const key = `sponsor-deliveries/${delivery}.json`;
    const result = await env.RELEASES.put(key, JSON.stringify({
      delivery_id: delivery,
      action: payload.action,
      sponsor_id: payload.sponsorship.sponsor.id,
      received_at: receivedAt,
      effect: payload.action === "cancelled" ? "early-access-revoked" : "reconciliation-required",
    }), { onlyIf: { etagDoesNotMatch: "*" }, httpMetadata: { contentType: "application/json" } });
    if (!result) return json({ accepted: true, duplicate: true, reconciliation_required: true, access_revoked: payload.action === "cancelled" }, 200);
    if (context?.waitUntil) {
      context.waitUntil(reconcileSponsors(env).catch((error) => {
        console.error("immediate sponsor reconciliation failed", String(error?.message || error));
      }));
    }
    return json({ accepted: true, reconciliation_required: true, access_revoked: payload.action === "cancelled" }, 202);
  } catch (error) {
    return json({ error: String(error.message || error) }, error.status || 400);
  }
}

async function recordSponsorRevocation(bucket, githubUserId, deliveryId, revokedAt) {
  const key = `sponsor-revocations/${githubUserId}.json`;
  for (let attempt = 0; attempt < MAX_RETRIES; attempt += 1) {
    const previous = await bucket.get(key);
    if (previous) {
      const current = await previous.json();
      if (current.delivery_id === deliveryId || Date.parse(current.revoked_at) >= Date.parse(revokedAt)) return current;
    }
    const record = {
      github_user_id: githubUserId,
      delivery_id: deliveryId,
      revoked_at: revokedAt,
      reason: "github-sponsorship-cancelled",
    };
    const options = {
      onlyIf: previous ? { etagMatches: previous.etag } : { etagDoesNotMatch: "*" },
      httpMetadata: { contentType: "application/json", cacheControl: "no-store" },
    };
    const saved = await bucket.put(key, JSON.stringify(record), options);
    if (saved) return record;
  }
  throw new Error("sponsor access revocation changed concurrently; retry webhook delivery");
}

async function hasActiveSponsorship(bucket, snapshot, githubUserId) {
  if (!snapshot || !snapshot.sponsors.some((sponsor) => sponsor.github_user_id === githubUserId)) return false;
  const revocation = await readRecord(bucket, `sponsor-revocations/${githubUserId}.json`);
  if (!revocation) return true;
  const snapshotAt = Date.parse(snapshot.reconciled_at);
  const revokedAt = Date.parse(revocation.record.revoked_at);
  // Fail closed on malformed markers. A later authoritative active-only
  // snapshot may re-enable a sponsor who starts a new sponsorship.
  return Number.isFinite(snapshotAt) && Number.isFinite(revokedAt) && snapshotAt > revokedAt;
}

async function fetchSponsorSnapshot(env, now) {
  if (!env.SPONSOR_GRAPHQL_TOKEN) throw new Error("GitHub Sponsors reconciliation token is not configured");
  let after = null;
  const sponsors = new Map();
  let pages = 0;
  do {
    if (++pages > 100) throw new Error("GitHub Sponsors pagination limit exceeded");
    const response = await fetch("https://api.github.com/graphql", {
      method: "POST",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${env.SPONSOR_GRAPHQL_TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        query: `query GetPatchedSponsorReconciliation($after: String) {
          organization(login: "getpatched") {
            login
            hasSponsorsListing
            sponsorshipsAsMaintainer(activeOnly: true, includePrivate: true, first: 100, after: $after) {
              nodes {
                isActive
                isOneTimePayment
                sponsorEntity {
                  __typename
                  ... on User { databaseId login }
                  ... on Organization { databaseId login }
                }
              }
              pageInfo { hasNextPage endCursor }
            }
          }
        }`,
        variables: { after },
      }),
    });
    if (!response.ok) throw new Error(`GitHub Sponsors GraphQL returned ${response.status}`);
    const result = await response.json();
    if (result.errors?.length) throw new Error("GitHub Sponsors GraphQL query failed");
    const organization = result.data?.organization;
    if (organization?.login?.toLowerCase() !== "getpatched" || organization.hasSponsorsListing !== true) {
      throw new Error("getpatched GitHub Sponsors listing is unavailable");
    }
    const connection = organization.sponsorshipsAsMaintainer;
    if (!connection || !Array.isArray(connection.nodes) || !connection.pageInfo) throw new Error("GitHub Sponsors response is incomplete");
    for (const sponsorship of connection.nodes) {
      const sponsor = sponsorship?.sponsorEntity;
      // Organization sponsors do not grant access to every member. Device entitlements
      // are mapped only to the individual user's immutable GitHub database ID.
      if (sponsorship.isActive === true && sponsor?.__typename === "User" && Number.isSafeInteger(sponsor.databaseId)) {
        const current = sponsors.get(sponsor.databaseId);
        sponsors.set(sponsor.databaseId, {
          github_user_id: sponsor.databaseId,
          github_login: sponsor.login,
          has_one_time_sponsorship: current?.has_one_time_sponsorship === true || sponsorship.isOneTimePayment === true,
        });
      }
    }
    after = connection.pageInfo.hasNextPage ? connection.pageInfo.endCursor : null;
    if (connection.pageInfo.hasNextPage && (typeof after !== "string" || !after)) throw new Error("GitHub Sponsors pagination cursor is missing");
  } while (after);
  return {
    organization: "getpatched",
    sponsors: [...sponsors.values()].sort((a, b) => a.github_user_id - b.github_user_id),
    reconciled_at: now.toISOString(),
    valid_until: new Date(now.getTime() + SPONSOR_SNAPSHOT_MAX_AGE_MS).toISOString(),
    authority: "github-sponsors-graphql-active-only",
    tier_policy: "any-active-individual-github-sponsorship-tier",
  };
}

async function saveSponsorSnapshot(bucket, snapshot) {
  const key = SPONSOR_ENTITLEMENTS_KEY;
  for (let attempt = 0; attempt < MAX_RETRIES; attempt += 1) {
    const previous = await bucket.get(key);
    if (previous) {
      const current = await previous.json();
      if (Date.parse(current.reconciled_at) >= Date.parse(snapshot.reconciled_at)) return current;
    }
    const options = {
      onlyIf: previous ? { etagMatches: previous.etag } : { etagDoesNotMatch: "*" },
      httpMetadata: { contentType: "application/json", cacheControl: "no-store" },
    };
    const saved = await bucket.put(key, JSON.stringify(snapshot), options);
    if (saved) return snapshot;
  }
  throw new Error("sponsor snapshot changed concurrently; retry reconciliation");
}

async function markSponsorEventsReconciled(bucket, snapshot) {
  let cursor;
  const failures = [];
  const active = new Set(snapshot.sponsors.map((sponsor) => sponsor.github_user_id));
  do {
    const page = await bucket.list({ prefix: "sponsor-deliveries/", cursor, limit: 1000 });
    for (const item of page.objects) {
      try {
        const loaded = await readRecord(bucket, item.key);
        if (!loaded || loaded.record.reconciled_at) continue;
        const updated = {
          ...loaded.record,
          reconciled_at: snapshot.reconciled_at,
          sponsor_active: active.has(loaded.record.sponsor_id),
          entitlement_source: "authoritative-snapshot",
        };
        const saved = await bucket.put(item.key, JSON.stringify(updated), {
          onlyIf: { etagMatches: loaded.etag },
          httpMetadata: { contentType: "application/json" },
        });
        if (!saved) failures.push(item.key);
      } catch { failures.push(item.key); }
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  return failures;
}

async function reconcileSponsors(env, now = new Date()) {
  const snapshot = await fetchSponsorSnapshot(env, now);
  const saved = await saveSponsorSnapshot(env.RELEASES, snapshot);
  const eventFailures = await markSponsorEventsReconciled(env.RELEASES, saved);
  if (eventFailures.length) throw new Error(`sponsor snapshot saved but ${eventFailures.length} webhook events still need reconciliation`);
  return saved;
}

async function readFreshSponsorSnapshot(bucket, now = new Date()) {
  const loaded = await readRecord(bucket, SPONSOR_ENTITLEMENTS_KEY);
  if (!loaded) return null;
  const snapshot = loaded.record;
  if (snapshot.organization !== "getpatched" || snapshot.authority !== "github-sponsors-graphql-active-only" ||
      !Number.isFinite(Date.parse(snapshot.valid_until)) || now.getTime() >= Date.parse(snapshot.valid_until)) return null;
  return snapshot;
}

function randomToken(bytes = 32) {
  const value = crypto.getRandomValues(new Uint8Array(bytes));
  return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function cookieValue(request, name) {
  const cookies = request.headers.get("cookie") || "";
  for (const part of cookies.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === name) {
      try { return decodeURIComponent(part.slice(separator + 1).trim()); } catch { return null; }
    }
  }
  return null;
}

function setCookie(name, value, path, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Path=${path}; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Lax`;
}

function clearCookie(name, path) {
  return `${name}=; Path=${path}; Max-Age=0; Secure; HttpOnly; SameSite=Lax`;
}

function assertSameOrigin(request, env) {
  const expected = env.PUBLIC_ORIGIN || new URL(request.url).origin;
  if (request.headers.get("origin") !== expected) throw requestError("request origin is not allowed", 403);
}

async function beginGithubLogin(request, env) {
  if (!env.GITHUB_OAUTH_CLIENT_ID || !env.PUBLIC_ORIGIN) return json({ error: "GitHub sign-in is not configured" }, 503);
  const state = randomToken();
  const codeVerifier = randomToken(48);
  const challengeDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier)));
  const codeChallenge = btoa(String.fromCharCode(...challengeDigest)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  const stateHash = await sha256Hex(new TextEncoder().encode(state));
  await env.RELEASES.put(`oauth-states/${stateHash}.json`, JSON.stringify({
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
    code_verifier: codeVerifier,
  }), { onlyIf: { etagDoesNotMatch: "*" }, httpMetadata: { contentType: "application/json" } });
  const redirect = new URL("https://github.com/login/oauth/authorize");
  redirect.searchParams.set("client_id", env.GITHUB_OAUTH_CLIENT_ID);
  redirect.searchParams.set("redirect_uri", `${env.PUBLIC_ORIGIN}/auth/github/callback`);
  redirect.searchParams.set("scope", "read:user");
  redirect.searchParams.set("state", state);
  redirect.searchParams.set("code_challenge", codeChallenge);
  redirect.searchParams.set("code_challenge_method", "S256");
  return new Response(null, {
    status: 302,
    headers: { location: redirect.toString(), "cache-control": "no-store", "set-cookie": setCookie("getpatched_oauth_state", state, "/auth/github/callback", 600) },
  });
}

async function consumeOauthState(request, env, returnedState) {
  const cookieState = cookieValue(request, "getpatched_oauth_state") || cookieValue(request, "aptto_oauth_state");
  if (!cookieState || !returnedState || !constantTimeEqual(cookieState, returnedState)) return false;
  const key = `oauth-states/${await sha256Hex(new TextEncoder().encode(returnedState))}.json`;
  const loaded = await readRecord(env.RELEASES, key);
  if (!loaded || loaded.record.consumed_at || Date.now() > Date.parse(loaded.record.expires_at)) return null;
  const saved = await env.RELEASES.put(key, JSON.stringify({ ...loaded.record, code_verifier: null, consumed_at: new Date().toISOString() }), {
    onlyIf: { etagMatches: loaded.etag }, httpMetadata: { contentType: "application/json" },
  });
  return saved ? loaded.record : null;
}

async function githubLoginCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const oauthState = code ? await consumeOauthState(request, env, state) : null;
  if (!oauthState?.code_verifier) return json({ error: "invalid or expired sign-in state" }, 400);
  if (!env.GITHUB_OAUTH_CLIENT_ID || !env.GITHUB_OAUTH_CLIENT_SECRET || !env.PUBLIC_ORIGIN) return json({ error: "GitHub sign-in is not configured" }, 503);
  const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({
      client_id: env.GITHUB_OAUTH_CLIENT_ID,
      client_secret: env.GITHUB_OAUTH_CLIENT_SECRET,
      code,
      redirect_uri: `${env.PUBLIC_ORIGIN}/auth/github/callback`,
      code_verifier: oauthState.code_verifier,
    }),
  });
  if (!tokenResponse.ok) return json({ error: "GitHub sign-in token exchange failed" }, 502);
  const tokenResult = await tokenResponse.json();
  const scopes = new Set(String(tokenResult.scope || "").split(/[ ,]+/).filter(Boolean));
  if (tokenResult.error || !tokenResult.access_token || !scopes.has("read:user")) return json({ error: "GitHub sign-in did not grant user identity permission" }, 403);
  const userResponse = await fetch("https://api.github.com/user", {
    headers: { accept: "application/vnd.github+json", authorization: `Bearer ${tokenResult.access_token}`, "x-github-api-version": "2022-11-28" },
  });
  if (!userResponse.ok) return json({ error: "GitHub identity lookup failed" }, 502);
  const user = await userResponse.json();
  if (!Number.isSafeInteger(user.id) || typeof user.login !== "string") return json({ error: "GitHub identity response is incomplete" }, 502);
  const session = randomToken();
  const sessionHash = await sha256Hex(new TextEncoder().encode(session));
  const now = new Date();
  await env.RELEASES.put(`apt-sessions/${sessionHash}.json`, JSON.stringify({
    github_user_id: user.id,
    github_login: user.login,
    created_at: now.toISOString(),
    expires_at: new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString(),
  }), { onlyIf: { etagDoesNotMatch: "*" }, httpMetadata: { contentType: "application/json" } });
  return new Response(null, {
    status: 302,
    headers: (() => {
      const headers = new Headers({ location: `${env.PUBLIC_ORIGIN}/account`, "cache-control": "no-store" });
      headers.append("set-cookie", clearCookie("getpatched_oauth_state", "/auth/github/callback"));
      headers.append("set-cookie", clearCookie("aptto_oauth_state", "/auth/github/callback"));
      headers.append("set-cookie", setCookie("getpatched_session", session, "/", 7 * 24 * 60 * 60));
      return headers;
    })(),
  });
}

async function sessionUser(request, env) {
  const session = cookieValue(request, "getpatched_session") || cookieValue(request, "aptto_session");
  if (!session) return null;
  const key = `apt-sessions/${await sha256Hex(new TextEncoder().encode(session))}.json`;
  const loaded = await readRecord(env.RELEASES, key);
  if (!loaded || loaded.record.revoked_at || Date.now() > Date.parse(loaded.record.expires_at)) return null;
  return loaded.record;
}

async function accountStatus(request, env) {
  if (!env.GITHUB_OAUTH_CLIENT_ID || !env.GITHUB_OAUTH_CLIENT_SECRET || !env.PUBLIC_ORIGIN) {
    return json({ error: "GitHub sign-in is not configured" }, 503);
  }
  const user = await sessionUser(request, env);
  if (!user) return json({ error: "sign-in required" }, 401);
  const snapshot = await readFreshSponsorSnapshot(env.RELEASES);
  const eligible = await hasActiveSponsorship(env.RELEASES, snapshot, user.github_user_id);
  return json({
    github_login: user.github_login,
    sponsorship: snapshot ? (eligible ? "eligible" : "not-eligible") : "unavailable",
    snapshot_valid_until: snapshot?.valid_until || null,
  });
}

async function logout(request, env) {
  assertSameOrigin(request, env);
  const session = cookieValue(request, "getpatched_session") || cookieValue(request, "aptto_session");
  if (session) {
    const key = `apt-sessions/${await sha256Hex(new TextEncoder().encode(session))}.json`;
    const loaded = await readRecord(env.RELEASES, key);
    if (loaded && !loaded.record.revoked_at) {
      const saved = await env.RELEASES.put(key, JSON.stringify({ ...loaded.record, revoked_at: new Date().toISOString() }), {
        onlyIf: { etagMatches: loaded.etag }, httpMetadata: { contentType: "application/json" },
      });
      if (!saved) return json({ error: "session changed concurrently; retry logout" }, 409);
    }
  }
  const headers = new Headers({ "cache-control": "no-store" });
  headers.append("set-cookie", clearCookie("getpatched_session", "/"));
  headers.append("set-cookie", clearCookie("aptto_session", "/"));
  return new Response(null, { status: 204, headers });
}

async function issueDeviceToken(request, env) {
  assertSameOrigin(request, env);
  const user = await sessionUser(request, env);
  if (!user) return json({ error: "sign-in required" }, 401);
  const snapshot = await readFreshSponsorSnapshot(env.RELEASES);
  if (!snapshot) return json({ error: "sponsor status is temporarily unavailable" }, 503);
  if (!await hasActiveSponsorship(env.RELEASES, snapshot, user.github_user_id)) return json({ error: "active GitHub sponsorship at any tier required" }, 403);
  let body;
  try { body = await readBoundedJson(request, 4096); }
  catch (error) { return json({ error: String(error.message || error) }, error.status || 400); }
  if (body.earlyBinaryLicenseId !== "LicenseRef-GetPatched-Early-Binary-1.2") {
    return json({ error: "accept the early-binary terms before creating a device credential" }, 400);
  }
  const label = typeof body.label === "string" ? body.label.trim() : "APT device";
  if (!label || label.length > 80) return json({ error: "device label must be 1 to 80 characters" }, 400);
  const token = `getpatched_${randomToken()}`;
  const tokenHash = await sha256Hex(new TextEncoder().encode(token));
  const now = new Date();
  const record = {
    github_user_id: user.github_user_id,
    created_at: now.toISOString(),
    expires_at: new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000).toISOString(),
    device_label: label,
    early_binary_license_id: body.earlyBinaryLicenseId,
    early_binary_terms_accepted_at: now.toISOString(),
  };
  const saved = await env.RELEASES.put(`apt-device-tokens/${tokenHash}.json`, JSON.stringify(record), {
    onlyIf: { etagDoesNotMatch: "*" }, httpMetadata: { contentType: "application/json" },
  });
  if (!saved) return json({ error: "could not issue a unique device token; retry" }, 503);
  return json({ token, label, expires_at: record.expires_at }, 201);
}

async function listDeviceTokens(request, env) {
  const user = await sessionUser(request, env);
  if (!user) return json({ error: "sign-in required" }, 401);
  const tokens = [];
  let cursor;
  do {
    const page = await env.RELEASES.list({ prefix: "apt-device-tokens/", cursor, limit: 1000 });
    for (const item of page.objects) {
      const loaded = await readRecord(env.RELEASES, item.key);
      if (loaded?.record.github_user_id === user.github_user_id) {
        tokens.push({
          id: item.key.slice("apt-device-tokens/".length, -5),
          label: loaded.record.device_label,
          created_at: loaded.record.created_at,
          expires_at: loaded.record.expires_at,
          revoked_at: loaded.record.revoked_at || null,
        });
      }
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  return json({ devices: tokens.sort((a, b) => a.created_at.localeCompare(b.created_at)) });
}

async function revokeDeviceToken(request, env, tokenId) {
  assertSameOrigin(request, env);
  const user = await sessionUser(request, env);
  if (!user) return json({ error: "sign-in required" }, 401);
  if (!/^[a-f0-9]{64}$/.test(tokenId)) return json({ error: "invalid device token id" }, 400);
  const key = `apt-device-tokens/${tokenId}.json`;
  const loaded = await readRecord(env.RELEASES, key);
  if (!loaded || loaded.record.github_user_id !== user.github_user_id) return json({ error: "device token not found" }, 404);
  if (loaded.record.revoked_at) return json({ revoked: true, already_revoked: true });
  const saved = await env.RELEASES.put(key, JSON.stringify({ ...loaded.record, revoked_at: new Date().toISOString() }), {
    onlyIf: { etagMatches: loaded.etag }, httpMetadata: { contentType: "application/json" },
  });
  if (!saved) return json({ error: "device token changed concurrently; retry" }, 409);
  return json({ revoked: true });
}

async function deviceTokenUser(request, env, now = new Date()) {
  const header = request.headers.get("authorization") || "";
  const match = header.match(/^Basic ([A-Za-z0-9+/]+=*)$/);
  if (!match) return null;
  let credentials;
  try { credentials = atob(match[1]); } catch { return null; }
  const separator = credentials.indexOf(":");
  if (separator < 0 || credentials.slice(0, separator) !== "apt") return null;
  const token = credentials.slice(separator + 1);
  if (!/^(?:getpatched|aptto)_[a-f0-9]{64}$/.test(token)) return null;
  const tokenHash = await sha256Hex(new TextEncoder().encode(token));
  const loaded = await readRecord(env.RELEASES, `apt-device-tokens/${tokenHash}.json`);
  if (!loaded || loaded.record.revoked_at || !Number.isSafeInteger(loaded.record.github_user_id) || now.getTime() > Date.parse(loaded.record.expires_at)) return null;
  const snapshot = await readFreshSponsorSnapshot(env.RELEASES, now);
  if (!await hasActiveSponsorship(env.RELEASES, snapshot, loaded.record.github_user_id)) return null;
  return loaded.record;
}

function parseByteRange(value, total) {
  if (typeof value !== "string" || !value.startsWith("bytes=") || value.includes(",")) return null;
  const match = value.slice(6).match(/^(\d*)-(\d*)$/);
  if (!match || (!match[1] && !match[2])) return null;
  const startText = match[1];
  const endText = match[2];
  if (!startText) {
    const suffix = Number(endText);
    if (!Number.isSafeInteger(suffix) || suffix <= 0) return null;
    if (total <= 0) return { unsatisfiable: true };
    const length = Math.min(suffix, total);
    return { offset: total - length, length, end: total - 1 };
  }
  const offset = Number(startText);
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= total) return { unsatisfiable: true };
  const requestedEnd = endText ? Number(endText) : total - 1;
  if (!Number.isSafeInteger(requestedEnd) || requestedEnd < offset) return { unsatisfiable: true };
  const end = Math.min(requestedEnd, total - 1);
  return { offset, length: end - offset + 1, end };
}

function ifRangeMatches(value, object, etag) {
  if (!value) return true;
  if (value.startsWith('"')) return value === etag;
  if (value.startsWith("W/")) return false;
  const requestedDate = Date.parse(value);
  const uploadedDate = object.uploaded instanceof Date ? object.uploaded.getTime() : NaN;
  return Number.isFinite(requestedDate) && Number.isFinite(uploadedDate) && uploadedDate <= requestedDate;
}

async function serveEarlyAsset(request, env, id, name, now = new Date(), channel = "early") {
  if (!/^[A-Za-z0-9][A-Za-z0-9._+~-]*$/.test(name)) return json({ error: "invalid asset name" }, 400);
  let key;
  try { key = stateKey(id); } catch { return json({ error: "invalid release id" }, 400); }
  const loaded = await readRecord(env.RELEASES, key);
  const release = loaded?.record;
  if (!release) {
    return json({ error: "sponsor release is unavailable" }, 404);
  }
  if (channel === "public" && release.state !== "public") {
    return json({ error: "package is not publicly available" }, 404);
  }
  const asset = canonicalAssets(release.required_assets).find((candidate) => candidate.name === name);
  if (!asset) return json({ error: "release asset not found" }, 404);
  if (release.state === "public") {
    if (!Number.isSafeInteger(release.public_release_id)) return json({ error: "public release mapping is missing" }, 502);
    const [owner, repository] = release.repository.split("/");
    const response = await githubRequest(env, `/repos/${owner}/${repository}/releases/${release.public_release_id}/assets`);
    const assets = await response.json();
    const published = assets.find((candidate) => candidate.name === asset.name);
    if (!published || typeof published.browser_download_url !== "string") return json({ error: "public release asset is missing" }, 502);
    let destination;
    try { destination = new URL(published.browser_download_url); } catch { return json({ error: "public release URL is invalid" }, 502); }
    if (destination.protocol !== "https:" || destination.hostname !== "github.com" ||
        !destination.pathname.startsWith(`/${owner}/${repository}/releases/download/`)) {
      return json({ error: "GitHub returned an unexpected public asset URL" }, 502);
    }
    return new Response(null, { status: 302, headers: {
      location: destination.toString(), "cache-control": "public, max-age=300", "referrer-policy": "no-referrer",
    } });
  }
  if (release.state !== "sponsor-period" || release.sponsor_delay_hours !== 168 || release.sponsor_publication_complete !== true ||
      !Number.isFinite(Date.parse(release.public_after)) || now.getTime() >= Date.parse(release.public_after)) {
    return json({ error: "sponsor release is unavailable" }, 404);
  }
  const user = await deviceTokenUser(request, env, now);
  if (!user) return new Response("sponsor authentication required", {
    status: 401,
    headers: { "www-authenticate": 'Basic realm="getpatched.dev early repository"', "cache-control": "private, no-store", vary: "Authorization" },
  });
  const metadata = await env.RELEASES.head(asset.r2_key);
  if (!metadata || !Number.isSafeInteger(metadata.size) || metadata.size <= 0 || checksumHex(metadata.checksums?.sha256) !== asset.sha256) {
    return json({ error: "release asset failed integrity verification" }, 502);
  }
  const etag = metadata.httpEtag || `"sha256-${asset.sha256}"`;
  const range = ifRangeMatches(request.headers.get("if-range"), metadata, etag)
    ? parseByteRange(request.headers.get("range"), metadata.size)
    : null;
  if (range?.unsatisfiable) {
    return new Response(null, { status: 416, headers: {
      "content-range": `bytes */${metadata.size}`, "cache-control": "private, no-store", vary: "Authorization",
    } });
  }
  const object = request.method === "HEAD"
    ? metadata
    : await env.RELEASES.get(asset.r2_key, range ? { range: { offset: range.offset, length: range.length } } : undefined);
  if (!object || !Number.isSafeInteger(object.size) || checksumHex(object.checksums?.sha256) !== asset.sha256) {
    return json({ error: "release asset failed integrity verification" }, 502);
  }
  const headers = new Headers({
    "content-type": object.httpMetadata?.contentType || "application/octet-stream",
    "content-length": String(range ? range.length : metadata.size),
    "content-disposition": `attachment; filename="${name}"`,
    "cache-control": "private, no-store",
    vary: "Authorization",
    "x-content-type-options": "nosniff",
    etag,
    "accept-ranges": "bytes",
  });
  if (range) headers.set("content-range", `bytes ${range.offset}-${range.end}/${metadata.size}`);
  return new Response(request.method === "HEAD" ? null : object.body, { status: range ? 206 : 200, headers });
}

async function servePublicSourceAsset(request, env, record, asset) {
  if (!Number.isSafeInteger(record.source_release_id)) return json({ error: "public source release is unavailable" }, 404);
  const response = await githubRequest(env, `/repos/${record.repository}/releases/${record.source_release_id}/assets`);
  if (!response.ok) return json({ error: "public source asset lookup failed" }, 502);
  const assets = await response.json();
  const published = assets.find((candidate) => candidate.name === asset.name);
  if (!published || typeof published.browser_download_url !== "string") return json({ error: "public source asset is missing" }, 404);
  let destination;
  try { destination = new URL(published.browser_download_url); } catch { return json({ error: "public source URL is invalid" }, 502); }
  const [owner, repository] = record.repository.split("/");
  if (destination.protocol !== "https:" || destination.hostname !== "github.com" ||
      !destination.pathname.startsWith(`/${owner}/${repository}/releases/download/`)) {
    return json({ error: "GitHub returned an unexpected public source URL" }, 502);
  }
  return new Response(null, { status: 302, headers: {
    location: destination.toString(), "cache-control": "public, max-age=300", "referrer-policy": "no-referrer",
  } });
}

async function servePoolAsset(request, env, path, channel) {
  const parts = path.split("/");
  if (parts.length !== 5 || parts[0] !== "pool" || parts[1] !== "main" ||
      parts.some((part) => !/^[A-Za-z0-9][A-Za-z0-9._+~-]*$/.test(part))) {
    return json({ error: "invalid repository pool path" }, 400);
  }
  const name = parts[4];
  let cursor;
  const matches = [];
  do {
    const page = await env.RELEASES.list({ prefix: STATE_PREFIX, cursor, limit: 1000 });
    for (const item of page.objects) {
      const loaded = await readRecord(env.RELEASES, item.key);
      const record = loaded?.record;
      if (!record) continue;
      assertRelease(record);
      const source = packageName(record.repository);
      if (path !== `pool/main/${source[0]}/${source}/${name}`) continue;
      const binary = canonicalAssets(record.required_assets).find((asset) => asset.name === name);
      const sourceAssets = record.source_assets?.length ? canonicalAssets(record.source_assets) : [];
      const sourceAsset = sourceAssets.find((asset) => asset.name === name);
      if (binary) matches.push({ record, id: record.id, asset: binary, name, kind: "binary" });
      if (sourceAsset) matches.push({ record, asset: sourceAsset, kind: "source" });
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  if (matches.length === 0) return json({ error: "repository asset not found" }, 404);
  const match = matches[0];
  if (matches.some((candidate) => candidate.kind !== match.kind || candidate.asset.sha256 !== match.asset.sha256)) {
    return json({ error: "repository asset mapping is ambiguous" }, 409);
  }
  if (match.kind === "source") return servePublicSourceAsset(request, env, match.record, match.asset);
  return serveEarlyAsset(request, env, match.id, match.name, new Date(), channel);
}

async function beginSponsorPublication(request, env, id, now = new Date()) {
  const identity = await githubActionsIdentity(request, env);
  if (!identity || (identity.type !== "admin" && identity.workflow !== "private-staging")) {
    return json({ error: "unauthorized" }, 401);
  }
  let key;
  try { key = stateKey(id); } catch { return json({ error: "invalid release id" }, 400); }
  const loaded = await readRecord(env.RELEASES, key);
  if (!loaded) return json({ error: "release not found" }, 404);
  const record = loaded.record;
  if (identity.type === "github-actions" && identity.run_id !== record.staging_run_id) return json({ error: "OIDC run identity does not match staged release" }, 403);
  if (record.sponsor_delay_hours !== 168 || record.release_checks_passed !== true) {
    return json({ error: "release is not eligible for sponsor publication" }, 409);
  }
  if (record.state === "sponsor-period" && record.sponsor_publication_complete === true) {
    return json({ id, state: record.state, sponsor_published_at: record.sponsor_published_at, public_after: record.public_after }, 200);
  }
  if (record.state !== "prepared") return json({ error: "release is not prepared" }, 409);
  const assets = canonicalAssets(record.required_assets);
  for (const asset of assets) {
    const stored = await env.RELEASES.head(asset.r2_key);
    if (!stored || !Number.isSafeInteger(stored.size) || stored.size <= 0 || checksumHex(stored.checksums?.sha256) !== asset.sha256 ||
        stored.customMetadata?.releaseId !== id || stored.customMetadata?.assetName !== asset.name) {
      return json({ error: `private sponsor publication is incomplete or failed integrity check: ${asset.name}` }, 409);
    }
  }
  const publishedAt = now;
  const publicAfter = new Date(publishedAt.getTime() + 168 * 60 * 60 * 1000);
  try {
    const next = await updateState(env.RELEASES, key, (current) => {
      if (current.state === "sponsor-period" && current.sponsor_publication_complete === true) return current;
      if (current.state !== "prepared" || current.sponsor_delay_hours !== 168 || current.release_checks_passed !== true) {
        throw requestError("release state changed before sponsor publication", 409);
      }
      return {
        ...current,
        state: "sponsor-period",
        sponsor_publication_complete: true,
        sponsor_published_at: publishedAt.toISOString(),
        public_after: publicAfter.toISOString(),
      };
    });
    return json({ id, state: next.state, sponsor_published_at: next.sponsor_published_at, public_after: next.public_after }, 201);
  } catch (error) {
    return json({ error: String(error.message || error) }, error.status || 409);
  }
}

async function publishImmediateRelease(request, env, id, now = new Date()) {
  const identity = await githubActionsIdentity(request, env);
  if (!identity || (identity.type !== "admin" && (identity.type !== "github-actions" || identity.workflow !== "private-staging"))) return json({ error: "private staging workflow identity required" }, 401);
  let key;
  try { key = stateKey(id); } catch { return json({ error: "invalid release id" }, 400); }
  const loaded = await readRecord(env.RELEASES, key);
  if (!loaded) return json({ error: "release not found" }, 404);
  const record = loaded.record;
  if (identity.run_id !== record.staging_run_id) return json({ error: "OIDC run identity does not match staged release" }, 403);
  if (record.sponsor_delay_hours !== 0 || record.release_checks_passed !== true) {
    return json({ error: "release is not eligible for immediate public publication" }, 409);
  }
  if (!["prepared", "public"].includes(record.state)) return json({ error: "release is not ready for public publication" }, 409);
  for (const asset of canonicalAssets(record.required_assets)) {
    const stored = await env.RELEASES.head(asset.r2_key);
    if (!stored || !Number.isSafeInteger(stored.size) || stored.size <= 0 || checksumHex(stored.checksums?.sha256) !== asset.sha256 ||
        stored.customMetadata?.releaseId !== id || stored.customMetadata?.assetName !== asset.name) {
      return json({ error: `public release staging is incomplete or failed integrity check: ${asset.name}` }, 409);
    }
  }
  if (record.source_release_id === undefined) return json({ error: "public Debian source release must be completed first" }, 409);
  await publishOne(env, key, now);
  const published = await readRecord(env.RELEASES, key);
  if (published?.record.state !== "public") return json({ error: "immediate public release did not reach the public state" }, 502);
  return json({ id, state: published.record.state, source_release_tag: published.record.source_release_tag, public_published_at: published.record.public_published_at }, 200);
}

async function publishPublicSources(request, env, id, now = new Date()) {
  const identity = await githubActionsIdentity(request, env);
  if (!identity || (identity.type !== "admin" && (identity.type !== "github-actions" || identity.workflow !== "private-staging"))) return json({ error: "private staging workflow identity required" }, 401);
  let key;
  try { key = stateKey(id); } catch { return json({ error: "invalid release id" }, 400); }
  const loaded = await readRecord(env.RELEASES, key);
  if (!loaded) return json({ error: "release not found" }, 404);
  const record = loaded.record;
  if (identity.run_id !== record.staging_run_id) return json({ error: "OIDC run identity does not match staged release" }, 403);
  if (!record.release_checks_passed || !["prepared", "sponsor-period", "public"].includes(record.state)) return json({ error: "source release is not eligible for publication" }, 409);
  if (!Array.isArray(record.source_assets) || record.source_assets.length === 0) return json({ error: "verified Debian source assets are required" }, 409);
  for (const asset of canonicalAssets(record.source_assets)) {
    const stored = await env.RELEASES.head(asset.r2_key);
    if (!stored || !Number.isSafeInteger(stored.size) || stored.size <= 0 || checksumHex(stored.checksums?.sha256) !== asset.sha256 ||
        stored.customMetadata?.releaseId !== id || stored.customMetadata?.assetName !== asset.name || stored.customMetadata?.assetKind !== "source") {
      return json({ error: `source staging is incomplete or failed integrity check: ${asset.name}` }, 409);
    }
  }
  try {
    const release = await publishSourceAssets(env, record);
    const next = await updateState(env.RELEASES, key, (current) => ({
      ...current, source_release_id: release.id, source_release_tag: release.tag_name,
      source_release_published_at: current.source_release_published_at || now.toISOString(),
    }));
    return json({ id, source_release_id: next.source_release_id, source_release_tag: next.source_release_tag, state: next.state }, 200);
  } catch (error) { return json({ error: String(error.message || error) }, 502); }
}

async function writeRecord(bucket, key, record, etag) {
  const options = { httpMetadata: { contentType: "application/json" } };
  options.onlyIf = etag ? { etagMatches: etag } : { etagDoesNotMatch: "*" };
  return bucket.put(key, JSON.stringify(record), options);
}

async function updateState(bucket, key, transform) {
  for (let attempt = 0; attempt < MAX_RETRIES; attempt += 1) {
    const previous = await readRecord(bucket, key);
    if (!previous) throw new Error("release state does not exist");
    const next = transform(previous.record);
    const saved = await writeRecord(bucket, key, next, previous.etag);
    if (saved) return next;
  }
  throw new Error("release state changed concurrently; retry later");
}

function stateKey(id) {
  if (typeof id !== "string" || !/^[a-z0-9][a-z0-9-]{1,100}$/.test(id)) throw new Error("invalid release id");
  return `${STATE_PREFIX}${id}.json`;
}

function assertRelease(record) {
  if (!record || !["prepared", "sponsor-period", "public"].includes(record.state)) throw new Error("invalid release state");
  const approvedRepositories = new Set([
    "getpatched/packaging-libxml2", "getpatched/packaging-libarchive",
    "getpatched/packaging-libpng1.6", "getpatched/packaging-libgit2",
    "getpatched/packaging-tiff", "getpatched/packaging-poppler",
  ]);
  if (!approvedRepositories.has(record.repository)) throw new Error("repository is not an approved package repository");
  if (typeof record.tag !== "string" || !/^getpatched\/(?:[a-z0-9-]+\/)?[A-Za-z0-9.+~-]+$/.test(record.tag)) throw new Error("invalid immutable release tag");
  const targetId = record.target_id || "ubuntu-focal-amd64";
  const supportedTargetIds = new Set(Object.values(REPOSITORY_TARGETS).flatMap((architectures) => Object.values(architectures)));
  if (!supportedTargetIds.has(targetId)) throw new Error("release target is not a configured repository suite and architecture");
  if (record.public_contribution_spdx !== undefined && record.public_contribution_spdx !== "MIT") throw new Error("public GetPatched contributions must use the configured MIT license");
  if (!Number.isInteger(record.sponsor_delay_hours) || ![0, 168].includes(record.sponsor_delay_hours)) throw new Error("policy must be 0 or 168 hours");
  const expectedDelay = record.repository === "getpatched/packaging-libxml2" ? 168 : 0;
  if (record.sponsor_delay_hours !== expectedDelay) throw new Error("release policy does not match the configured package");
  if (expectedDelay === 0 && record.state === "sponsor-period") throw new Error("immediately public packages cannot enter a sponsor period");
  if (expectedDelay === 168 && record.early_binary_license_id !== undefined && record.early_binary_license_id !== "LicenseRef-GetPatched-Early-Binary-1.2") throw new Error("sponsor-first release has an unsupported early-binary license");
  if (!Array.isArray(record.required_assets) || record.required_assets.length === 0) throw new Error("required assets missing");
  canonicalAssets(record.required_assets);
}

function packageName(repository) {
  return repository.slice("getpatched/packaging-".length);
}

async function verifyPackageRun(env, repository, sourceCommit, tag, runId, targetId = "ubuntu-focal-amd64", sourceBranch = "getpatched/focal") {
  if (!Number.isSafeInteger(runId) || runId <= 0) throw new Error("verification_run_id must be a positive integer");
  if (typeof sourceCommit !== "string" || !/^[a-f0-9]{40}$/.test(sourceCommit)) throw new Error("source_commit must be a full Git commit SHA");
  const runResponse = await githubRequest(env, `/repos/getpatched/platform/actions/runs/${runId}`);
  const run = await runResponse.json();
  const expectedPath = ".github/workflows/package-verification.yml";
  const expectedTitle = `Verify ${packageName(repository)} on ${targetId} at ${sourceCommit}`;
  if (run.event !== "workflow_dispatch" || run.conclusion !== "success" || run.head_branch !== "main" || run.path !== expectedPath || run.display_title !== expectedTitle) {
    throw new Error("verification run must be a successful package-verification dispatch from main");
  }
  const jobsResponse = await githubRequest(env, `/repos/getpatched/platform/actions/runs/${runId}/jobs?per_page=100`);
  const jobs = await jobsResponse.json();
  const requiredJob = `package (${packageName(repository)})`;
  const job = jobs.jobs?.find((candidate) => candidate.name === requiredJob && candidate.run_attempt === run.run_attempt);
  if (!job || job.conclusion !== "success") throw new Error(`required verification job did not pass: ${requiredJob}`);
  await verifySignedSourceTag(env, repository, tag, sourceCommit, sourceBranch);
  return {
    run_id: run.id,
    run_url: run.html_url,
    head_sha: run.head_sha,
    completed_at: run.updated_at,
    job_name: job.name,
    job_id: job.id,
  };
}

async function verifySignedSourceTag(env, repository, tag, sourceCommit, sourceBranch = "getpatched/focal") {
  if (typeof sourceBranch !== "string" || !/^getpatched\/[a-z0-9-]+$/.test(sourceBranch)) {
    throw new Error("configured package source branch is invalid");
  }
  const allowedSigner = String(env.GETPATCHED_RELEASE_TAG_SIGNER || "").trim().toLowerCase();
  if (!allowedSigner) throw new Error("allowed GitHub release-tag signer is not configured");
  const encodedTag = tag.split("/").map(encodeURIComponent).join("/");
  const refResponse = await githubRequest(env, `/repos/${repository}/git/ref/tags/${encodedTag}`);
  const ref = await refResponse.json();
  if (ref.ref !== `refs/tags/${tag}`) throw new Error("package tag reference must resolve exactly");
  let object = ref.object;
  if (object?.type !== "tag" || typeof object.sha !== "string") throw new Error("package release tag must be an annotated signed tag");
  const tagResponse = await githubRequest(env, `/repos/${repository}/git/tags/${object.sha}`);
  const annotated = await tagResponse.json();
  if (annotated.sha !== object.sha || annotated.verification?.verified !== true || annotated.verification?.reason !== "valid" || annotated.object?.type !== "commit" || annotated.object.sha !== sourceCommit) {
    throw new Error("signed package tag must verify and point to the tested source commit");
  }
  const [owner, name] = repository.split("/");
  const signerResponse = await fetch(`${env.GITHUB_API}/graphql`, {
    method: "POST",
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${env.GITHUB_TOKEN}`,
      "content-type": "application/json",
      "x-github-api-version": "2022-11-28",
    },
    body: JSON.stringify({
      query: "query($owner: String!, $name: String!, $expression: String!) { repository(owner: $owner, name: $name) { object(expression: $expression) { __typename ... on Tag { oid name tagger { email user { login } } } } } }",
      variables: { owner, name, expression: `refs/tags/${tag}` },
    }),
  });
  if (!signerResponse.ok) throw new Error(`GitHub signer lookup returned ${signerResponse.status}`);
  const signerPayload = await signerResponse.json();
  if (signerPayload.errors?.length) throw new Error("GitHub signer lookup failed");
  const signedTag = signerPayload.data?.repository?.object;
  if (signedTag?.__typename !== "Tag" || signedTag.oid !== object.sha || signedTag.name !== tag ||
      !signedTag.tagger?.email || signedTag.tagger.email.toLowerCase() !== annotated.tagger?.email?.toLowerCase() ||
      signedTag.tagger.user?.login?.toLowerCase() !== allowedSigner) {
    throw new Error("package release tag signer is not the configured GitHub account");
  }
  const ancestry = await githubRequest(env, `/repos/${repository}/compare/${encodeURIComponent(sourceBranch)}...${sourceCommit}`);
  const comparison = await ancestry.json();
  if (comparison.merge_base_commit?.sha !== sourceCommit) {
    throw new Error(`tested source commit must be reachable from ${sourceBranch}`);
  }
  return annotated;
}

async function registerRelease(request, env) {
  const identity = await githubActionsIdentity(request, env);
  if (!identity || (identity.type !== "admin" && identity.workflow !== "private-staging")) {
    return json({ error: "unauthorized" }, 401);
  }
  const body = await readBoundedJson(request, MAX_REGISTRATION_BYTES);
  if (!env.ASSETS) throw requestError("platform package policy is unavailable", 503);
  const policyResponse = await env.ASSETS.fetch(new Request("https://getpatched.dev/packages.json"));
  if (!policyResponse.ok) throw requestError("platform package policy is unavailable", 503);
  const platformPolicy = await policyResponse.json();
  const packageKey = typeof body.repository === "string" && body.repository.startsWith("getpatched/packaging-")
    ? body.repository.slice("getpatched/packaging-".length) : "";
  const targetProfile = platformPolicy.targets?.[body.target_id];
  const sourceBranch = targetProfile?.sourceBranch;
  const packageTarget = platformPolicy.packages?.[packageKey]?.targets?.[body.target_id];
  const configured = packageTarget?.releaseAccess;
  if (!configured || typeof sourceBranch !== "string" || !/^getpatched\/[a-z0-9-]+$/.test(sourceBranch)) {
    throw requestError("release package target or source branch is not configured", 422);
  }
  if (packageTarget.candidateStatus !== "development-verified-production-release-pending") {
    throw requestError("package candidate has not passed its verification gates", 422);
  }
  const requiredDelay = configured.sponsorDelayHours;
  const expectedPolicy = requiredDelay === 168 ? "sponsor-first" : "public-after-checks";
  if (![0, 168].includes(requiredDelay) || configured.policy !== expectedPolicy ||
      configured.publicContributionSpdx !== "MIT" ||
      JSON.stringify(configured.earlyUse) !== JSON.stringify(["private", "commercial"]) ||
      configured.earlyRedistributionAllowed !== false || configured.publicLicenseScope !== "getpatched-authored-contributions-only" ||
      (requiredDelay === 168 && (configured.sponsorEligibility !== "any-active-individual-github-sponsorship-tier" ||
        configured.earlyBinaryLicenseId !== "LicenseRef-GetPatched-Early-Binary-1.2")) ||
      (requiredDelay === 0 && (configured.sponsorEligibility !== null || configured.earlyBinaryLicenseId !== null))) {
    throw requestError("configured release access or license policy is invalid", 503);
  }
  const supportedTargetIds = new Set(Object.values(REPOSITORY_TARGETS).flatMap((architectures) => Object.values(architectures)));
  if (!supportedTargetIds.has(body.target_id) || body.public_contribution_spdx !== "MIT" ||
      body.sponsor_delay_hours !== requiredDelay ||
      body.early_binary_license_id !== (requiredDelay ? configured.earlyBinaryLicenseId : null)) {
    throw requestError("release target, sponsorship, or license policy is incomplete or unsupported", 422);
  }
  const record = {
    id: body.id,
    state: "prepared",
    repository: body.repository,
    tag: body.tag,
    target_id: body.target_id || "ubuntu-focal-amd64",
    source_commit: body.source_commit,
    sponsor_delay_hours: body.sponsor_delay_hours,
    early_binary_license_id: body.early_binary_license_id,
    public_contribution_spdx: body.public_contribution_spdx,
    release_checks_passed: false,
    required_assets: releaseAssets(body.required_assets, body.id),
    source_assets: releaseAssets(body.source_assets, body.id).map((asset) => ({ ...asset, r2_key: `staging/${body.id}/source/${asset.sha256}` })),
    created_at: new Date().toISOString(),
    ...(identity.type === "github-actions" ? { staging_run_id: identity.run_id } : {}),
  };
  assertRelease(record);
  const verifiedRun = await verifyPackageRun(env, record.repository, record.source_commit, record.tag, body.verification_run_id, record.target_id, sourceBranch);
  record.release_checks_passed = true;
  record.verification = verifiedRun;
  const existing = await readRecord(env.RELEASES, stateKey(record.id));
  if (existing) {
    const current = existing.record;
    const sameRelease = current.repository === record.repository && current.tag === record.tag && current.source_commit === record.source_commit &&
      current.sponsor_delay_hours === record.sponsor_delay_hours &&
      JSON.stringify(canonicalAssets(current.required_assets)) === JSON.stringify(canonicalAssets(record.required_assets)) &&
      JSON.stringify(canonicalAssets(current.source_assets || [])) === JSON.stringify(canonicalAssets(record.source_assets));
    if (!sameRelease) return json({ error: "release id already exists with different immutable release data" }, 409);
    const next = await updateState(env.RELEASES, stateKey(record.id), (latest) => ({
      ...latest,
      ...(identity.type === "github-actions" ? { staging_run_id: identity.run_id } : {}),
    }));
    return json({ id: record.id, state: next.state, replay: true }, 200);
  }
  const saved = await writeRecord(env.RELEASES, stateKey(record.id), record, null);
  if (!saved) return json({ error: "release id already exists" }, 409);
  return json({ id: record.id, state: record.state }, 201);
}

async function uploadReleaseAsset(request, env, id, name, kind = "binary") {
  const identity = await githubActionsIdentity(request, env);
  if (!identity || (identity.type !== "admin" && identity.workflow !== "private-staging")) {
    return json({ error: "unauthorized" }, 401);
  }
  let key;
  try { key = stateKey(id); } catch { return json({ error: "invalid release id" }, 400); }
  if (!/^[A-Za-z0-9][A-Za-z0-9._+~-]*$/.test(name)) return json({ error: "invalid asset name" }, 400);
  const loaded = await readRecord(env.RELEASES, key);
  if (!loaded) return json({ error: "release not found" }, 404);
  const record = loaded.record;
  if (identity.type === "github-actions" && identity.run_id !== record.staging_run_id) return json({ error: "OIDC run identity does not match staged release" }, 403);
  if (record.state !== "prepared" || record.release_checks_passed !== true) {
    return json({ error: "release is not accepting staged assets" }, 409);
  }
  const manifest = kind === "source" ? record.source_assets : record.required_assets;
  const asset = canonicalAssets(manifest || []).find((candidate) => candidate.name === name);
  if (!asset) return json({ error: "asset is not in the verified release manifest" }, 404);
  const lengthHeader = request.headers.get("content-length");
  const length = lengthHeader === null ? NaN : Number(lengthHeader);
  if (!Number.isSafeInteger(length) || length <= 0 || length > MAX_RELEASE_ASSET_BYTES) {
    return json({ error: "asset size must be declared and at most 64 MiB" }, 413);
  }
  if (!request.body) return json({ error: "asset body is required" }, 400);

  const options = {
    onlyIf: { etagDoesNotMatch: "*" },
    sha256: checksumBuffer(asset.sha256),
    httpMetadata: { contentType: "application/octet-stream" },
    customMetadata: { sha256: asset.sha256, releaseId: id, assetName: name, assetKind: kind },
  };
  const stored = await env.RELEASES.put(asset.r2_key, request.body, options);
  if (stored) {
    if (stored.size !== length || checksumHex(stored.checksums?.sha256) !== asset.sha256) {
      return json({ error: "R2 stored asset size or checksum did not match the verified manifest" }, 422);
    }
    return json({ name, sha256: asset.sha256, bytes: length, stored: true }, 201);
  }

  const existing = await env.RELEASES.head(asset.r2_key);
  // R2 validates the supplied SHA-256 on put and exposes its computed checksum
  // through checksums; user-supplied custom metadata alone is never sufficient.
  if (existing?.size === length && checksumHex(existing.checksums?.sha256) === asset.sha256 &&
      existing.customMetadata?.releaseId === id && existing.customMetadata?.assetName === name) {
    return json({ name, sha256: asset.sha256, bytes: length, stored: true, replay: true }, 200);
  }
  return json({ error: "staging key already exists with different content" }, 409);
}

async function githubRequest(env, path, options = {}) {
  if (!env.GITHUB_TOKEN) throw new Error("GitHub publication token is not configured");
  const response = await fetch(`${env.GITHUB_API}${path}`, {
    ...options,
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${env.GITHUB_TOKEN}`,
      "x-github-api-version": "2022-11-28",
      ...(options.headers || {}),
    },
  });
  if (!response.ok) throw new Error(`GitHub API returned ${response.status} for ${path}`);
  return response;
}

async function githubUpload(url, env, options = {}) {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" || parsed.hostname !== "uploads.github.com") {
    throw new Error("GitHub returned an unexpected release upload host");
  }
  const response = await fetch(url, {
    ...options,
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${env.GITHUB_TOKEN}`,
      "x-github-api-version": "2022-11-28",
      ...(options.headers || {}),
    },
  });
  if (!response.ok) throw new Error(`GitHub release asset upload returned ${response.status}`);
  return response;
}

async function ensureGithubRelease(env, record) {
  const [owner, repo] = record.repository.split("/");
  const tag = encodeURIComponent(record.tag);
  const existing = await fetch(`${env.GITHUB_API}/repos/${owner}/${repo}/releases/tags/${tag}`, {
    headers: { accept: "application/vnd.github+json", authorization: `Bearer ${env.GITHUB_TOKEN}`, "x-github-api-version": "2022-11-28" },
  });
  if (existing.ok) {
    const release = await existing.json();
    if (release.tag_name !== record.tag) throw new Error("GitHub release tag does not match the registered tag");
    if (!release.draft && !release.assets?.length) throw new Error("published GitHub release is empty; refusing to mutate it");
    return release;
  }
  if (existing.status !== 404) throw new Error(`GitHub release lookup returned ${existing.status}`);
  const created = await githubRequest(env, `/repos/${owner}/${repo}/releases`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ tag_name: record.tag, name: record.tag, draft: true, prerelease: false, generate_release_notes: false }),
  });
  return created.json();
}

async function publishSourceAssets(env, record) {
  const [owner, repo] = record.repository.split("/");
  const tagName = sourceReleaseTag(record);
  const lookup = await fetch(`${env.GITHUB_API}/repos/${owner}/${repo}/releases/tags/${tagName.split("/").map(encodeURIComponent).join("/")}`, {
    headers: { accept: "application/vnd.github+json", authorization: `Bearer ${env.GITHUB_TOKEN}`, "x-github-api-version": "2022-11-28" },
  });
  let release;
  if (lookup.ok) {
    release = await lookup.json();
    if (release.tag_name !== tagName || (!release.draft && !release.assets?.length)) throw new Error("source release tag mismatch or published release is empty");
  } else if (lookup.status === 404) {
    release = await (await githubRequest(env, `/repos/${record.repository}/releases`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ tag_name: tagName, target_commitish: record.source_commit, name: `Debian source ${record.tag.slice("getpatched/".length)}`, draft: true, prerelease: false, generate_release_notes: false }),
    })).json();
  } else throw new Error(`GitHub source release lookup returned ${lookup.status}`);
  const assets = canonicalAssets(record.source_assets || []);
  const allowed = new Set(assets.map((asset) => asset.name));
  if ((release.assets || []).some((asset) => !allowed.has(asset.name))) throw new Error("source release contains assets outside the verified manifest");
  for (const asset of assets) {
    const currentHash = await assetReadback(env, { ...release, owner: { login: owner }, name: repo }, asset.name);
    if (currentHash) {
      if (currentHash !== asset.sha256) throw new Error(`published source asset ${asset.name} differs from immutable manifest`);
      continue;
    }
    if (!release.draft) throw new Error(`published source release is missing ${asset.name}; refusing to mutate it`);
    const staged = await env.RELEASES.get(asset.r2_key);
    if (!staged) throw new Error(`staged source asset ${asset.name} is missing`);
    const bytes = await staged.arrayBuffer();
    if (await sha256Hex(bytes) !== asset.sha256) throw new Error(`staged source asset ${asset.name} failed SHA-256 verification`);
    const uploadUrl = new URL(release.upload_url.replace("{?name,label}", ""));
    uploadUrl.searchParams.set("name", asset.name);
    await githubUpload(uploadUrl, env, { method: "POST", headers: { "content-type": "application/octet-stream", "content-length": String(bytes.byteLength) }, body: bytes });
    if (await assetReadback(env, { ...release, owner: { login: owner }, name: repo }, asset.name) !== asset.sha256) throw new Error(`GitHub readback hash mismatch for source asset ${asset.name}`);
  }
  if (release.draft) {
    await requireImmutableReleasesEnabled(env, record.repository);
    const finalized = await (await githubRequest(env, `/repos/${record.repository}/releases/${release.id}`, {
      method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ draft: false }),
    })).json();
    if (finalized.immutable !== true) throw new Error("GitHub did not mark the source release immutable");
    return finalized;
  }
  if (release.immutable !== true) throw new Error("published source release is not immutable");
  return release;
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function assetReadback(env, release, name) {
  const response = await githubRequest(env, `/repos/${release.owner?.login || release.owner}/${release.name}/releases/${release.id}/assets`);
  const assets = await response.json();
  const asset = assets.find((candidate) => candidate.name === name);
  if (!asset) return null;
  const download = await fetch(asset.url, {
    headers: { accept: "application/octet-stream", authorization: `Bearer ${env.GITHUB_TOKEN}`, "x-github-api-version": "2022-11-28" },
    redirect: "follow",
  });
  if (!download.ok) throw new Error(`GitHub asset readback returned ${download.status}`);
  return sha256Hex(await download.arrayBuffer());
}

async function requireImmutableReleasesEnabled(env, repository) {
  const response = await githubRequest(env, `/repos/${repository}/immutable-releases`);
  const policy = await response.json();
  if (policy.enabled !== true) throw new Error("GitHub immutable releases must be enabled before publishing");
}

async function auditPublicRelease(env, record) {
  if (!Number.isSafeInteger(record.public_release_id) || !Array.isArray(record.verified_assets)) {
    throw new Error("public release is missing its immutable release id or verified asset manifest");
  }
  const response = await githubRequest(env, `/repos/${record.repository}/releases/${record.public_release_id}`);
  const release = await response.json();
  if (release.draft || release.immutable !== true || release.tag_name !== record.tag) {
    throw new Error("public GitHub release is not immutable or no longer matches its release tag");
  }
  await verifySignedSourceTag(env, record.repository, record.tag, record.source_commit);
  const expected = canonicalAssets(record.verified_assets);
  const expectedNames = new Set(expected.map((asset) => asset.name));
  if ((release.assets || []).length !== expected.length || (release.assets || []).some((asset) => !expectedNames.has(asset.name))) {
    throw new Error("public GitHub release asset list differs from the verified manifest");
  }
  for (const asset of expected) {
    const digest = await assetReadback(env, { ...release, owner: record.repository.split("/")[0], name: record.repository.split("/")[1] }, asset.name);
    if (digest !== asset.sha256) throw new Error(`public release asset ${asset.name} failed integrity audit`);
  }
}

async function auditPublicSourceRelease(env, record) {
  if (!Number.isSafeInteger(record.source_release_id) || !Array.isArray(record.source_assets) || !record.source_release_tag) {
    throw new Error("public source release is missing its immutable release id or verified source manifest");
  }
  const response = await githubRequest(env, `/repos/${record.repository}/releases/${record.source_release_id}`);
  const release = await response.json();
  if (release.draft || release.immutable !== true || release.tag_name !== sourceReleaseTag(record) || release.tag_name !== record.source_release_tag) {
    throw new Error("public source release is not immutable or no longer matches its source tag");
  }
  const expected = canonicalAssets(record.source_assets);
  const expectedNames = new Set(expected.map((asset) => asset.name));
  if ((release.assets || []).length !== expected.length || (release.assets || []).some((asset) => !expectedNames.has(asset.name))) {
    throw new Error("public source release asset list differs from the verified source manifest");
  }
  for (const asset of expected) {
    const digest = await assetReadback(env, { ...release, owner: record.repository.split("/")[0], name: record.repository.split("/")[1] }, asset.name);
    if (digest !== asset.sha256) throw new Error(`public source asset ${asset.name} failed integrity audit`);
  }
}

async function cleanupPublishedReleaseStaging(env, record, now) {
  if (!record.public_published_at) return 0;
  let publishedAt;
  try { publishedAt = parseUtc(record.public_published_at).getTime(); }
  catch { throw new Error("public release staging recovery timestamp is invalid"); }
  const expectedCleanupAt = new Date(publishedAt + PUBLIC_RELEASE_STAGING_RECOVERY_MS).toISOString();
  if (record.staging_cleanup_after && record.staging_cleanup_after !== expectedCleanupAt) {
    throw new Error("public release staging cleanup deadline differs from the documented recovery interval");
  }
  if (now.getTime() < Date.parse(expectedCleanupAt)) return 0;
  await auditPublicSourceRelease(env, record);
  const assets = [
    ...canonicalAssets(record.required_assets).map((asset) => ({ ...asset, expected: `staging/${record.id}/${asset.sha256}` })),
    ...canonicalAssets(record.source_assets).map((asset) => ({ ...asset, expected: `staging/${record.id}/source/${asset.sha256}` })),
  ];
  const keys = assets.map((asset) => {
    if (asset.r2_key !== asset.expected) throw new Error("release staging key differs from its immutable release identity");
    return asset.expected;
  });
  for (let offset = 0; offset < keys.length; offset += 1000) await env.RELEASES.delete(keys.slice(offset, offset + 1000));
  return keys.length;
}

async function publishAssets(env, record) {
  const [owner, repo] = record.repository.split("/");
  const release = await ensureGithubRelease(env, record);
  const expectedAssets = canonicalAssets(record.required_assets);
  const expectedNames = new Set(expectedAssets.map((asset) => asset.name));
  if ((release.assets || []).some((asset) => !expectedNames.has(asset.name))) {
    throw new Error("GitHub release contains assets outside the registered manifest");
  }
  for (const asset of expectedAssets) {
    const currentHash = await assetReadback(env, { ...release, owner: { login: owner }, name: repo }, asset.name);
    if (currentHash) {
      if (currentHash !== asset.sha256) throw new Error(`published asset ${asset.name} differs from immutable manifest`);
      continue;
    }
    if (!release.draft) throw new Error(`published GitHub release is missing required asset ${asset.name}; refusing to mutate it`);
    const staged = await env.RELEASES.get(asset.r2_key);
    if (!staged) throw new Error(`staged asset ${asset.name} is missing`);
    const bytes = await staged.arrayBuffer();
    if (await sha256Hex(bytes) !== asset.sha256) throw new Error(`staged asset ${asset.name} failed SHA-256 verification`);
    const uploadUrl = new URL(release.upload_url.replace("{?name,label}", ""));
    uploadUrl.searchParams.set("name", asset.name);
    await githubUpload(uploadUrl, env, {
      method: "POST",
      headers: { "content-type": staged.httpMetadata?.contentType || "application/octet-stream", "content-length": String(bytes.byteLength) },
      body: bytes,
    });
    const readbackHash = await assetReadback(env, { ...release, owner: { login: owner }, name: repo }, asset.name);
    if (readbackHash !== asset.sha256) throw new Error(`GitHub readback hash mismatch for ${asset.name}`);
  }
  if (!release.draft) {
    if (release.immutable !== true) throw new Error("published GitHub release is not immutable");
    return release;
  }
  await requireImmutableReleasesEnabled(env, record.repository);
  const published = await githubRequest(env, `/repos/${owner}/${repo}/releases/${release.id}`, {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ draft: false }),
  });
  const finalized = await published.json();
  if (finalized.immutable !== true) throw new Error("GitHub did not mark the published release immutable");
  return finalized;
}

function verifiedReleaseAssets(record) {
  return canonicalAssets(record.required_assets).map(({ name, sha256, r2_key }) => ({ name, sha256, r2_key }));
}

async function publishOne(env, key, now) {
  const loaded = await readRecord(env.RELEASES, key);
  if (!loaded) return;
  const record = loaded.record;
  assertRelease(record);
  if (record.state === "public") {
    await auditPublicRelease(env, record);
    await cleanupPublishedReleaseStaging(env, record, now);
    return;
  }
  if (!record.release_checks_passed) return;
  if (record.state === "prepared" && record.sponsor_delay_hours === 168) {
    throw new Error("seven-day release must complete private sponsor publication before reconciliation");
  }
  if (!Number.isSafeInteger(record.source_release_id)) return;
  await verifySignedSourceTag(env, record.repository, record.tag, record.source_commit);
  if (record.state === "sponsor-period" && now < parseUtc(record.public_after)) return;
  const release = await publishAssets(env, record);
  await updateState(env.RELEASES, key, (current) => {
    if (current.state === "public") return current;
    if (current.state === "sponsor-period" && now < parseUtc(current.public_after)) throw new Error("promotion deadline has not arrived");
    if (current.state === "sponsor-period" && JSON.stringify(verifiedReleaseAssets(current)) !== JSON.stringify(verifiedReleaseAssets(record))) {
      throw new Error("asset manifest changed during promotion");
    }
    return {
      ...current,
      state: "public",
      public_release_id: release.id,
      public_published_at: now.toISOString(),
      staging_cleanup_after: new Date(now.getTime() + PUBLIC_RELEASE_STAGING_RECOVERY_MS).toISOString(),
      verified_assets: verifiedReleaseAssets(current),
    };
  });
}

async function reconcile(env, now = new Date()) {
  let cursor;
  const failures = [];
  do {
    const page = await env.RELEASES.list({ prefix: STATE_PREFIX, cursor, limit: 1000 });
    for (const item of page.objects) {
      try { await publishOne(env, item.key, now); }
      catch (error) { failures.push({ key: item.key, error: String(error.message || error) }); }
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  return failures;
}

export default {
  async fetch(request, env, context) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/account") {
      if (!env.ASSETS) return new Response("account page is not configured", { status: 503 });
      return env.ASSETS.fetch(request);
    }
    const securityPage = await handleSecurityPage(request, env);
    if (securityPage) return securityPage;
    if (request.method === "GET" && url.pathname === "/api/me") {
      try { return await accountStatus(request, env); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 500); }
    }
    if (request.method === "POST" && url.pathname === "/internal/r2-self-test") {
      try { return await verifyR2Binding(request, env); }
      catch { return json({ error: "R2 storage self-test failed", stage: "unexpected" }, 502); }
    }
    if (request.method === "GET" && url.pathname === "/auth/github") return beginGithubLogin(request, env);
    if (request.method === "GET" && url.pathname === "/auth/github/callback") {
      try { return await githubLoginCallback(request, env); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 502); }
    }
    if (request.method === "POST" && url.pathname === "/api/logout") {
      try { return await logout(request, env); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 500); }
    }
    if (request.method === "GET" && url.pathname === "/api/device-tokens") {
      try { return await listDeviceTokens(request, env); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 500); }
    }
    if (request.method === "POST" && url.pathname === "/api/device-tokens") {
      try { return await issueDeviceToken(request, env); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 500); }
    }
    const sponsorPublishRoute = url.pathname.match(/^\/internal\/releases\/([^/]+)\/publish-sponsor$/);
    if (request.method === "POST" && sponsorPublishRoute) {
      let id;
      try { id = decodeURIComponent(sponsorPublishRoute[1]); }
      catch { return json({ error: "invalid path encoding" }, 400); }
      try { return await beginSponsorPublication(request, env, id); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 500); }
    }
    const publishNowRoute = url.pathname.match(/^\/internal\/releases\/([^/]+)\/publish-now$/);
    if (request.method === "POST" && publishNowRoute) {
      let id;
      try { id = decodeURIComponent(publishNowRoute[1]); }
      catch { return json({ error: "invalid path encoding" }, 400); }
      try { return await publishImmediateRelease(request, env, id); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 502); }
    }
    const publishSourcesRoute = url.pathname.match(/^\/internal\/releases\/([^/]+)\/publish-sources$/);
    if (request.method === "POST" && publishSourcesRoute) {
      let id;
      try { id = decodeURIComponent(publishSourcesRoute[1]); }
      catch { return json({ error: "invalid path encoding" }, 400); }
      try { return await publishPublicSources(request, env, id); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 502); }
    }
    const sourceAssetRoute = url.pathname.match(/^\/internal\/releases\/([^/]+)\/source-assets\/([^/]+)$/);
    if (request.method === "PUT" && sourceAssetRoute) {
      let id;
      try { id = decodeURIComponent(sourceAssetRoute[1]); }
      catch { return json({ error: "invalid path encoding" }, 400); }
      let name;
      try { name = decodeURIComponent(sourceAssetRoute[2]); }
      catch { return json({ error: "invalid asset name encoding" }, 400); }
      try { return await uploadReleaseAsset(request, env, id, name, "source"); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 500); }
    }
    const snapshotUploadRoute = url.pathname.match(/^\/internal\/repository-snapshots\/(public|early)\/([^/]+)\/files\/(.+)$/);
    if (request.method === "PUT" && snapshotUploadRoute) {
      try { return await uploadRepositorySnapshotFile(request, env, snapshotUploadRoute[1], snapshotUploadRoute[2], snapshotUploadRoute[3]); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 500); }
    }
    const snapshotBuildFileRoute = url.pathname.match(/^\/internal\/repository-snapshot-builds\/(public|early)\/([^/]+)\/files\/(.+)$/);
    if (["GET", "HEAD", "PUT"].includes(request.method) && snapshotBuildFileRoute) {
      const [, channel, id, encodedPath] = snapshotBuildFileRoute;
      try {
        if (request.method === "PUT") return await uploadRepositorySnapshotBuildFile(request, env, channel, id, encodedPath);
        return await readRepositorySnapshotBuild(request, env, channel, id, encodedPath);
      } catch (error) { return json({ error: String(error.message || error) }, error.status || 500); }
    }
    const snapshotBuildManifestRoute = url.pathname.match(/^\/internal\/repository-snapshot-builds\/(public|early)\/([^/]+)$/);
    if (request.method === "GET" && snapshotBuildManifestRoute) {
      const [, channel, id] = snapshotBuildManifestRoute;
      try {
        return await readRepositorySnapshotBuild(request, env, channel, id, "manifest.json");
      } catch (error) { return json({ error: String(error.message || error) }, error.status || 500); }
    }
    const snapshotBuildRegistrationRoute = url.pathname.match(/^\/internal\/repository-snapshot-builds\/(public|early)$/);
    if (request.method === "POST" && snapshotBuildRegistrationRoute) {
      try { return await registerRepositorySnapshotBuild(request, env, snapshotBuildRegistrationRoute[1]); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 500); }
    }
    const snapshotActivationRoute = url.pathname.match(/^\/internal\/repository-snapshots\/(public|early)\/([^/]+)\/activate$/);
    if (request.method === "POST" && snapshotActivationRoute) {
      try { return await activateRepositorySnapshot(request, env, snapshotActivationRoute[1], snapshotActivationRoute[2]); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 500); }
    }
    const snapshotRegistrationRoute = url.pathname.match(/^\/internal\/repository-snapshots\/(public|early)$/);
    if (request.method === "POST" && snapshotRegistrationRoute) {
      try { return await registerRepositorySnapshot(request, env, snapshotRegistrationRoute[1]); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 500); }
    }
    if (request.method === "POST" && url.pathname === "/internal/repository-snapshots/retention") {
      try { return await pruneRepositorySnapshots(request, env); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 500); }
    }
    const snapshotInventoryRoute = url.pathname.match(/^\/internal\/repository-snapshots\/(public|early)\/releases$/);
    if (request.method === "GET" && snapshotInventoryRoute) {
      try { return await listSnapshotReleases(request, env, snapshotInventoryRoute[1]); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 500); }
    }
    const snapshotAssetRoute = url.pathname.match(/^\/internal\/repository-snapshots\/(public|early)\/releases\/([^/]+)\/assets\/([^/]+)$/);
    if (["GET", "HEAD"].includes(request.method) && snapshotAssetRoute) {
      let id;
      let name;
      try { id = decodeURIComponent(snapshotAssetRoute[2]); name = decodeURIComponent(snapshotAssetRoute[3]); }
      catch { return json({ error: "invalid path encoding" }, 400); }
      try { return await readSnapshotReleaseAsset(request, env, snapshotAssetRoute[1], id, name); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 500); }
    }
    const revokeRoute = url.pathname.match(/^\/api\/device-tokens\/([a-f0-9]{64})\/revoke$/);
    if (request.method === "POST" && revokeRoute) {
      try { return await revokeDeviceToken(request, env, revokeRoute[1]); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 500); }
    }
    const earlyAssetRoute = url.pathname.match(/^\/early\/releases\/([^/]+)\/assets\/([^/]+)$/);
    if (["GET", "HEAD"].includes(request.method) && earlyAssetRoute) {
      let id;
      let name;
      try {
        id = decodeURIComponent(earlyAssetRoute[1]);
        name = decodeURIComponent(earlyAssetRoute[2]);
      } catch { return json({ error: "invalid path encoding" }, 400); }
      try { return await serveEarlyAsset(request, env, id, name); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 500); }
    }
    const poolRoute = url.pathname.match(/^\/pool\/(.+)$/);
    if (["GET", "HEAD"].includes(request.method) && poolRoute) {
      let path;
      try { path = decodeURIComponent(poolRoute[1]); }
      catch { return json({ error: "invalid repository path encoding" }, 400); }
      const channel = url.hostname === "early.getpatched.dev" ? "early" : "public";
      try { return await servePoolAsset(request, env, `pool/${path}`, channel); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 500); }
    }
    const repositoryFileRoute = url.pathname.match(/^\/dists\/(.+)$/);
    if (["GET", "HEAD"].includes(request.method) && repositoryFileRoute) {
      let path;
      try { path = `dists/${decodeURIComponent(repositoryFileRoute[1])}`; }
      catch { return json({ error: "invalid repository metadata path encoding" }, 400); }
      const channel = new URL(request.url).hostname === "early.getpatched.dev" ? "early" : "public";
      try { return await serveRepositoryFile(request, env, channel, path); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 500); }
    }
    if (["GET", "HEAD"].includes(request.method) && url.pathname === "/getpatched-archive-keyring.gpg") {
      try { return await serveRepositoryFile(request, env, "public", "getpatched-archive-keyring.gpg"); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 500); }
    }
    if (request.method === "POST" && url.pathname === "/webhooks/github/sponsorship") {
      return acceptSponsorWebhook(request, env, context);
    }
    const assetRoute = url.pathname.match(/^\/internal\/releases\/([^/]+)\/assets\/([^/]+)$/);
    if (request.method === "PUT" && assetRoute) {
      let id;
      let name;
      try {
        id = decodeURIComponent(assetRoute[1]);
        name = decodeURIComponent(assetRoute[2]);
      } catch {
        return json({ error: "invalid path encoding" }, 400);
      }
      try { return await uploadReleaseAsset(request, env, id, name); }
      catch (error) { return json({ error: String(error.message || error) }, 422); }
    }
    if (request.method === "POST" && url.pathname === "/internal/releases") {
      try { return await registerRelease(request, env); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 400); }
    }
    if (url.pathname.startsWith("/api/")) {
      if (url.pathname.endsWith(".json")) return notFoundJson(request);
      return json({ error: "not found" }, 404);
    }
    if (env.ASSETS) {
      const asset = await env.ASSETS.fetch(request);
      if (url.pathname.endsWith(".json") && (asset.status === 404 || asset.headers.get("content-type")?.includes("text/html"))) {
        return notFoundJson(request);
      }
      return asset;
    }
    if (url.pathname.endsWith(".json")) return notFoundJson(request);
    return json({ error: "not found" }, 404);
  },
  async scheduled(_event, env, context) {
    context.waitUntil(Promise.allSettled([reconcile(env), reconcileSponsors(env)]).then((results) => {
      for (const [index, result] of results.entries()) {
        if (result.status === "rejected") console.error(index === 0 ? "release reconciliation failed" : "sponsor reconciliation failed", String(result.reason?.message || result.reason));
        else if (index === 0 && result.value.length) console.error("promotion reconciliation had failures", result.value);
      }
    }));
  },
};

export { beginSponsorPublication, canonicalAssets, fetchSponsorSnapshot, githubActionsIdentity, hasActiveSponsorship, parseUtc, publishImmediateRelease, publishOne, publishPublicSources, readFreshSponsorSnapshot, reconcile, reconcileSponsors, recordSponsorRevocation, releaseAssets, requireImmutableReleasesEnabled, updateState, verifyGithubSignature, verifyPackageRun, verifySignedSourceTag };
