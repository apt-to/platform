const STATE_PREFIX = "release-state/";
const MAX_RETRIES = 5;

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

async function readRecord(bucket, key) {
  const object = await bucket.get(key);
  if (!object) return null;
  return { record: await object.json(), etag: object.etag };
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
  if (!["apt-to/packaging-libxml2", "apt-to/packaging-libarchive"].includes(record.repository)) throw new Error("repository is not an approved pilot package");
  if (typeof record.tag !== "string" || !/^aptto\/[A-Za-z0-9.+~-]+$/.test(record.tag)) throw new Error("invalid immutable release tag");
  if (!Number.isInteger(record.sponsor_delay_hours) || ![0, 168].includes(record.sponsor_delay_hours)) throw new Error("policy must be 0 or 168 hours");
  if (!Array.isArray(record.required_assets) || record.required_assets.length === 0) throw new Error("required assets missing");
  canonicalAssets(record.required_assets);
}

function packageName(repository) {
  return repository.slice("apt-to/packaging-".length);
}

async function verifyPackageRun(env, repository, sourceCommit, tag, runId) {
  if (!Number.isSafeInteger(runId) || runId <= 0) throw new Error("verification_run_id must be a positive integer");
  if (typeof sourceCommit !== "string" || !/^[a-f0-9]{40}$/.test(sourceCommit)) throw new Error("source_commit must be a full Git commit SHA");
  const runResponse = await githubRequest(env, `/repos/apt-to/platform/actions/runs/${runId}`);
  const run = await runResponse.json();
  const expectedPath = ".github/workflows/package-verification.yml";
  const expectedTitle = `Verify ${packageName(repository)} at ${sourceCommit}`;
  if (run.event !== "workflow_dispatch" || run.conclusion !== "success" || run.head_branch !== "main" || run.path !== expectedPath || run.display_title !== expectedTitle) {
    throw new Error("verification run must be a successful package-verification dispatch from main");
  }
  const jobsResponse = await githubRequest(env, `/repos/apt-to/platform/actions/runs/${runId}/jobs?per_page=100`);
  const jobs = await jobsResponse.json();
  const requiredJob = `package (${packageName(repository)})`;
  const job = jobs.jobs?.find((candidate) => candidate.name === requiredJob && candidate.run_attempt === run.run_attempt);
  if (!job || job.conclusion !== "success") throw new Error(`required verification job did not pass: ${requiredJob}`);
  await verifySignedSourceTag(env, repository, tag, sourceCommit);
  return {
    run_id: run.id,
    run_url: run.html_url,
    head_sha: run.head_sha,
    completed_at: run.updated_at,
    job_name: job.name,
    job_id: job.id,
  };
}

async function verifySignedSourceTag(env, repository, tag, sourceCommit) {
  const encodedTag = tag.split("/").map(encodeURIComponent).join("/");
  const refResponse = await githubRequest(env, `/repos/${repository}/git/ref/tags/${encodedTag}`);
  const ref = await refResponse.json();
  if (ref.ref !== `refs/tags/${tag}`) throw new Error("package tag reference must resolve exactly");
  let object = ref.object;
  if (object?.type !== "tag" || typeof object.sha !== "string") throw new Error("package release tag must be an annotated signed tag");
  const tagResponse = await githubRequest(env, `/repos/${repository}/git/tags/${object.sha}`);
  const annotated = await tagResponse.json();
  if (annotated.verification?.verified !== true || annotated.object?.type !== "commit" || annotated.object.sha !== sourceCommit) {
    throw new Error("signed package tag must verify and point to the tested source commit");
  }
  const ancestry = await githubRequest(env, `/repos/${repository}/compare/aptto%2Ffocal...${sourceCommit}`);
  const comparison = await ancestry.json();
  if (comparison.merge_base_commit?.sha !== sourceCommit) {
    throw new Error("tested source commit must be reachable from aptto/focal");
  }
  return annotated;
}

async function registerRelease(request, env) {
  if (!env.RELEASE_ADMIN_TOKEN || request.headers.get("authorization") !== `Bearer ${env.RELEASE_ADMIN_TOKEN}`) {
    return json({ error: "unauthorized" }, 401);
  }
  const body = await request.json();
  const record = {
    id: body.id,
    state: "prepared",
    repository: body.repository,
    tag: body.tag,
    source_commit: body.source_commit,
    sponsor_delay_hours: body.sponsor_delay_hours,
    release_checks_passed: false,
    required_assets: canonicalAssets(body.required_assets),
    created_at: new Date().toISOString(),
  };
  assertRelease(record);
  const verifiedRun = await verifyPackageRun(env, record.repository, record.source_commit, record.tag, body.verification_run_id);
  record.release_checks_passed = true;
  record.verification = verifiedRun;
  const saved = await writeRecord(env.RELEASES, stateKey(record.id), record, null);
  if (!saved) return json({ error: "release id already exists" }, 409);
  return json({ id: record.id, state: record.state }, 201);
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
    return;
  }
  if (!record.release_checks_passed) return;
  if (record.state === "prepared" && record.sponsor_delay_hours === 168) {
    throw new Error("seven-day releases are disabled until sponsor authentication and private serving are integrated");
  }
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
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/internal/releases") {
      try { return await registerRelease(request, env); }
      catch (error) { return json({ error: String(error.message || error) }, 400); }
    }
    return json({ error: "not found" }, 404);
  },
  async scheduled(_event, env, context) {
    context.waitUntil(reconcile(env).then((failures) => {
      if (failures.length) console.error("promotion reconciliation had failures", failures);
    }));
  },
};

export { canonicalAssets, parseUtc, publishOne, reconcile, requireImmutableReleasesEnabled, updateState, verifyPackageRun, verifySignedSourceTag };
