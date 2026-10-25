const STATE_PREFIX = "release-state/";
const MAX_RETRIES = 5;
const MAX_RELEASE_ASSET_BYTES = 64 * 1024 * 1024;
const MAX_REGISTRATION_BYTES = 64 * 1024;
const MAX_SPONSOR_WEBHOOK_BYTES = 256 * 1024;
const SPONSOR_ENTITLEMENTS_KEY = "sponsor-entitlements/current.json";
const SPONSOR_SNAPSHOT_MAX_AGE_MS = 30 * 60 * 1000;
const OIDC_ISSUER = "https://token.actions.githubusercontent.com";
const OIDC_AUDIENCE = "aptto-release-gateway";
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
    if (claims.iss !== OIDC_ISSUER || audiences.length !== 1 || audiences[0] !== OIDC_AUDIENCE || !Number.isSafeInteger(claims.exp) || claims.exp <= now ||
        !Number.isSafeInteger(claims.iat) || claims.iat > now + 60 || claims.repository !== "apt-to/platform" || claims.repository_id !== "1433070541" ||
        claims.repository_owner !== "apt-to" || claims.repository_visibility !== "public" || claims.event_name !== "workflow_run" ||
        claims.ref !== "refs/heads/main" || claims.workflow_ref !== "apt-to/platform/.github/workflows/private-staging.yml@refs/heads/main" ||
        claims.runner_environment !== "github-hosted" || !/^\d+$/.test(String(claims.run_id || "")) || !Number.isSafeInteger(claims.run_attempt) ||
        (claims.nbf !== undefined && (!Number.isSafeInteger(claims.nbf) || claims.nbf > now + 60)) || typeof claims.jti !== "string" || !claims.jti) return null;
    return { type: "github-actions", run_id: Number(claims.run_id), run_attempt: claims.run_attempt };
  } catch { return null; }
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
  return `aptto-source/${record.tag.slice("aptto/".length)}`;
}

function checksumBuffer(hex) {
  return Uint8Array.from(hex.match(/.{2}/g), (pair) => Number.parseInt(pair, 16)).buffer;
}

function checksumHex(value) {
  if (!value) return null;
  return [...new Uint8Array(value)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
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

async function acceptSponsorWebhook(request, env) {
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
    if (payload.action !== "cancelled" || !Number.isSafeInteger(payload.sponsorship?.sponsor?.id)) {
      return json({ error: "unsupported or incomplete sponsorship event" }, 422);
    }
    const key = `sponsor-deliveries/${delivery}.json`;
    const result = await env.RELEASES.put(key, JSON.stringify({
      delivery_id: delivery,
      action: "cancelled",
      sponsor_id: payload.sponsorship.sponsor.id,
      received_at: new Date().toISOString(),
      effect: "reconciliation-required",
    }), { onlyIf: { etagDoesNotMatch: "*" }, httpMetadata: { contentType: "application/json" } });
    if (!result) return json({ accepted: true, duplicate: true, reconciliation_required: true }, 200);
    return json({ accepted: true, reconciliation_required: true }, 202);
  } catch (error) {
    return json({ error: String(error.message || error) }, error.status || 400);
  }
}

function configuredSponsorTiers(value) {
  const tiers = typeof value === "string" ? value.split(",").map((tier) => tier.trim()).filter(Boolean) : [];
  if (tiers.length === 0 || tiers.some((tier) => tier.length > 200)) {
    throw new Error("SPONSOR_ALLOWED_TIER_IDS must list the approved GitHub Sponsors tier IDs");
  }
  return new Set(tiers);
}

async function fetchSponsorSnapshot(env, now) {
  if (!env.SPONSOR_GRAPHQL_TOKEN) throw new Error("GitHub Sponsors reconciliation token is not configured");
  const allowedTiers = configuredSponsorTiers(env.SPONSOR_ALLOWED_TIER_IDS);
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
        query: `query AptToSponsorReconciliation($after: String) {
          organization(login: "apt-to") {
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
                tier { id name isOneTime }
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
    if (organization?.login?.toLowerCase() !== "apt-to" || organization.hasSponsorsListing !== true) {
      throw new Error("apt-to GitHub Sponsors listing is unavailable");
    }
    const connection = organization.sponsorshipsAsMaintainer;
    if (!connection || !Array.isArray(connection.nodes) || !connection.pageInfo) throw new Error("GitHub Sponsors response is incomplete");
    for (const sponsorship of connection.nodes) {
      const sponsor = sponsorship?.sponsorEntity;
      const tier = sponsorship?.tier;
      // Organization sponsors do not grant access to every member. Device entitlements
      // are mapped only to the individual user's immutable GitHub database ID.
      if (sponsorship.isActive === true && sponsor?.__typename === "User" && Number.isSafeInteger(sponsor.databaseId) &&
          tier && allowedTiers.has(tier.id)) {
        const current = sponsors.get(sponsor.databaseId);
        const tierIds = new Set(current?.tier_ids || []);
        tierIds.add(tier.id);
        sponsors.set(sponsor.databaseId, {
          github_user_id: sponsor.databaseId,
          github_login: sponsor.login,
          tier_ids: [...tierIds].sort(),
          has_one_time_sponsorship: current?.has_one_time_sponsorship === true || sponsorship.isOneTimePayment === true,
        });
      }
    }
    after = connection.pageInfo.hasNextPage ? connection.pageInfo.endCursor : null;
    if (connection.pageInfo.hasNextPage && (typeof after !== "string" || !after)) throw new Error("GitHub Sponsors pagination cursor is missing");
  } while (after);
  return {
    organization: "apt-to",
    tier_ids: [...allowedTiers].sort(),
    sponsors: [...sponsors.values()].sort((a, b) => a.github_user_id - b.github_user_id),
    reconciled_at: now.toISOString(),
    valid_until: new Date(now.getTime() + SPONSOR_SNAPSHOT_MAX_AGE_MS).toISOString(),
    authority: "github-sponsors-graphql-active-only",
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
  if (snapshot.organization !== "apt-to" || snapshot.authority !== "github-sponsors-graphql-active-only" ||
      !Number.isFinite(Date.parse(snapshot.valid_until)) || now.getTime() > Date.parse(snapshot.valid_until)) return null;
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
    headers: { location: redirect.toString(), "cache-control": "no-store", "set-cookie": setCookie("aptto_oauth_state", state, "/auth/github/callback", 600) },
  });
}

async function consumeOauthState(request, env, returnedState) {
  const cookieState = cookieValue(request, "aptto_oauth_state");
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
      headers.append("set-cookie", clearCookie("aptto_oauth_state", "/auth/github/callback"));
      headers.append("set-cookie", setCookie("aptto_session", session, "/", 7 * 24 * 60 * 60));
      return headers;
    })(),
  });
}

async function sessionUser(request, env) {
  const session = cookieValue(request, "aptto_session");
  if (!session) return null;
  const key = `apt-sessions/${await sha256Hex(new TextEncoder().encode(session))}.json`;
  const loaded = await readRecord(env.RELEASES, key);
  if (!loaded || loaded.record.revoked_at || Date.now() > Date.parse(loaded.record.expires_at)) return null;
  return loaded.record;
}

async function accountStatus(request, env) {
  const user = await sessionUser(request, env);
  if (!user) return json({ error: "sign-in required" }, 401);
  const snapshot = await readFreshSponsorSnapshot(env.RELEASES);
  const eligible = snapshot?.sponsors.some((sponsor) => sponsor.github_user_id === user.github_user_id) === true;
  return json({
    github_login: user.github_login,
    sponsorship: snapshot ? (eligible ? "eligible" : "not-eligible") : "unavailable",
    snapshot_valid_until: snapshot?.valid_until || null,
  });
}

async function logout(request, env) {
  assertSameOrigin(request, env);
  const session = cookieValue(request, "aptto_session");
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
  return new Response(null, { status: 204, headers: { "cache-control": "no-store", "set-cookie": clearCookie("aptto_session", "/") } });
}

async function issueDeviceToken(request, env) {
  assertSameOrigin(request, env);
  const user = await sessionUser(request, env);
  if (!user) return json({ error: "sign-in required" }, 401);
  const snapshot = await readFreshSponsorSnapshot(env.RELEASES);
  if (!snapshot) return json({ error: "sponsor status is temporarily unavailable" }, 503);
  if (!snapshot.sponsors.some((sponsor) => sponsor.github_user_id === user.github_user_id)) return json({ error: "active eligible sponsorship required" }, 403);
  let body;
  try { body = await readBoundedJson(request, 4096); }
  catch (error) { return json({ error: String(error.message || error) }, error.status || 400); }
  const label = typeof body.label === "string" ? body.label.trim() : "APT device";
  if (!label || label.length > 80) return json({ error: "device label must be 1 to 80 characters" }, 400);
  const token = `aptto_${randomToken()}`;
  const tokenHash = await sha256Hex(new TextEncoder().encode(token));
  const now = new Date();
  const record = {
    github_user_id: user.github_user_id,
    created_at: now.toISOString(),
    expires_at: new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000).toISOString(),
    device_label: label,
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
  if (!/^aptto_[a-f0-9]{64}$/.test(token)) return null;
  const tokenHash = await sha256Hex(new TextEncoder().encode(token));
  const loaded = await readRecord(env.RELEASES, `apt-device-tokens/${tokenHash}.json`);
  if (!loaded || loaded.record.revoked_at || !Number.isSafeInteger(loaded.record.github_user_id) || now.getTime() > Date.parse(loaded.record.expires_at)) return null;
  const snapshot = await readFreshSponsorSnapshot(env.RELEASES, now);
  if (!snapshot?.sponsors.some((sponsor) => sponsor.github_user_id === loaded.record.github_user_id)) return null;
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

async function serveEarlyAsset(request, env, id, name, now = new Date()) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._+~-]*$/.test(name)) return json({ error: "invalid asset name" }, 400);
  let key;
  try { key = stateKey(id); } catch { return json({ error: "invalid release id" }, 400); }
  const loaded = await readRecord(env.RELEASES, key);
  const release = loaded?.record;
  if (!release) {
    return json({ error: "sponsor release is unavailable" }, 404);
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
    headers: { "www-authenticate": 'Basic realm="apt.to early repository"', "cache-control": "private, no-store", vary: "Authorization" },
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

async function beginSponsorPublication(request, env, id, now = new Date()) {
  const identity = await githubActionsIdentity(request, env);
  if (!identity) {
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
  if (!identity || identity.type !== "github-actions") return json({ error: "GitHub Actions identity required" }, 401);
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
  if (!identity || identity.type !== "github-actions") return json({ error: "GitHub Actions identity required" }, 401);
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
  if (!["apt-to/packaging-libxml2", "apt-to/packaging-libarchive"].includes(record.repository)) throw new Error("repository is not an approved pilot package");
  if (typeof record.tag !== "string" || !/^aptto\/[A-Za-z0-9.+~-]+$/.test(record.tag)) throw new Error("invalid immutable release tag");
  if (!Number.isInteger(record.sponsor_delay_hours) || ![0, 168].includes(record.sponsor_delay_hours)) throw new Error("policy must be 0 or 168 hours");
  const expectedDelay = record.repository === "apt-to/packaging-libxml2" ? 168 : 0;
  if (record.sponsor_delay_hours !== expectedDelay) throw new Error("release policy does not match the approved pilot package");
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
  const identity = await githubActionsIdentity(request, env);
  if (!identity) {
    return json({ error: "unauthorized" }, 401);
  }
  const body = await readBoundedJson(request, MAX_REGISTRATION_BYTES);
  const record = {
    id: body.id,
    state: "prepared",
    repository: body.repository,
    tag: body.tag,
    source_commit: body.source_commit,
    sponsor_delay_hours: body.sponsor_delay_hours,
    release_checks_passed: false,
    required_assets: releaseAssets(body.required_assets, body.id),
    source_assets: releaseAssets(body.source_assets, body.id).map((asset) => ({ ...asset, r2_key: `staging/${body.id}/source/${asset.sha256}` })),
    created_at: new Date().toISOString(),
    ...(identity.type === "github-actions" ? { staging_run_id: identity.run_id } : {}),
  };
  assertRelease(record);
  const verifiedRun = await verifyPackageRun(env, record.repository, record.source_commit, record.tag, body.verification_run_id);
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
  if (!identity) {
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
      body: JSON.stringify({ tag_name: tagName, target_commitish: record.source_commit, name: `Debian source ${record.tag.slice("aptto/".length)}`, draft: true, prerelease: false, generate_release_notes: false }),
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
    if (request.method === "GET" && url.pathname === "/account") {
      if (!env.ASSETS) return new Response("account page is not configured", { status: 503 });
      return env.ASSETS.fetch(new Request(new URL("/account.html", request.url), request));
    }
    if (request.method === "GET" && url.pathname === "/api/me") {
      try { return await accountStatus(request, env); }
      catch (error) { return json({ error: String(error.message || error) }, error.status || 500); }
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
    if (request.method === "POST" && url.pathname === "/webhooks/github/sponsorship") {
      return acceptSponsorWebhook(request, env);
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
    if (url.pathname.startsWith("/api/")) return json({ error: "not found" }, 404);
    if (env.ASSETS) return env.ASSETS.fetch(request);
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

export { beginSponsorPublication, canonicalAssets, fetchSponsorSnapshot, githubActionsIdentity, parseUtc, publishImmediateRelease, publishOne, publishPublicSources, readFreshSponsorSnapshot, reconcile, reconcileSponsors, releaseAssets, requireImmutableReleasesEnabled, updateState, verifyGithubSignature, verifyPackageRun, verifySignedSourceTag };
