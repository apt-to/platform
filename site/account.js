const message = document.querySelector("#account-message");
const signedOut = document.querySelector("#signed-out");
const signedIn = document.querySelector("#signed-in");
const eligiblePanel = document.querySelector("#eligible-panel");
const notEligiblePanel = document.querySelector("#not-eligible-panel");
const deviceList = document.querySelector("#device-list");
const deviceCount = document.querySelector("#device-count");
const deviceError = document.querySelector("#device-error");
const tokenReveal = document.querySelector("#one-time-token");
const authLine = document.querySelector("#auth-line");
const EARLY_BINARY_LICENSE_ID = "LicenseRef-GetPatched-Early-Binary-1.0";

function setMessage(text, kind = "info") {
  message.textContent = text;
  message.dataset.kind = kind;
  message.hidden = !text;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    cache: "no-store",
    ...options,
    headers: { accept: "application/json", ...(options.body ? { "content-type": "application/json" } : {}), ...options.headers },
  });
  let body = {};
  try { body = await response.json(); } catch { /* Keep the transport error generic. */ }
  if (!response.ok) {
    const error = new Error(body.error || `Request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return body;
}

function formatDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "unknown" : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeZone: "UTC" }).format(date);
}

function showError(error) {
  deviceError.hidden = false;
  deviceError.textContent = error.message || "Device credentials could not be loaded.";
}

function renderDevices(devices) {
  deviceList.replaceChildren();
  const now = Date.now();
  const active = devices.filter((device) => !device.revoked_at && Number.isFinite(Date.parse(device.expires_at)) && Date.parse(device.expires_at) > now).length;
  deviceCount.textContent = `${active} active / ${devices.length} total`;
  if (devices.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty-devices";
    empty.textContent = "No machines have credentials yet. Create one for each Ubuntu host that needs early package access.";
    deviceList.append(empty);
    return;
  }
  for (const device of devices) {
    const row = document.createElement("div");
    row.className = "device-row";
    const name = document.createElement("div");
    name.className = "device-name";
    name.textContent = device.label;
    const meta = document.createElement("span");
    meta.className = "device-meta";
    meta.textContent = `Created ${formatDate(device.created_at)} · Expires ${formatDate(device.expires_at)}`;
    name.append(meta);
    const state = document.createElement("span");
    const expired = !device.revoked_at && !(Number.isFinite(Date.parse(device.expires_at)) && Date.parse(device.expires_at) > now);
    state.className = `device-state${device.revoked_at || expired ? " is-revoked" : ""}`;
    state.textContent = device.revoked_at ? `REVOKED ${formatDate(device.revoked_at)}` : expired ? `EXPIRED ${formatDate(device.expires_at)}` : "ACTIVE";
    row.append(name, state);
    if (!device.revoked_at && !expired) {
      const revoke = document.createElement("button");
      revoke.className = "revoke-button";
      revoke.type = "button";
      revoke.textContent = "Revoke";
      revoke.setAttribute("aria-label", `Revoke credential for ${device.label}`);
      revoke.addEventListener("click", async () => {
        if (!window.confirm(`Revoke the credential for “${device.label}”? That machine will lose sponsor-period access.`)) return;
        revoke.disabled = true;
        try {
          await api(`/api/device-tokens/${device.id}/revoke`, { method: "POST" });
          await loadDevices();
          setMessage(`Credential for ${device.label} was revoked.`, "success");
        } catch (error) {
          revoke.disabled = false;
          showError(error);
        }
      });
      row.append(revoke);
    }
    deviceList.append(row);
  }
}

async function loadDevices() {
  deviceError.hidden = true;
  const result = await api("/api/device-tokens");
  renderDevices(result.devices);
}

function showTokenOnce(token) {
  authLine.textContent = `machine early.getpatched.dev login apt password ${token}`;
  tokenReveal.hidden = false;
}

async function start() {
  let user;
  try {
    user = await api("/api/me");
  } catch (error) {
    signedIn.hidden = true;
    if (error.status === 401) {
      signedOut.hidden = false;
      setMessage("You are signed out. Sign in with GitHub to check sponsor eligibility.");
    } else if (error.status === 503) {
      signedOut.hidden = true;
      setMessage("GitHub sign-in is not configured yet. The public catalogue and package sources remain available.", "error");
    } else {
      signedOut.hidden = true;
      setMessage("Your account status could not be loaded. Try reloading this page.", "error");
    }
    return;
  }

  signedOut.hidden = true;
  signedIn.hidden = false;
  document.querySelector("#github-login").textContent = `@${user.github_login}`;
  eligiblePanel.hidden = false;
  try {
    await loadDevices();
  } catch (error) {
    showError(error);
  }

  if (user.sponsorship === "eligible") {
    notEligiblePanel.hidden = true;
    document.querySelector("#device-form").hidden = false;
    document.querySelector("#sponsor-status").textContent = "An active GitHub Sponsors sponsorship is confirmed. Every tier is eligible, and device credentials are checked against current sponsor status when used.";
    setMessage("Sponsor status verified. Manage credentials for your machines below.", "success");
    return;
  }

  document.querySelector("#device-form").hidden = true;
  tokenReveal.hidden = true;
  notEligiblePanel.hidden = false;
  const statusCopy = document.querySelector("#sponsor-status");
  if (user.sponsorship === "unavailable") {
    statusCopy.textContent = "Sponsor status could not be verified right now.";
    document.querySelector("#eligibility-title").textContent = "Sponsor access is temporarily unavailable";
    document.querySelector("#eligibility-copy").textContent = "The current GitHub Sponsors eligibility snapshot is missing or expired. Try again later; no device access will be granted until status can be verified.";
    document.querySelector("#sponsor-link").hidden = true;
    setMessage("Sponsor eligibility is temporarily unavailable.", "error");
  } else {
    statusCopy.textContent = "No active GitHub Sponsors sponsorship was found for this account.";
    document.querySelector("#eligibility-title").textContent = "Sponsor access is not active";
    document.querySelector("#eligibility-copy").textContent = "Public source and build instructions remain available under MIT for GetPatched-authored material. Any active individual sponsorship qualifies, regardless of tier; one-time sponsorships qualify only while GitHub reports them active.";
    document.querySelector("#sponsor-link").hidden = false;
    setMessage("Signed in. Sponsor access is not active for this account.");
  }
}

document.querySelector("#device-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = document.querySelector("#create-device");
  const label = document.querySelector("#device-label").value.trim();
  button.disabled = true;
  deviceError.hidden = true;
  try {
    const result = await api("/api/device-tokens", { method: "POST", body: JSON.stringify({ label, earlyBinaryLicenseId: EARLY_BINARY_LICENSE_ID }) });
    showTokenOnce(result.token);
    document.querySelector("#device-label").value = "";
    await loadDevices();
    setMessage("Credential created. Copy and store it now; it will not be shown again.", "success");
  } catch (error) {
    showError(error);
    if (error.status === 403 || error.status === 503) setMessage(error.message, "error");
  } finally { button.disabled = false; }
});

document.querySelector("#copy-token").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(authLine.textContent);
    setMessage("APT auth.conf line copied to your clipboard.", "success");
  } catch {
    setMessage("Clipboard access was denied. Select and copy the displayed line manually.", "error");
  }
});

document.querySelector("#dismiss-token").addEventListener("click", () => {
  authLine.textContent = "";
  tokenReveal.hidden = true;
});

document.querySelector("#sign-out").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await api("/api/logout", { method: "POST" });
    window.location.reload();
  } catch (error) {
    setMessage(error.message || "Sign-out failed. Please retry.", "error");
    button.disabled = false;
  }
});

start();
