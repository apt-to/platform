import assert from "node:assert/strict";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

class Element {
  constructor() {
    this.hidden = false;
    this.dataset = {};
    this.listeners = new Map();
    this.children = [];
    this.textContent = "";
    this.value = "";
  }

  addEventListener(type, listener) { this.listeners.set(type, listener); }
  setAttribute() {}
  replaceChildren(...children) { this.children = children; }
  append(...children) { this.children.push(...children); }
}

function makeDocument() {
  const elements = new Map();
  for (const selector of [
    "#signed-out", "#signed-in", "#eligible-panel", "#not-eligible-panel",
    "#device-error", "#one-time-token",
  ]) {
    const element = new Element();
    element.hidden = true;
    elements.set(selector, element);
  }
  elements.set("#account-message", Object.assign(new Element(), { textContent: "Checking your sign-in…" }));
  return {
    createElement: () => new Element(),
    querySelector(selector) {
      if (!elements.has(selector)) elements.set(selector, new Element());
      return elements.get(selector);
    },
    elements,
  };
}

async function boot(fetchImpl, isSettled) {
  const document = makeDocument();
  const previous = {
    document: globalThis.document,
    fetch: globalThis.fetch,
    window: globalThis.window,
  };
  globalThis.document = document;
  globalThis.fetch = fetchImpl;
  globalThis.window = { confirm: () => true, location: { reload() {} } };
  const moduleUrl = pathToFileURL(resolve("site/account.js"));
  moduleUrl.searchParams.set("test", String(Math.random()));
  try {
    await import(moduleUrl.href);
    for (let attempt = 0; attempt < 50; attempt += 1) {
      if (isSettled(document)) break;
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 0));
    }
    assert.ok(isSettled(document), "account UI reached the expected settled state");
  } finally {
    globalThis.document = previous.document;
    globalThis.fetch = previous.fetch;
    globalThis.window = previous.window;
  }
  return document;
}

test("device-list failure does not erase an authenticated account state", async () => {
  const authenticatedWithDeviceError = await boot(async (path) => {
    if (path === "/api/me") {
      return Response.json({ github_login: "alice", sponsorship: "eligible" });
    }
    return Response.json({ error: "device service unavailable" }, { status: 503 });
  }, (document) => !document.querySelector("#device-error").hidden);
  assert.equal(authenticatedWithDeviceError.querySelector("#signed-in").hidden, false);
  assert.equal(authenticatedWithDeviceError.querySelector("#signed-out").hidden, true);
  assert.equal(authenticatedWithDeviceError.querySelector("#device-error").hidden, false);
  assert.equal(authenticatedWithDeviceError.querySelector("#github-login").textContent, "@alice");
});
