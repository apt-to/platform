import assert from "node:assert/strict";
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
  };
}

export async function bootAccountUi(fetchImpl, isSettled) {
  const document = makeDocument();
  const previous = {
    document: globalThis.document,
    fetch: globalThis.fetch,
    window: globalThis.window,
  };
  globalThis.document = document;
  globalThis.fetch = fetchImpl;
  globalThis.window = { confirm: () => true, location: { reload() {} } };
  try {
    await import(pathToFileURL(resolve("site/account.js")).href);
    const deadline = Date.now() + 1000;
    while (!isSettled(document) && Date.now() < deadline) {
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 5));
    }
    assert.ok(isSettled(document), "account UI reached the expected settled state");
  } finally {
    globalThis.document = previous.document;
    globalThis.fetch = previous.fetch;
    globalThis.window = previous.window;
  }
  return document;
}
