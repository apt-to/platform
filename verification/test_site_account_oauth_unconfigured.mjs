import assert from "node:assert/strict";
import test from "node:test";
import { bootAccountUi } from "./account_ui_harness.mjs";

test("unconfigured sponsor sign-in is shown as unavailable rather than signed out", async () => {
  const unavailable = await bootAccountUi(async () => Response.json(
    { error: "GitHub sign-in is not configured" },
    { status: 503 },
  ), (document) => document.querySelector("#account-message").dataset.kind === "error");

  assert.equal(unavailable.querySelector("#signed-out").hidden, true);
  assert.equal(unavailable.querySelector("#signed-in").hidden, true);
  assert.match(unavailable.querySelector("#account-message").textContent, /not configured yet/i);
  assert.match(unavailable.querySelector("#account-message").textContent, /public catalogue and package sources/i);
});
