import assert from "node:assert/strict";
import test from "node:test";
import { bootAccountUi } from "./account_ui_harness.mjs";

test("device-list failure does not erase an authenticated account state", async () => {
  const authenticatedWithDeviceError = await bootAccountUi(async (path) => {
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
