#!/usr/bin/env python3
"""Verify the deployed release Worker can write, read and clean up one R2 object."""
import json
import os
import urllib.error
import urllib.parse
import urllib.request

ENDPOINT = "https://repo.getpatched.dev/internal/r2-self-test"
WORKFLOW_REF = "getpatched/platform/.github/workflows/r2-storage-self-test.yml@refs/heads/main"
AUDIENCE = "getpatched-release-gateway"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def validate_identity():
    required = ("ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    token_url = urllib.parse.urlsplit(os.environ.get(required[0], ""))
    if (os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch" or
            any(not os.environ.get(name) for name in required)):
        raise RuntimeError("GitHub Actions OIDC is not available to this job")
    if os.environ.get("GITHUB_REPOSITORY") != "getpatched/platform" or os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise RuntimeError("R2 self-test is restricted to getpatched/platform on main")
    if os.environ.get("GITHUB_WORKFLOW_REF") != WORKFLOW_REF:
        raise RuntimeError("R2 self-test is restricted to its protected workflow")
    if token_url.scheme != "https" or not token_url.hostname or not token_url.hostname.endswith(".actions.githubusercontent.com"):
        raise RuntimeError("GitHub OIDC request URL is not on the GitHub Actions token service")


def request_token():
    url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    separator = "&" if "?" in url else "?"
    request = urllib.request.Request(
        url + separator + urllib.parse.urlencode({"audience": AUDIENCE}),
        headers={"Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]},
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=20) as response:
            token = json.load(response).get("value")
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        raise RuntimeError("GitHub OIDC token request failed") from None
    if not isinstance(token, str) or not token:
        raise RuntimeError("GitHub did not issue an OIDC token")
    return token


def verify_remote_binding():
    validate_identity()
    request = urllib.request.Request(ENDPOINT, data=b"", method="POST", headers={"Authorization": "Bearer " + request_token()})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
            if response.status != 200:
                raise RuntimeError(f"R2 self-test endpoint returned HTTP {response.status}")
            report = json.load(response)
    except urllib.error.HTTPError as error:
        message = f"R2 self-test endpoint returned HTTP {error.code}"
        try:
            report = json.load(error)
            if isinstance(report, dict) and isinstance(report.get("error"), str):
                detail = " ".join(report["error"].split())[:160]
                message += f": {detail}"
            if error.code == 502 and isinstance(report, dict):
                if report.get("cleaned") is False and isinstance(report.get("object_key"), str) and report["object_key"].startswith("diagnostics/r2-self-test/"):
                    message += f"; cleanup required for {report['object_key']}"
                elif isinstance(report.get("stage"), str):
                    message += f" at stage {report['stage']}"
        except (OSError, json.JSONDecodeError):
            pass
        finally:
            error.close()
        raise RuntimeError(message) from None
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        raise RuntimeError("R2 self-test endpoint request failed") from None
    if (report.get("ok") is not True or report.get("operation") != "write-read-delete" or report.get("cleaned") is not True or
            not isinstance(report.get("bytes"), int) or report["bytes"] <= 0 or
            not isinstance(report.get("sha256"), str) or len(report["sha256"]) != 64 or
            any(character not in "0123456789abcdef" for character in report["sha256"]) or
            not isinstance(report.get("run_id"), int) or report["run_id"] <= 0):
        raise RuntimeError("R2 self-test returned an incomplete or unsuccessful report")
    return report


if __name__ == "__main__":
    result = verify_remote_binding()
    print(f"R2 binding verified: write/read/delete passed; bytes={result['bytes']}; sha256={result['sha256']}; run={result['run_id']}")
