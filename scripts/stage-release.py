#!/usr/bin/env python3
"""Upload only a hash-matched post-run rebuild to the authenticated release Worker."""
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def token():
    request_url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    separator = "&" if "?" in request_url else "?"
    url = request_url + separator + urllib.parse.urlencode({"audience": "aptto-release-gateway"})
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
    with urllib.request.urlopen(request, timeout=20) as response:
        value = json.load(response)["value"]
    if not isinstance(value, str) or not value:
        raise RuntimeError("GitHub did not issue an OIDC token")
    return value


def call(endpoint, method, body=None, path=None):
    headers = {"Authorization": "Bearer " + token()}
    data = body
    if path is not None:
        data = path.read_bytes()
        headers["Content-Type"] = "application/vnd.debian.binary-package"
        headers["Content-Length"] = str(len(data))
    elif body is not None:
        data = json.dumps(body, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(endpoint, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            return response.status, json.load(response) if "json" in response.headers.get("content-type", "") else None
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"release Worker returned HTTP {error.code}: {error.read(1024).decode(errors='replace')}") from None


def main():
    manifest = json.loads(Path(os.environ["CANDIDATE_MANIFEST"]).read_text())
    config = json.loads((ROOT / "packages.json").read_text())
    package = manifest["source"]
    policy = config["packages"].get(package)
    if not policy or manifest["distribution"] != "focal" or manifest["architecture"] != "amd64":
        raise RuntimeError("candidate is outside the configured focal amd64 pilot")
    if manifest["sourceCommit"] != os.environ.get("SOURCE_COMMIT", manifest["sourceCommit"]):
        raise RuntimeError("candidate source commit does not match the completed build")
    candidates = manifest["packages"]
    if not candidates or {item["package"] for item in candidates} != set(policy["binaryPackages"]):
        raise RuntimeError("candidate binary package set does not match the approved package policy")
    for item in candidates:
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*_[A-Za-z0-9.+:~+-]+_amd64\.deb", item["name"]):
            raise RuntimeError("candidate contains an unsafe or unexpected binary filename")
        if item["architecture"] != "amd64" or item["version"] != manifest["sourceVersion"]:
            raise RuntimeError("candidate binary version or architecture is inconsistent")
        binary = Path(os.environ["BINARY_DIRECTORY"]) / item["name"]
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        if digest != item["sha256"] or binary.stat().st_size != item["bytes"]:
            raise RuntimeError(f"candidate binary failed local manifest verification: {item['name']}")

    endpoint = os.environ["APTTO_RELEASE_ENDPOINT"].rstrip("/")
    source_repo = f"apt-to/packaging-{package}"
    release_id = f"{package}-{manifest['sourceVersion'].lower()}"
    release_id = "-".join(filter(None, re.split(r"[^a-z0-9]+", release_id)))
    assets = [{"name": item["name"], "sha256": item["sha256"]} for item in candidates]
    registration = {
        "id": release_id,
        "repository": source_repo,
        "tag": f"aptto/{manifest['sourceVersion']}",
        "source_commit": manifest["sourceCommit"],
        "sponsor_delay_hours": policy["sponsorDelayHours"],
        "verification_run_id": int(os.environ["VERIFICATION_RUN_ID"]),
        "required_assets": assets,
    }
    status, saved = call(endpoint + "/internal/releases", "POST", body=registration)
    if status not in (200, 201) or not isinstance(saved, dict):
        raise RuntimeError(f"release registration returned unexpected HTTP {status}")
    if saved.get("state") == "prepared":
        for item in candidates:
            path = Path(os.environ["BINARY_DIRECTORY"]) / item["name"]
            status, _ = call(f"{endpoint}/internal/releases/{release_id}/assets/{urllib.parse.quote(item['name'])}", "PUT", path=path)
            if status not in (200, 201):
                raise RuntimeError(f"private R2 staging returned unexpected HTTP {status}")
    elif saved.get("state") not in ("sponsor-period", "public"):
        raise RuntimeError("release Worker returned an unknown state")
    if policy["sponsorDelayHours"] == 168 and saved.get("state") == "prepared":
        status, _ = call(f"{endpoint}/internal/releases/{release_id}/publish-sponsor", "POST", body={})
        if status not in (200, 201):
            raise RuntimeError(f"sponsor publication returned unexpected HTTP {status}")
    print(f"staged {len(candidates)} hash-verified binaries for {package} {manifest['sourceVersion']}")


if __name__ == "__main__":
    main()
