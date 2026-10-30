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
import sys
sys.path.insert(0, str(ROOT / "scripts"))
from platform_policy import package_target_policy, target_profile


def validate_endpoint(value):
    endpoint = value.rstrip("/")
    parsed = urllib.parse.urlsplit(endpoint)
    if (parsed.scheme != "https" or parsed.hostname != "repo.getpatched.dev" or parsed.port not in (None, 443) or
            parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment):
        raise ValueError("release endpoint must be the configured HTTPS repo.getpatched.dev gateway")
    return endpoint


def token():
    request_url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    separator = "&" if "?" in request_url else "?"
    url = request_url + separator + urllib.parse.urlencode({"audience": "getpatched-release-gateway"})
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
    target_id = manifest.get("targetId")
    try:
        profile = target_profile(config, target_id)
        policy = package_target_policy(config, package, target_id)
    except (KeyError, ValueError) as error:
        raise RuntimeError(f"candidate target is not configured: {error}") from error
    if (not profile["repository"]["enabled"]
            or manifest["distribution"] != profile["codename"]
            or manifest["architecture"] != profile["architecture"]):
        raise RuntimeError("candidate target is configured for builds but not enabled for repository publication")
    if manifest["sourceCommit"] != os.environ.get("SOURCE_COMMIT", manifest["sourceCommit"]):
        raise RuntimeError("candidate source commit does not match the completed build")
    candidates = manifest["packages"]
    source_candidates = manifest.get("sourceFiles", [])
    if not source_candidates or not any(item["name"].endswith(".dsc") for item in source_candidates):
        raise RuntimeError("candidate manifest must include the complete Debian source package")
    if not candidates or {item["package"] for item in candidates} != set(policy["binaryPackages"]):
        raise RuntimeError("candidate binary package set does not match the approved package policy")
    for item in candidates:
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*_[A-Za-z0-9.+:~+-]+_" + re.escape(profile["architecture"]) + r"\.deb", item["name"]):
            raise RuntimeError("candidate contains an unsafe or unexpected binary filename")
        if item["architecture"] != profile["architecture"] or item["version"] != manifest["sourceVersion"]:
            raise RuntimeError("candidate binary version or architecture is inconsistent")
        binary = Path(os.environ["BINARY_DIRECTORY"]) / item["name"]
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        if digest != item["sha256"] or binary.stat().st_size != item["bytes"]:
            raise RuntimeError(f"candidate binary failed local manifest verification: {item['name']}")
    source_directory = Path(os.environ.get("SOURCE_DIRECTORY", Path(os.environ["CANDIDATE_MANIFEST"]).parent / "source"))
    for item in source_candidates:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+~-]*", item["name"]):
            raise RuntimeError("candidate contains an unsafe source filename")
        source_file = source_directory / item["name"]
        digest = hashlib.sha256(source_file.read_bytes()).hexdigest()
        if digest != item["sha256"] or source_file.stat().st_size != item["bytes"]:
            raise RuntimeError(f"candidate source file failed local manifest verification: {item['name']}")

    endpoint = validate_endpoint(os.environ["GETPATCHED_RELEASE_ENDPOINT"])
    source_repo = f"getpatched/packaging-{package}"
    release_id = f"{package}-{target_id}-{manifest['sourceVersion'].lower()}"
    release_id = "-".join(filter(None, re.split(r"[^a-z0-9]+", release_id)))
    assets = [{"name": item["name"], "sha256": item["sha256"]} for item in candidates]
    registration = {
        "id": release_id,
        "repository": source_repo,
        "tag": f"getpatched/{target_id}/{manifest['sourceVersion']}",
        "target_id": target_id,
        "source_commit": manifest["sourceCommit"],
        "sponsor_delay_hours": policy["releaseAccess"]["sponsorDelayHours"],
        "early_binary_license_id": policy["releaseAccess"]["earlyBinaryLicenseId"],
        "public_contribution_spdx": policy["releaseAccess"]["publicContributionSpdx"],
        "verification_run_id": int(os.environ["VERIFICATION_RUN_ID"]),
        "required_assets": assets,
        "source_assets": [{"name": item["name"], "sha256": item["sha256"]} for item in source_candidates],
    }
    status, saved = call(endpoint + "/internal/releases", "POST", body=registration)
    if status not in (200, 201) or not isinstance(saved, dict):
        raise RuntimeError(f"release registration returned unexpected HTTP {status}")
    publication_state = saved.get("state")
    if saved.get("state") == "prepared":
        for item in candidates:
            path = Path(os.environ["BINARY_DIRECTORY"]) / item["name"]
            status, _ = call(f"{endpoint}/internal/releases/{release_id}/assets/{urllib.parse.quote(item['name'])}", "PUT", path=path)
            if status not in (200, 201):
                raise RuntimeError(f"private R2 staging returned unexpected HTTP {status}")
        for item in source_candidates:
            path = source_directory / item["name"]
            status, _ = call(f"{endpoint}/internal/releases/{release_id}/source-assets/{urllib.parse.quote(item['name'])}", "PUT", path=path)
            if status not in (200, 201):
                raise RuntimeError(f"public source R2 staging returned unexpected HTTP {status}")
    elif saved.get("state") not in ("sponsor-period", "public"):
        raise RuntimeError("release Worker returned an unknown state")
    status, source_publication = call(f"{endpoint}/internal/releases/{release_id}/publish-sources", "POST", body={})
    if status != 200 or not isinstance(source_publication, dict) or not source_publication.get("source_release_tag"):
        raise RuntimeError(f"public source release returned unexpected HTTP {status}")
    if policy["releaseAccess"]["sponsorDelayHours"] == 168 and saved.get("state") == "prepared":
        status, publication = call(f"{endpoint}/internal/releases/{release_id}/publish-sponsor", "POST", body={})
        if status not in (200, 201):
            raise RuntimeError(f"sponsor publication returned unexpected HTTP {status}")
        publication_state = publication.get("state")
    elif policy["releaseAccess"]["sponsorDelayHours"] == 0 and saved.get("state") == "prepared":
        status, published = call(f"{endpoint}/internal/releases/{release_id}/publish-now", "POST", body={})
        if status != 200 or not isinstance(published, dict) or published.get("state") != "public":
            raise RuntimeError(f"immediate public release returned unexpected HTTP {status}")
        publication_state = published["state"]
    print(f"{package} {manifest['sourceVersion']}: {publication_state}; {len(candidates)} hash-verified binaries and {len(source_candidates)} source files")


if __name__ == "__main__":
    main()
