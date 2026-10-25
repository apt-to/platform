#!/usr/bin/env python3
"""Build and privately stage unsigned channel-specific APT indexes."""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MAX_ASSET_BYTES = 64 * 1024 * 1024
PUBLISH_SPEC = importlib.util.spec_from_file_location("aptto_snapshot_publisher", ROOT / "scripts" / "publish-apt-snapshot.py")
PUBLISH = importlib.util.module_from_spec(PUBLISH_SPEC)
PUBLISH_SPEC.loader.exec_module(PUBLISH)
GENERATOR_SPEC = importlib.util.spec_from_file_location("aptto_index_generator", ROOT / "scripts" / "generate-apt-index.py")
GENERATOR = importlib.util.module_from_spec(GENERATOR_SPEC)
GENERATOR_SPEC.loader.exec_module(GENERATOR)


def request_headers():
    return {"Authorization": "Bearer " + PUBLISH.request_token()}


def fetch_inventory(endpoint, channel):
    request = urllib.request.Request(f"{endpoint}/internal/repository-snapshots/{channel}/releases", headers=request_headers())
    with PUBLISH.open_without_redirect(request, timeout=60) as response:
        payload = json.load(response)
    if payload.get("channel") != channel or payload.get("suite") != "focal" or payload.get("architecture") != "amd64":
        raise RuntimeError("release Worker returned an unexpected snapshot inventory identity")
    releases = payload.get("releases")
    if not isinstance(releases, list) or not releases or len(releases) > 32:
        raise RuntimeError("release Worker returned an empty or oversized snapshot inventory")
    return releases


def validate_release(release):
    if (not isinstance(release, dict) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,100}", str(release.get("id", ""))) or
            release.get("state") not in {"public", "sponsor-period"} or
            not re.fullmatch(r"apt-to/packaging-(?:libxml2|libarchive)", str(release.get("repository", ""))) or
            not re.fullmatch(r"aptto/[A-Za-z0-9.+~-]+", str(release.get("tag", ""))) or
            not re.fullmatch(r"[a-f0-9]{40}", str(release.get("source_commit", "")))):
        raise ValueError("release inventory contains an invalid pilot package record")
    for field in ("required_assets", "source_assets"):
        assets = release.get(field)
        if not isinstance(assets, list) or not assets:
            raise ValueError(f"release inventory has no {field}")
        names = set()
        for asset in assets:
            if (not isinstance(asset, dict) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+~-]*", str(asset.get("name", ""))) or
                    not re.fullmatch(r"[a-f0-9]{64}", str(asset.get("sha256", ""))) or asset["name"] in names):
                raise ValueError(f"release inventory has an invalid {field} entry")
            names.add(asset["name"])
    if not any(asset["name"].endswith(".deb") for asset in release["required_assets"]):
        raise ValueError("release inventory has no binary package")
    if not any(asset["name"].endswith(".dsc") for asset in release["source_assets"]):
        raise ValueError("release inventory has no Debian source descriptor")


def public_asset_url(endpoint, release, asset):
    source = release["repository"].split("/", 1)[1].removeprefix("packaging-")
    path = f"/pool/main/{source[0]}/{source}/{asset['name']}"
    request = urllib.request.Request(endpoint + path, method="GET")
    try:
        PUBLISH.open_without_redirect(request, timeout=60)
    except urllib.error.HTTPError as error:
        if error.code not in (301, 302, 303, 307, 308):
            raise RuntimeError(f"public pool asset lookup returned HTTP {error.code}") from None
        destination = error.headers.get("Location", "")
    else:
        raise RuntimeError("public pool asset lookup did not redirect to an immutable GitHub Release asset")
    parsed = urllib.parse.urlsplit(destination)
    owner, repository = release["repository"].split("/")
    prefix = f"/{owner}/{repository}/releases/download/"
    if parsed.scheme != "https" or parsed.hostname != "github.com" or not parsed.path.startswith(prefix) or parsed.username or parsed.password or parsed.fragment:
        raise RuntimeError("public pool route returned a URL outside the expected GitHub repository release")
    return destination


def download_asset(endpoint, channel, release, asset, target, *, private_binary=False):
    if private_binary:
        url = (f"{endpoint}/internal/repository-snapshots/{channel}/releases/"+
               f"{urllib.parse.quote(release['id'], safe='')}/assets/{urllib.parse.quote(asset['name'], safe='')}")
        request = urllib.request.Request(url, headers=request_headers())
    else:
        url = public_asset_url(endpoint, release, asset)
        request = urllib.request.Request(url)
    total = 0
    digest = hashlib.sha256()
    with PUBLISH.open_without_redirect(request, timeout=180) as response, target.open("xb") as output:
        declared = response.headers.get("Content-Length")
        if declared is not None and (not declared.isdigit() or int(declared) > MAX_ASSET_BYTES):
            raise ValueError("package asset exceeds the 64 MiB limit")
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ASSET_BYTES:
                raise ValueError("package asset exceeds the 64 MiB limit")
            digest.update(chunk)
            output.write(chunk)
    if not total or digest.hexdigest() != asset["sha256"]:
        target.unlink(missing_ok=True)
        raise ValueError(f"downloaded package asset did not match its release SHA-256: {asset['name']}")


def index_manifest(repository):
    dist = repository / "dists/focal"
    files = []
    for path in sorted(dist.rglob("*")):
        if path.is_symlink():
            raise ValueError("generated repository metadata contains a symbolic link")
        if not path.is_file():
            continue
        relative = path.relative_to(repository).as_posix()
        data = path.read_bytes()
        files.append({"path": relative, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    return files


def register_unsigned_build(endpoint, channel, snapshot_id, release_ids, repository):
    files = index_manifest(repository)
    if any(path in {"dists/focal/InRelease", "dists/focal/Release.gpg"} for path in (item["path"] for item in files)):
        raise ValueError("unsigned snapshot unexpectedly contains signature files")
    base = f"{endpoint}/internal/repository-snapshot-builds/{channel}"
    status, _ = PUBLISH.call(base, "POST", body={"id": snapshot_id, "release_ids": release_ids, "files": files})
    if status not in (200, 201):
        raise RuntimeError(f"snapshot build registration returned unexpected HTTP {status}")
    for item in files:
        path = urllib.parse.quote(item["path"], safe="/")
        status, _ = PUBLISH.call(f"{base}/{snapshot_id}/files/{path}", "PUT", body=(repository / item["path"]).read_bytes(), content_type="application/octet-stream")
        if status not in (200, 201):
            raise RuntimeError(f"snapshot build upload returned unexpected HTTP {status}: {item['path']}")
    return len(files)


def assemble_channel(endpoint, channel, work_root):
    releases = fetch_inventory(endpoint, channel)
    if channel == "public":
        releases = [release for release in releases if release["state"] == "public"]
    elif channel == "early":
        releases = [release for release in releases if release["state"] in {"public", "sponsor-period"}]
    if not releases:
        raise RuntimeError(f"no currently eligible releases for {channel} channel")
    for release in releases:
        validate_release(release)
    repository = work_root / channel
    repository.mkdir(parents=True, exist_ok=False)
    release_ids = []
    for release in releases:
        source = release["repository"].split("/", 1)[1].removeprefix("packaging-")
        pool = repository / "pool" / "main" / source[0] / source
        pool.mkdir(parents=True, exist_ok=True)
        for asset in release["required_assets"]:
            if not asset["name"].endswith(".deb"):
                continue
            download_asset(endpoint, channel, release, asset, pool / asset["name"],
                           private_binary=(channel == "early" and release["state"] == "sponsor-period"))
        for asset in release["source_assets"]:
            download_asset(endpoint, channel, release, asset, pool / asset["name"])
        release_ids.append(release["id"])
    result = GENERATOR.generate(repository, "focal", "amd64", "main", "AptTo maintained packages")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not re.fullmatch(r"[0-9]{1,20}", run_id):
        raise RuntimeError("GitHub Actions run identity is required for immutable snapshot ids")
    snapshot_id = "focal-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S") + "-r" + run_id + "-" + channel
    count = register_unsigned_build(endpoint, channel, snapshot_id, release_ids, repository)
    return {"channel": channel, "snapshot_build": snapshot_id, "release_count": len(release_ids), "index_count": len(result["indexes"]), "file_count": count}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default=os.environ.get("APTTO_RELEASE_ENDPOINT", "https://repo.apt.to"))
    parser.add_argument("--channel", choices=("public", "early", "both"), default="both")
    args = parser.parse_args()
    PUBLISH.validate_identity()
    endpoint = args.endpoint.rstrip("/")
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != "https" or parsed.hostname != "repo.apt.to" or parsed.path or parsed.query or parsed.fragment:
        raise SystemExit("snapshot endpoint must be the configured HTTPS repo.apt.to gateway")
    with tempfile.TemporaryDirectory(prefix="aptto-repository-build-") as temporary:
        root = Path(temporary)
        channels = ("public", "early") if args.channel == "both" else (args.channel,)
        results = []
        for channel in channels:
            results.append(assemble_channel(endpoint, channel, root))
        for result in results:
            print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
