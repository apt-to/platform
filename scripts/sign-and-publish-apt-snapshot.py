#!/usr/bin/env python3
"""Verify unsigned index snapshots, sign metadata, and activate the APT channels."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 64 * 1024 * 1024
PUBLISH_SPEC = importlib.util.spec_from_file_location("aptto_snapshot_publisher", ROOT / "scripts" / "publish-apt-snapshot.py")
PUBLISH = importlib.util.module_from_spec(PUBLISH_SPEC)
PUBLISH_SPEC.loader.exec_module(PUBLISH)
GENERATOR_SPEC = importlib.util.spec_from_file_location("aptto_index_generator", ROOT / "scripts" / "generate-apt-index.py")
GENERATOR = importlib.util.module_from_spec(GENERATOR_SPEC)
GENERATOR_SPEC.loader.exec_module(GENERATOR)


def request_json(url):
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + PUBLISH.request_token()})
    with PUBLISH.open_without_redirect(request, timeout=60) as response:
        return json.load(response)


def read_build(endpoint, channel, snapshot_id, repository):
    base = f"{endpoint}/internal/repository-snapshot-builds/{channel}/{snapshot_id}"
    manifest = request_json(base)
    if (manifest.get("id") != snapshot_id or manifest.get("channel") != channel or manifest.get("suite") != "focal" or
            manifest.get("architecture") != "amd64" or not isinstance(manifest.get("release_ids"), list) or
            not manifest["release_ids"] or len(set(manifest["release_ids"])) != len(manifest["release_ids"])):
        raise RuntimeError("snapshot builder returned an invalid manifest identity")
    files = manifest.get("files")
    if not isinstance(files, list) or not files or len(files) > 256:
        raise RuntimeError("snapshot builder returned an empty or oversized file list")
    seen = set()
    for item in files:
        path = item.get("path", "") if isinstance(item, dict) else ""
        if (not re.fullmatch(r"dists/focal/(?:[A-Za-z0-9][A-Za-z0-9._+~-]*/)*[A-Za-z0-9][A-Za-z0-9._+~-]*", path) or
                path in {"dists/focal/InRelease", "dists/focal/Release.gpg"} or path in seen or
                not isinstance(item.get("size"), int) or item["size"] <= 0 or item["size"] > MAX_FILE_BYTES or
                not re.fullmatch(r"[a-f0-9]{64}", str(item.get("sha256", "")))):
            raise RuntimeError("snapshot builder returned an invalid metadata file entry")
        seen.add(path)
        target = repository / path
        target.parent.mkdir(parents=True, exist_ok=True)
        request = urllib.request.Request(f"{base}/files/{urllib.parse.quote(path, safe='/')}", headers={"Authorization": "Bearer " + PUBLISH.request_token()})
        digest = hashlib.sha256()
        total = 0
        with PUBLISH.open_without_redirect(request, timeout=120) as response, target.open("xb") as output:
            declared = response.headers.get("Content-Length")
            if declared is not None and (not declared.isdigit() or int(declared) != item["size"]):
                raise RuntimeError("snapshot metadata length differs from its private manifest")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > item["size"]:
                    raise RuntimeError("snapshot metadata exceeded its private manifest size")
                digest.update(chunk)
                output.write(chunk)
        if total != item["size"] or digest.hexdigest() != item["sha256"]:
            raise RuntimeError(f"snapshot metadata failed private manifest verification: {path}")
    return manifest


def sign_and_publish_channel(endpoint, channel, snapshot_id, key_home, fingerprint, root):
    repository = root / channel
    repository.mkdir(mode=0o700)
    manifest = read_build(endpoint, channel, snapshot_id, repository)
    PUBLISH.verify_release_indexes(repository)
    GENERATOR.sign_release(repository / "dists/focal", key_home, fingerprint)
    PUBLISH.verify_release(repository, fingerprint)
    count = PUBLISH.publish(endpoint, channel, snapshot_id, manifest["release_ids"], repository, fingerprint)
    return {"snapshot": snapshot_id, "channel": channel, "release_count": len(manifest["release_ids"]), "published_file_count": count}


def validate_snapshot_ids(value):
    if not isinstance(value, dict) or not value or not set(value).issubset({"public", "early"}):
        raise ValueError("snapshot IDs must contain at least one valid channel")
    pattern = r"focal-[0-9]{8}T[0-9]{6}-r[0-9]{1,20}-(public|early)"
    for channel, snapshot_id in value.items():
        match = re.fullmatch(pattern, snapshot_id) if isinstance(snapshot_id, str) else None
        if not match or match.group(1) != channel:
            raise ValueError("snapshot ID does not match its builder channel")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default=os.environ.get("APTTO_RELEASE_ENDPOINT", "https://repo.apt.to"))
    parser.add_argument("--channel", choices=("public", "early", "both"), default="both")
    parser.add_argument("--signing-fingerprint", default=os.environ.get("APTTO_SIGNING_FINGERPRINT"))
    args = parser.parse_args()
    PUBLISH.validate_identity()
    if not args.signing_fingerprint:
        raise SystemExit("APTTO_SIGNING_FINGERPRINT is required")
    endpoint = args.endpoint.rstrip("/")
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != "https" or parsed.hostname != "repo.apt.to" or parsed.path or parsed.query or parsed.fragment:
        raise SystemExit("snapshot endpoint must be the configured HTTPS repo.apt.to gateway")
    try:
        snapshot_ids = json.loads(os.environ.get("APTTO_SNAPSHOT_IDS", ""))
    except json.JSONDecodeError as error:
        raise SystemExit("APTTO_SNAPSHOT_IDS must contain the builder's JSON channel-to-ID output") from error
    try:
        snapshot_ids = validate_snapshot_ids(snapshot_ids)
    except ValueError as error:
        raise SystemExit("APTTO_SNAPSHOT_IDS must contain exact public and early builder IDs") from error
    key_data = os.environ.get("APTTO_SIGNING_KEY_ARMORED", "")
    if not key_data:
        raise SystemExit("APTTO_SIGNING_KEY_ARMORED secret is required")
    with tempfile.TemporaryDirectory(prefix="aptto-snapshot-signing-") as temporary:
        root = Path(temporary)
        key_home = root / "gnupg"
        key_home.mkdir(mode=0o700)
        subprocess.run(["gpg", "--batch", "--homedir", str(key_home), "--import"], input=key_data.encode(), check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        channels = ("public", "early") if args.channel == "both" else (args.channel,)
        results = []
        for channel in channels:
            if channel not in snapshot_ids:
                continue
            snapshot_id = snapshot_ids[channel]
            results.append(sign_and_publish_channel(endpoint, channel, snapshot_id, key_home, args.signing_fingerprint, root))
        for result in results:
            print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
