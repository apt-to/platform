#!/usr/bin/env python3
"""Reactivate a retained immutable GetPatched focal repository snapshot."""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import urllib.parse


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("getpatched_snapshot_publisher", ROOT / "scripts" / "publish-apt-snapshot.py")
PUBLISH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLISH)
SNAPSHOT_ID = re.compile(r"focal-[0-9]{8}T[0-9]{6}-r[0-9]{1,20}-(public|early)\Z")


def rollback(endpoint, channel, snapshot_id):
    if channel not in {"public", "early"}:
        raise ValueError("channel must be public or early")
    match = SNAPSHOT_ID.fullmatch(snapshot_id) if isinstance(snapshot_id, str) else None
    if not match or match.group(1) != channel:
        raise ValueError("snapshot ID must be a retained focal snapshot for the selected channel")
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != "https" or parsed.hostname != "repo.getpatched.dev" or parsed.path not in ("", "/") or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("snapshot rollback endpoint must be the configured HTTPS repo.getpatched.dev gateway")
    url = endpoint.rstrip("/") + f"/internal/repository-snapshots/{channel}/{snapshot_id}/activate"
    status, result = PUBLISH.call(url, "POST", body={})
    if (status not in (200, 201) or not isinstance(result, dict) or result.get("id") != snapshot_id or
            result.get("channel") != channel or result.get("active") is not True):
        raise RuntimeError("Worker did not confirm activation of the requested retained snapshot")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default=os.environ.get("GETPATCHED_RELEASE_ENDPOINT", "https://repo.getpatched.dev"))
    parser.add_argument("--channel", default=os.environ.get("GETPATCHED_ROLLBACK_CHANNEL"))
    parser.add_argument("--snapshot-id", default=os.environ.get("GETPATCHED_ROLLBACK_SNAPSHOT_ID"))
    args = parser.parse_args()
    PUBLISH.validate_identity()
    result = rollback(args.endpoint, args.channel, args.snapshot_id)
    print(f"reactivated retained {result['channel']} snapshot {result['id']}")


if __name__ == "__main__":
    main()
