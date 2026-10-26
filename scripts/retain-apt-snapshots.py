#!/usr/bin/env python3
"""Run the protected, bounded retention policy for immutable APT snapshots."""
import argparse
import importlib.util
import os
from pathlib import Path
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("aptto_snapshot_publisher", ROOT / "scripts" / "publish-apt-snapshot.py")
PUBLISH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLISH)


def retain(endpoint, channels):
    if not isinstance(channels, (list, tuple)) or not channels or len(channels) > 2 or len(set(channels)) != len(channels) or any(channel not in {"public", "early"} for channel in channels):
        raise ValueError("retention channels must be unique public and/or early values")
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != "https" or parsed.hostname != "repo.getpatched.dev" or parsed.path not in ("", "/") or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("snapshot retention endpoint must be the configured HTTPS repo.getpatched.dev gateway")
    status, result = PUBLISH.call(endpoint.rstrip("/") + "/internal/repository-snapshots/retention", "POST", body={"channels": list(channels)})
    results = result.get("channels") if isinstance(result, dict) else None
    if status != 200 or not isinstance(results, dict) or set(results) != set(channels):
        raise RuntimeError("Worker did not confirm retention for every requested channel")
    for channel in channels:
        counts = results[channel]
        count_names = ("retained_snapshots", "deleted_snapshots", "pending_snapshots", "retained_builds",
                       "deleted_builds", "pending_builds", "deleted_objects")
        if (not isinstance(counts, dict) or any(type(counts.get(name)) is not int or counts[name] < 0 for name in count_names)):
            raise RuntimeError(f"Worker returned invalid retention counts for {channel}")
        if counts["retained_snapshots"] > 6 or counts["retained_builds"] > 1:
            raise RuntimeError(f"Worker returned counts beyond the bounded retention policy for {channel}")
    if result.get("rollback_snapshots_kept_per_channel") != 5:
        raise RuntimeError("Worker returned an unexpected rollback retention policy")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default=os.environ.get("APTTO_RELEASE_ENDPOINT", "https://repo.getpatched.dev"))
    parser.add_argument("--channel", choices=("public", "early", "both"), default="both")
    args = parser.parse_args()
    PUBLISH.validate_identity()
    channels = ["public", "early"] if args.channel == "both" else [args.channel]
    result = retain(args.endpoint, channels)
    for channel in channels:
        counts = result["channels"][channel]
        print(f"{channel}: kept {counts['retained_snapshots']} snapshots and {counts['retained_builds']} recent build; removed {counts['deleted_snapshots']} snapshots and {counts['deleted_builds']} stale builds; pending {counts['pending_snapshots']} snapshots and {counts['pending_builds']} builds")


if __name__ == "__main__":
    main()
