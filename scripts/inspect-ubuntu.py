#!/usr/bin/env python3
"""Inspect Ubuntu's public source publications without downloading build data."""

import argparse
import datetime
from email.parser import Parser
import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

API = "https://api.launchpad.net/1.0/"
ALLOWED_PACKAGES = ("libxml2", "libarchive")


def read_bytes(url, limit=4 * 1024 * 1024):
    request = urllib.request.Request(url, headers={"User-Agent": "getpatched.dev-source-preflight/0.1"})
    with urllib.request.urlopen(request, timeout=40) as response:
        if response.status != 200:
            raise RuntimeError(f"Launchpad returned HTTP {response.status}")
        data = response.read(limit + 1)
        if len(data) > limit:
            raise RuntimeError("Source metadata exceeded size limit")
        return data


def read_json(url):
    return json.loads(read_bytes(url))


def source_integrity(package, version, files):
    descriptors = [url for url in files if url.endswith(".dsc")]
    if len(descriptors) != 1:
        raise RuntimeError("Expected exactly one source descriptor")
    url = descriptors[0]
    content = read_bytes(url, 1024 * 1024)
    text = content.decode("utf-8")
    if not text.startswith("-----BEGIN PGP SIGNED MESSAGE-----\n"):
        raise RuntimeError("Expected a clear-signed source descriptor")
    body = text.split("\n\n", 1)[1].split("\n-----BEGIN PGP SIGNATURE-----", 1)[0]
    fields = Parser().parsestr(body)
    if fields["Source"] != package or fields["Version"] != version:
        raise RuntimeError("Source descriptor identity does not match publication")
    archives = []
    urls = {urllib.parse.unquote(urllib.parse.urlparse(u).path.rsplit("/", 1)[-1]): u for u in files}
    for line in fields.get("Checksums-Sha256", "").splitlines():
        if not line.strip():
            continue
        checksum, size, name = line.split()
        if not re.fullmatch(r"[0-9a-f]{64}", checksum) or name not in urls or not size.isdecimal():
            raise RuntimeError("Invalid source archive checksum entry")
        archives.append({"name": name, "url": urls[name], "sha256": checksum, "bytes": int(size)})
    if not archives:
        raise RuntimeError("Source descriptor has no SHA-256 archive checksums")
    return {
        "descriptor": {"url": url, "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)},
        "archives": archives,
        "signature_verified": False,
        "verification_scope": "HTTPS publication and descriptor identity; archives must be checked against these hashes during import",
    }


def publications(package):
    query = urllib.parse.urlencode({
        "ws.op": "getPublishedSources",
        "source_name": package,
        "exact_match": "true",
        "distro_series": API + "ubuntu/focal",
        "status": "Published",
        "order_by_date": "true",
    })
    page = API + "ubuntu/+archive/primary?" + query
    records = []
    visited = set()
    while page:
        if page in visited or not page.startswith(API + "ubuntu/+archive/primary?"):
            raise RuntimeError("Unexpected or repeated Launchpad pagination link")
        visited.add(page)
        result = read_json(page)
        records.extend(result["entries"])
        page = result.get("next_collection_link")
    output = []
    seen = set()
    integrity = {}
    for record in records:
        version = record["source_package_version"]
        pocket = record["pocket"]
        if (version, pocket) in seen:
            continue
        seen.add((version, pocket))
        files = read_json(record["self_link"] + "?ws.op=sourceFileUrls")
        if version not in integrity:
            integrity[version] = source_integrity(package, version, files)
        output.append({
            "package": record["source_package_name"],
            "version": version,
            "pocket": pocket,
            "published_at": record.get("date_published"),
            "publication": record["self_link"],
            "source_files": files,
            "source_integrity": integrity[version],
        })
    if not output:
        raise RuntimeError(f"No published focal sources returned for {package}")
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packages", nargs="*", choices=ALLOWED_PACKAGES)
    parser.add_argument("--output", type=Path, help="Save complete evidence as JSON and print a short summary")
    args = parser.parse_args()
    data = {
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "release": "focal",
        "archive": "ubuntu/primary",
        "source": "Launchpad public API",
        "packages": {},
    }
    for package in args.packages or ALLOWED_PACKAGES:
        data["packages"][package] = publications(package)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(data, indent=2) + "\n")
        for package, records in data["packages"].items():
            print(package + ": " + ", ".join(r["pocket"] + "=" + r["version"] for r in records))
        print("Evidence:", args.output)
    else:
        json.dump(data, sys.stdout, indent=2)
        print()


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, urllib.error.URLError) as error:
        print(f"Source preflight failed: {error}", file=sys.stderr)
        raise SystemExit(1)
