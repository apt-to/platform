#!/usr/bin/env python3
"""Verify and atomically publish a signed focal APT snapshot to the Worker."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request

MAX_FILES = 256
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
REQUIRED = {
    "dists/focal/Release", "dists/focal/InRelease", "dists/focal/Release.gpg",
    "dists/focal/main/binary-amd64/Packages", "dists/focal/main/binary-amd64/Packages.gz", "dists/focal/main/binary-amd64/Packages.xz",
    "dists/focal/main/source/Sources", "dists/focal/main/source/Sources.gz", "dists/focal/main/source/Sources.xz",
    "aptto-archive-keyring.gpg",
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def open_without_redirect(request, timeout):
    return urllib.request.build_opener(NoRedirect()).open(request, timeout=timeout)


def validate_identity():
    required = ("ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    event = os.environ.get("GITHUB_EVENT_NAME")
    if os.environ.get("GITHUB_ACTIONS") != "true" or event not in {"workflow_run", "schedule", "workflow_dispatch"} or any(not os.environ.get(name) for name in required):
        raise RuntimeError("GitHub Actions OIDC is not available to this job")
    if os.environ.get("GITHUB_REPOSITORY") != "apt-to/platform" or os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise RuntimeError("snapshot publication is restricted to apt-to/platform on main")
    workflow = os.environ.get("GITHUB_WORKFLOW_REF", "")
    allowed_workflows = {
        "workflow_run": "apt-to/platform/.github/workflows/repository-snapshot.yml@refs/heads/main",
        "schedule": "apt-to/platform/.github/workflows/repository-snapshot.yml@refs/heads/main",
        "workflow_dispatch": "apt-to/platform/.github/workflows/repository-snapshot.yml@refs/heads/main",
    }
    if workflow != allowed_workflows[event]:
        raise RuntimeError("snapshot publication is restricted to a protected AptTo workflow")
    token_host = urllib.parse.urlsplit(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"])
    if token_host.scheme != "https" or not token_host.hostname or not token_host.hostname.endswith(".actions.githubusercontent.com"):
        raise RuntimeError("GitHub OIDC request URL is not on the GitHub Actions token service")


def snapshot_files(repository):
    repository = Path(repository).resolve(strict=True)
    paths = []
    for candidate in (repository / "dists/focal").rglob("*"):
        if candidate.is_symlink():
            raise ValueError(f"snapshot contains a symbolic link: {candidate}")
        if candidate.is_file():
            paths.append((candidate.relative_to(repository).as_posix(), candidate))
    keyring = repository / "aptto-archive-keyring.gpg"
    if keyring.is_symlink() or not keyring.is_file():
        raise ValueError("snapshot is missing a regular public archive key")
    paths.append((keyring.relative_to(repository).as_posix(), keyring))
    if not REQUIRED.issubset({path for path, _ in paths}) or len(paths) > MAX_FILES:
        raise ValueError("snapshot is missing required focal indexes/signatures or has too many files")
    total = 0
    manifest = []
    for relative, path in sorted(paths):
        if not re.fullmatch(r"dists/focal/(?:[A-Za-z0-9][A-Za-z0-9._+~-]*/)*[A-Za-z0-9][A-Za-z0-9._+~-]*|aptto-archive-keyring\.gpg", relative):
            raise ValueError(f"snapshot contains an unsafe path: {relative}")
        size = path.stat().st_size
        if size <= 0 or size > MAX_FILE_BYTES:
            raise ValueError(f"snapshot file size is outside the allowed range: {relative}")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("snapshot exceeds the 128 MiB total size limit")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest.append({"path": relative, "size": size, "sha256": digest})
    return repository, manifest


def verify_release_indexes(repository):
    repository = Path(repository)
    dist = repository / "dists/focal"
    release = (dist / "Release").read_bytes()
    entries = {}
    in_sha256 = False
    for line in release.decode("utf-8").splitlines():
        if line == "SHA256:":
            in_sha256 = True
            continue
        if in_sha256 and line and not line[0].isspace():
            break
        if not in_sha256 or not line.strip():
            continue
        digest, size_text, relative = line.split()
        if not re.fullmatch(r"[a-f0-9]{64}", digest) or relative in entries:
            raise ValueError("Release contains an invalid or duplicate SHA256 entry")
        size = int(size_text)
        target = (dist / relative).resolve()
        if not target.is_relative_to(dist.resolve()) or not target.is_file():
            raise ValueError(f"Release references a missing or unsafe index: {relative}")
        data = target.read_bytes()
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f"Release SHA256 does not match its index: {relative}")
        entries[relative] = digest
    if not entries:
        raise ValueError("Release metadata has no SHA256 index entries")
    return release


def verify_release(repository, expected_fingerprint):
    if not isinstance(expected_fingerprint, str) or not re.fullmatch(r"(?:[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})", expected_fingerprint):
        raise ValueError("a configured 40- or 64-character archive primary-key fingerprint is required")
    expected_fingerprint = expected_fingerprint.upper()
    repository = Path(repository)
    dist = repository / "dists/focal"
    release = verify_release_indexes(repository)

    with tempfile.TemporaryDirectory(prefix="aptto-snapshot-verify-") as temporary:
        home = Path(temporary) / "gnupg"
        home.mkdir(mode=0o700)
        env = {**os.environ, "GNUPGHOME": str(home)}
        keyring = repository / "aptto-archive-keyring.gpg"
        imported = subprocess.run(["gpg", "--batch", "--no-autostart", "--import", str(keyring)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if imported.returncode != 0:
            detail = imported.stderr.decode("utf-8", errors="replace")[:1000]
            raise ValueError(f"published archive key could not be imported by GnuPG: {detail}")
        listed = subprocess.run(["gpg", "--batch", "--no-autostart", "--with-colons", "--fingerprint", "--list-keys"], check=True, env=env, capture_output=True, text=True).stdout
        fingerprints = set()
        primary_fingerprints = set()
        awaiting_primary_fingerprint = False
        for line in listed.splitlines():
            if line.startswith("pub:"):
                awaiting_primary_fingerprint = True
            elif line.startswith("sub:"):
                awaiting_primary_fingerprint = False
            elif line.startswith("fpr:"):
                fingerprint = line.split(":")[9].upper()
                fingerprints.add(fingerprint)
                if awaiting_primary_fingerprint:
                    primary_fingerprints.add(fingerprint)
                    awaiting_primary_fingerprint = False
        if expected_fingerprint not in primary_fingerprints:
            raise ValueError("published archive key does not match the configured primary-key fingerprint")
        inrelease = subprocess.run(["gpg", "--batch", "--no-autostart", "--status-fd", "2", "--decrypt", str(dist / "InRelease")], check=True, env=env, capture_output=True)
        detached = subprocess.run(["gpg", "--batch", "--no-autostart", "--status-fd", "2", "--verify", str(dist / "Release.gpg"), str(dist / "Release")], check=True, env=env, capture_output=True)
        if inrelease.stdout != release:
            raise ValueError("InRelease signed payload differs from Release")
        for result in (inrelease, detached):
            status = result.stderr.decode("utf-8", errors="replace")
            valid_signatures = re.findall(r"\[GNUPG:\] VALIDSIG ([A-F0-9]{40,64})(?: [^\n]*)?", status)
            signer_fingerprints = [signature.upper() for signature in valid_signatures]
            primary_signers = re.findall(r"\[GNUPG:\] VALIDSIG [A-F0-9]{40,64} (?:[^\n]* )?([A-F0-9]{40,64})$", status, re.MULTILINE)
            trusted_signatures = [signer for signer in signer_fingerprints if signer in fingerprints]
            trusted_signatures.extend(fingerprint.upper() for fingerprint in primary_signers if fingerprint.upper() == expected_fingerprint)
            if len(valid_signatures) != 1 or not trusted_signatures:
                raise ValueError("APT Release signature is not valid under the published archive key")


def request_token():
    url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    separator = "&" if "?" in url else "?"
    url += separator + urllib.parse.urlencode({"audience": "aptto-release-gateway"})
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
    with open_without_redirect(request, timeout=20) as response:
        token = json.load(response).get("value")
    if not isinstance(token, str) or not token:
        raise RuntimeError("GitHub did not issue an OIDC token")
    return token


def call(endpoint, method, *, body=None, content_type="application/json"):
    headers = {"Authorization": "Bearer " + request_token()}
    data = body
    if isinstance(body, dict):
        data = json.dumps(body, separators=(",", ":")).encode()
    if data is not None:
        headers["Content-Type"] = content_type
        headers["Content-Length"] = str(len(data))
    request = urllib.request.Request(endpoint, data=data, headers=headers, method=method)
    try:
        with open_without_redirect(request, timeout=300) as response:
            return response.status, json.load(response) if "json" in response.headers.get("content-type", "") else None
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"repository Worker returned HTTP {error.code}") from None


def publish(endpoint, channel, snapshot_id, release_ids, repository, expected_fingerprint):
    if channel not in {"public", "early"} or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{2,79}", snapshot_id):
        raise ValueError("invalid repository channel or snapshot id")
    endpoint_url = urllib.parse.urlsplit(endpoint)
    if endpoint_url.scheme != "https" or endpoint_url.hostname != "repo.apt.to" or endpoint_url.path not in ("", "/") or endpoint_url.username or endpoint_url.password or endpoint_url.query or endpoint_url.fragment:
        raise ValueError("snapshot publication endpoint must be the configured HTTPS repo.apt.to gateway")
    if not release_ids or len(set(release_ids)) != len(release_ids) or any(not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,100}", item) for item in release_ids):
        raise ValueError("at least one valid release id is required")
    repository, files = snapshot_files(repository)
    verify_release(repository, expected_fingerprint)
    base = endpoint.rstrip("/") + "/internal/repository-snapshots/" + channel
    manifest = {"id": snapshot_id, "release_ids": release_ids, "files": files}
    status, _ = call(base, "POST", body=manifest)
    if status not in (200, 201):
        raise RuntimeError(f"snapshot registration returned unexpected HTTP {status}")
    for item in files:
        encoded = urllib.parse.quote(item["path"], safe="/")
        status, _ = call(f"{base}/{snapshot_id}/files/{encoded}", "PUT", body=(repository / item["path"]).read_bytes(), content_type="application/octet-stream")
        if status not in (200, 201):
            raise RuntimeError(f"snapshot upload returned unexpected HTTP {status}: {item['path']}")
    status, _ = call(f"{base}/{snapshot_id}/activate", "POST", body={})
    if status not in (200, 201):
        raise RuntimeError(f"snapshot activation returned unexpected HTTP {status}")
    return len(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default=os.environ.get("APTTO_RELEASE_ENDPOINT", "https://repo.apt.to"))
    parser.add_argument("--channel", required=True, choices=("public", "early"))
    parser.add_argument("--snapshot-id", required=True)
    parser.add_argument("--release-id", required=True, action="append")
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--expected-fingerprint", required=True, help="trusted archive primary-key fingerprint (40 or 64 hex characters)")
    args = parser.parse_args()
    validate_identity()
    count = publish(args.endpoint, args.channel, args.snapshot_id, args.release_id, args.repository, args.expected_fingerprint)
    print(f"activated {args.channel} focal snapshot {args.snapshot_id} with {count} verified files")


if __name__ == "__main__":
    main()
