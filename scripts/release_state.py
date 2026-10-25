"""Pure release transition rules; storage and provider effects belong in adapters."""
from datetime import datetime, timedelta, timezone
import re


SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("publication time must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _asset_set(assets, field_name: str) -> dict[str, str]:
    if not isinstance(assets, list) or not assets:
        raise ValueError(f"{field_name} must be a non-empty asset list")
    result = {}
    for asset in assets:
        if not isinstance(asset, dict):
            raise ValueError(f"{field_name} entries must be objects")
        name, digest = asset.get("name"), asset.get("sha256")
        if not isinstance(name, str) or not name or not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise ValueError(f"{field_name} entries require a name and lowercase SHA-256")
        if name in result:
            raise ValueError(f"{field_name} contains duplicate asset names")
        result[name] = digest
    return result


def _parse_utc(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("public_after must be an ISO-8601 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("public_after must be an ISO-8601 UTC timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("public_after must be timezone-aware")
    return parsed


def is_public_due(public_after: datetime, now: datetime) -> bool:
    """Return whether a gated release has reached its UTC publication time."""
    if public_after.tzinfo is None or public_after.utcoffset() is None:
        raise ValueError("public_after must be timezone-aware")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    return now.astimezone(timezone.utc) >= public_after.astimezone(timezone.utc)


def mark_sponsor_published(release: dict, verified_assets: list, published_at: datetime) -> dict:
    """Start the sponsor clock only after every required asset hash is read back."""
    published_time = _utc_iso(published_at)
    state = release.get("state")
    if state == "sponsor-period":
        verified = _asset_set(verified_assets, "verified assets")
        if release.get("verified_assets") != [
            {"name": name, "sha256": digest} for name, digest in sorted(verified.items())
        ]:
            raise ValueError("published release asset set is immutable")
        return dict(release)
    if state != "prepared":
        raise ValueError("only a prepared release can enter the sponsor period")
    if release.get("release_checks_passed") is not True or release.get("sponsor_publication_complete") is not True:
        raise ValueError("release publication is not complete and verified")

    expected = _asset_set(release.get("required_assets"), "required_assets")
    verified = _asset_set(verified_assets, "verified assets")
    if expected != verified:
        raise ValueError("sponsor publication requires the complete asset set with matching read-back hashes")

    delay_hours = release.get("sponsor_delay_hours")
    if type(delay_hours) is not int or delay_hours != 168:
        raise ValueError("sponsor_delay_hours must be exactly 168 integer hours")
    public_after = published_at.astimezone(timezone.utc) + timedelta(hours=delay_hours)

    updated = dict(release)
    updated.update({
        "state": "sponsor-period",
        "sponsor_published_at": published_time,
        "public_after": _utc_iso(public_after),
        "verified_assets": [{"name": name, "sha256": digest} for name, digest in sorted(verified.items())],
    })
    return updated


def mark_public_published(release: dict, verified_assets: list, published_at: datetime) -> dict:
    """Publish a zero-delay release only after checks and public asset read-back."""
    published_time = _utc_iso(published_at)
    state = release.get("state")
    if state == "public":
        verified = _asset_set(verified_assets, "verified assets")
        if release.get("verified_assets") != [
            {"name": name, "sha256": digest} for name, digest in sorted(verified.items())
        ]:
            raise ValueError("published release asset set is immutable")
        return dict(release)
    if state != "prepared":
        raise ValueError("only a prepared release can be published directly")
    if type(release.get("sponsor_delay_hours")) is not int or release["sponsor_delay_hours"] != 0:
        raise ValueError("direct public publication requires a zero-hour integer policy")
    if release.get("release_checks_passed") is not True or release.get("public_publication_complete") is not True:
        raise ValueError("release publication is not complete and verified")

    expected = _asset_set(release.get("required_assets"), "required_assets")
    verified = _asset_set(verified_assets, "verified assets")
    if expected != verified:
        raise ValueError("public publication requires the complete asset set with matching read-back hashes")

    updated = dict(release)
    updated.update({
        "state": "public",
        "public_published_at": published_time,
        "verified_assets": [{"name": name, "sha256": digest} for name, digest in sorted(verified.items())],
    })
    return updated


def mark_public_promoted(
    release: dict,
    verified_assets: list,
    promoted_at: datetime,
    *,
    public_publication_complete: bool,
) -> dict:
    """Promote a gated release only at its deadline with identical public bytes."""
    published_time = _utc_iso(promoted_at)
    state = release.get("state")
    assets = _asset_set(verified_assets, "verified public assets")
    if state == "public":
        if release.get("verified_assets") != [
            {"name": name, "sha256": digest} for name, digest in sorted(assets.items())
        ]:
            raise ValueError("published release asset set is immutable")
        return dict(release)
    if state != "sponsor-period":
        raise ValueError("only a sponsor-period release can be promoted")
    if public_publication_complete is not True:
        raise ValueError("public release publication is not complete and verified")

    deadline = _parse_utc(release.get("public_after"))
    if not is_public_due(deadline, promoted_at):
        raise ValueError("promotion is not allowed before the 168-hour deadline")

    sponsor_assets = _asset_set(release.get("verified_assets"), "sponsor verified assets")
    if sponsor_assets != assets:
        raise ValueError("public promotion must preserve sponsor-period asset hashes")

    updated = dict(release)
    updated.update({"state": "public", "public_published_at": published_time})
    return updated
