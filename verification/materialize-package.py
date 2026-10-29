#!/usr/bin/env python3
"""Apply a validated target recipe to an extracted Debian source package."""
import argparse
from email.utils import parsedate_to_datetime
import json
import os
from pathlib import Path
import re
import shutil


def read_json(path):
    return json.loads(Path(path).read_text())


def copy_identical(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if destination.read_bytes() != source.read_bytes():
            raise RuntimeError(f"Recipe file would overwrite different Ubuntu source content: {destination}")
        return
    shutil.copyfile(source, destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipe", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--provenance", required=True, type=Path)
    parser.add_argument("--source-provenance", required=True, type=Path)
    args = parser.parse_args()

    recipe = args.recipe.resolve()
    source_root = args.source.resolve()
    manifest = read_json(recipe / "package-manifest.json")
    targets = [item for item in manifest["targets"] if item.get("id") == args.target]
    if len(targets) != 1:
        raise RuntimeError("Build target is missing or duplicated in package recipe")
    target_ref = targets[0]
    if manifest.get("schemaVersion") == 3:
        target_candidate = recipe / target_ref["file"]
        target_path = target_candidate.resolve()
        if (target_candidate.is_symlink() or not target_path.is_file()
                or os.path.commonpath((str(target_path), str(recipe)) ) != str(recipe)):
            raise RuntimeError("Target recipe file is missing, linked, or escapes the package checkout")
        target = read_json(target_path)
        if target.get("schemaVersion") != 2 or target.get("id") != args.target:
            raise RuntimeError("Target recipe file schema or identity is invalid")
    else:
        target = target_ref
    package = manifest["package"]["source"]
    base_version = target["source"]["version"]
    package_version = target["packageVersion"]
    changelog_path = source_root / "debian/changelog"
    changelog = changelog_path.read_text()
    current_entry = re.match(r"^([^\s]+) \(([^)]+)\) ([^;]+); urgency=([^\n]+)\n", changelog)
    if not current_entry or current_entry.group(1) != package or current_entry.group(2) != base_version:
        raise RuntimeError("Extracted source changelog does not match the recipe's pinned source package")
    if (source_root / "debian/source/format").read_text().strip() != "3.0 (quilt)":
        raise RuntimeError("Extracted Ubuntu source package is not in 3.0 (quilt) format")

    metadata = read_json(recipe / manifest["patchMetadata"])
    patch_by_id = {item["id"]: item for item in metadata["patches"]}
    selected_patch_ids = target["patches"] + target.get("buildPatches", [])
    patch_dir = source_root / "debian/patches"
    patch_dir.mkdir(parents=True, exist_ok=True)
    series_path = patch_dir / "series"
    existing_series = series_path.read_text() if series_path.exists() else ""
    series_entries = [line.split("#", 1)[0].strip().split()[0]
                      for line in existing_series.splitlines()
                      if line.split("#", 1)[0].strip()]
    appended = []
    for patch_id in selected_patch_ids:
        item = patch_by_id[patch_id]
        patch_name = item["file"]
        if Path(patch_name).name != patch_name or "\n" in patch_name or "\t" in patch_name:
            raise RuntimeError("Patch file name is not safe for a quilt series")
        copy_identical(recipe / "patches" / patch_name, patch_dir / patch_name)
        if patch_name not in series_entries:
            appended.append(patch_name)

    if appended:
        separator = "" if not existing_series or existing_series.endswith("\n") else "\n"
        series_path.write_text(existing_series + separator + "\n".join(appended) + "\n")
    fixture_root = recipe / manifest["regressionTests"]["fixturesDirectory"]
    for item in metadata["patches"]:
        if item["id"] not in selected_patch_ids:
            continue
        for reference in item.get("referenceFiles", []):
            relative = Path(reference["path"])
            if relative.is_absolute() or ".." in relative.parts:
                raise RuntimeError("Reference file path escapes the recipe")
            reference_source = recipe / relative
            if (not reference_source.is_file()
                    or os.path.commonpath((str(reference_source.resolve()), str(recipe))) != str(recipe)):
                raise RuntimeError("Declared reference file is missing or escapes the recipe")
            copy_identical(
                reference_source,
                source_root / "debian/tests/fixtures" / relative.relative_to(fixture_root.relative_to(recipe)),
            )
        for test in item["tests"]:
            for fixture in test.get("fixtures", []):
                relative = Path(fixture["path"])
                if relative.is_absolute() or ".." in relative.parts:
                    raise RuntimeError("Regression fixture path escapes the recipe")
                fixture_source = recipe / relative
                if (not fixture_source.is_file()
                        or os.path.commonpath((str(fixture_source.resolve()), str(recipe))) != str(recipe)):
                    raise RuntimeError("Declared regression fixture is missing or escapes the recipe")
                copy_identical(
                    fixture_source,
                    source_root / "debian/tests/fixtures" / relative.relative_to(fixture_root.relative_to(recipe)),
                )

    policy = read_json(args.policy)
    provenance = read_json(args.provenance)
    if (policy.get("source") != package or policy.get("baseVersion") != base_version
            or policy.get("version") != package_version
            or policy.get("patches") != target["patches"]
            or policy.get("releaseSerial") != target["releaseSerial"]
            or policy.get("targetId") != target["id"]
            or policy.get("buildPatches", []) != target.get("buildPatches", [])):
        raise RuntimeError("Derived policy does not match the recipe target")

    getpatched = source_root / "debian/getpatched"
    getpatched.mkdir(parents=True, exist_ok=True)
    (getpatched / "release-policy.json").write_text(json.dumps(policy, indent=2) + "\n")
    (getpatched / "source-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    shutil.copyfile(recipe / "package-manifest.json", getpatched / "package-manifest.json")
    shutil.copyfile(recipe / manifest["patchMetadata"], getpatched / "patches.json")
    shutil.copyfile(recipe / "README.md", getpatched / "README.md")

    patch_lines = []
    for patch_id in target["patches"]:
        item = patch_by_id[patch_id]
        patch_lines.append(f"  * Backport {', '.join(item['cves'])}: {item['title']}.")
    for patch_id in target.get("buildPatches", []):
        item = patch_by_id[patch_id]
        patch_lines.append(f"  * Apply test-only build compatibility patch: {item['title']}.")
    patch_summary = "\n".join(patch_lines)
    changelog_data = target["changelog"]
    parsed_date = parsedate_to_datetime(changelog_data["date"])
    if parsed_date is None:
        raise RuntimeError("Recipe changelog date is invalid")
    entry = (
        f"{package} ({package_version}) {changelog_data['distribution']}; urgency={changelog_data['urgency']}\n\n"
        f"{patch_summary}\n"
        "  * Build from the SHA-256-pinned public Ubuntu source package using the GetPatched recipe.\n\n"
        f" -- {changelog_data['maintainer']}  {changelog_data['date']}\n\n"
    )
    changelog_path.write_text(entry + changelog)

    args.source_provenance.parent.mkdir(parents=True, exist_ok=True)
    args.source_provenance.write_text(json.dumps(provenance, indent=2) + "\n")
    print(f"{package}: materialized target {target['id']} with patches {', '.join(selected_patch_ids)}")


if __name__ == "__main__":
    main()
