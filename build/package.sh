#!/bin/bash
set -euo pipefail
ulimit -c 0
trap 'chown -R "$1:$2" /output' EXIT
mkdir -p /build /output/source
descriptors=(/originals/*.dsc)
if [[ ${#descriptors[@]} -ne 1 || ! -f "${descriptors[0]}" ]]; then
  echo "Expected exactly one pinned Debian source descriptor" >&2
  exit 1
fi
cd /originals
dpkg-source -x "${descriptors[0]}" /build/source
cp /originals/*.orig.tar.* /build/
cd /build/source
target="$(python3 -c 'import json; print(json.load(open("/package-policy.json"))["targetId"])')"
python3 /materialize-package.py --recipe /recipe --source /build/source --target "$target" \
  --policy /package-policy.json --provenance /source-provenance.json \
  --source-provenance /output/source-provenance.json
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' > /output/build-toolchain.tsv
python3 /verification/regression.py --recipe /recipe --policy /output/package-policy.json --phase baseline --output /output/baseline-regression.json
dpkg-source --before-build .
dpkg-source -b .
export DEB_BUILD_OPTIONS='check parallel=1'
dpkg-buildpackage -b -us -uc -j1
cp /build/*.buildinfo /output/
dpkg -i /build/*.deb
python3 /verification/regression.py --recipe /recipe --policy /output/package-policy.json --phase patched --output /output/patched-regression.json
base="$(python3 -c 'import json; print(json.load(open("/output/package-policy.json"))["baseVersion"])')"
expected="$(python3 -c 'import json; print(json.load(open("/output/package-policy.json"))["version"])')"
serial="$(python3 -c 'import json; print(json.load(open("/output/package-policy.json"))["releaseSerial"])')"
version="$(dpkg-parsechangelog -S Version)"
dpkg --compare-versions "$version" eq "$expected"
dpkg --compare-versions "$version" gt "$base"
next_version="$base+getpatched$((serial + 1))"
dpkg --compare-versions "$version" lt "$next_version"
printf '%s\n' "base < configured GetPatched release < next same-base release; ordering against vendor ESM remains unresolved" > /output/version-ordering.txt
cp /build/*.dsc /build/*.orig.tar.* /build/*.debian.tar.* /output/source/
python3 - <<'PY'
from pathlib import Path
import hashlib, json, subprocess
policy=json.loads(Path('/output/package-policy.json').read_text())
files = []
for path in sorted(Path('/build').glob('*.deb')):
    identity = subprocess.check_output(['dpkg-deb','-f',str(path),'Package','Version','Architecture','Depends'],text=True)
    files.append({'name':path.name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'bytes':path.stat().st_size,'control':identity})
if not files: raise RuntimeError('No binary outputs')
manifest={
    'schemaVersion': 2,
    'purpose': 'unpublished build verification; binaries not exported',
    'source': policy['source'],
    'targetId': policy['targetId'],
    'sourceVersion': policy['baseVersion'],
    'version': policy['version'],
    'architecture': policy['architecture'],
    'packages': files,
}
Path('/output/binary-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
PY
