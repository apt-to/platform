#!/bin/bash
set -euo pipefail
ulimit -c 0
trap 'chown -R "$1:$2" /output' EXIT
mkdir -p /build/source /output/source
cp -a /input/. /build/source/
rm -rf /build/source/.git
cp /originals/*.orig.tar.* /build/
cd /build/source
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' > /output/build-toolchain.tsv
python3 /verification/regression.py --source . --phase baseline --output /output/baseline-regression.json
dpkg-source --before-build .
dpkg-source -b .
export DEB_BUILD_OPTIONS='check parallel=1'
dpkg-buildpackage -b -us -uc -j1
cp /build/*.buildinfo /output/
dpkg -i /build/*.deb
python3 /verification/regression.py --source . --phase patched --output /output/patched-regression.json
base="$(python3 -c 'import json; print(json.load(open("debian/getpatched/release-policy.json"))["baseVersion"])')"
version="$(dpkg-parsechangelog -S Version)"
dpkg --compare-versions "$version" gt "$base"
dpkg --compare-versions "$version" lt "$base+getpatched2"
dpkg --compare-versions "$version" lt "$base+esm1"
printf '%s\n' "base < getpatched1 < getpatched2; getpatched1 < vendor esm1: verified" > /output/version-ordering.txt
cp /build/*.dsc /build/*.orig.tar.* /build/*.debian.tar.* /output/source/
python3 - <<'PY'
from pathlib import Path
import hashlib, json, subprocess
files = []
for path in sorted(Path('/build').glob('*.deb')):
    identity = subprocess.check_output(['dpkg-deb','-f',str(path),'Package','Version','Architecture','Depends'],text=True)
    files.append({'name':path.name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'bytes':path.stat().st_size,'control':identity})
if not files: raise RuntimeError('No binary outputs')
Path('/output/binary-manifest.json').write_text(json.dumps({'purpose':'unpublished build verification; binaries not exported','packages':files},indent=2)+'\n')
PY
