"""Debian package-version comparison shared by recipe and scan validation."""


def debian_version_parts(value):
    if not isinstance(value, str) or not value or len(value) > 256 or any(ch.isspace() for ch in value):
        raise ValueError("invalid Debian package version")
    epoch = "0"
    version = value
    if ":" in version:
        epoch, version = version.split(":", 1)
        if not epoch.isdigit():
            raise ValueError("invalid Debian version epoch")
    if "-" in version:
        upstream, revision = version.rsplit("-", 1)
    else:
        upstream, revision = version, "0"
    if not upstream or not revision:
        raise ValueError("invalid Debian version components")
    return int(epoch), upstream, revision


def verrevcmp(left, right):
    i = j = 0

    def order(char):
        if char == "~":
            return -1
        if not char:
            return 0
        if char.isalpha():
            return ord(char)
        return ord(char) + 256

    while i < len(left) or j < len(right):
        while (i < len(left) and not left[i].isdigit()) or (j < len(right) and not right[j].isdigit()):
            a = left[i] if i < len(left) and not left[i].isdigit() else ""
            b = right[j] if j < len(right) and not right[j].isdigit() else ""
            if order(a) != order(b):
                return -1 if order(a) < order(b) else 1
            if a:
                i += 1
            if b:
                j += 1
        while i < len(left) and left[i] == "0":
            i += 1
        while j < len(right) and right[j] == "0":
            j += 1
        first_difference = 0
        while i < len(left) and j < len(right) and left[i].isdigit() and right[j].isdigit():
            if first_difference == 0:
                first_difference = ord(left[i]) - ord(right[j])
            i += 1
            j += 1
        if i < len(left) and left[i].isdigit():
            return 1
        if j < len(right) and right[j].isdigit():
            return -1
        if first_difference:
            return -1 if first_difference < 0 else 1
    return 0


def debian_version_compare(left, right):
    left_epoch, left_upstream, left_revision = debian_version_parts(left)
    right_epoch, right_upstream, right_revision = debian_version_parts(right)
    if left_epoch != right_epoch:
        return -1 if left_epoch < right_epoch else 1
    upstream = verrevcmp(left_upstream, right_upstream)
    return upstream or verrevcmp(left_revision, right_revision)
