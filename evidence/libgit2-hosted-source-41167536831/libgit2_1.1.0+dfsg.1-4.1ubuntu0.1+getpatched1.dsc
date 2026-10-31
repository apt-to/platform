Format: 3.0 (quilt)
Source: libgit2
Binary: libgit2-dev, libgit2-1.1, libgit2-fixtures
Architecture: any all
Version: 1.1.0+dfsg.1-4.1ubuntu0.1+getpatched1
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Uploaders: Pirate Praveen <praveen@debian.org>
Homepage: https://libgit2.github.com/
Standards-Version: 4.5.1
Vcs-Browser: https://salsa.debian.org/debian/libgit2
Vcs-Git: https://salsa.debian.org/debian/libgit2.git
Testsuite: autopkgtest
Testsuite-Triggers: cmake, g++, gcc
Build-Depends: debhelper-compat (= 12), python3-minimal:any, pkg-config, ca-certificates, cmake, zlib1g-dev, libmbedtls-dev, libssh2-1-dev, libhttp-parser-dev, libpcre3-dev, libkrb5-dev
Package-List:
 libgit2-1.1 deb libs optional arch=any
 libgit2-dev deb libdevel optional arch=any
 libgit2-fixtures deb libs optional arch=all
Checksums-Sha1:
 b32593dbbf0e7a382118cc144cb9bcb4c22f33a7 2901284 libgit2_1.1.0+dfsg.1.orig.tar.xz
 d89169ee4c01ec13a1b0fa36f09c0495aea77728 30484 libgit2_1.1.0+dfsg.1-4.1ubuntu0.1+getpatched1.debian.tar.xz
Checksums-Sha256:
 d3eba7909c5df1023c25a44ead8ee97cfc36da91a84ca50837d90f4521cf4e04 2901284 libgit2_1.1.0+dfsg.1.orig.tar.xz
 6786e26b0559e0c7e21d45f4f450cb16e1b3ec0fcc9c4142a37eda6f6f614a7d 30484 libgit2_1.1.0+dfsg.1-4.1ubuntu0.1+getpatched1.debian.tar.xz
Files:
 950f6512ff615d6ad968b6f26eafff57 2901284 libgit2_1.1.0+dfsg.1.orig.tar.xz
 137d92cfb5e7b9c15ea98331010a2e71 30484 libgit2_1.1.0+dfsg.1-4.1ubuntu0.1+getpatched1.debian.tar.xz
Original-Maintainer: Utkarsh Gupta <utkarsh@debian.org>
