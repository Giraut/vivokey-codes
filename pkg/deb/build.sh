#!/bin/sh

# Directories and files
BUILDSCRIPTPATH=$(realpath "$0")
BUILDSCRIPTDIR=$(dirname ${BUILDSCRIPTPATH})
SRC=$(realpath ${BUILDSCRIPTDIR}/../..)
PKGSRC=${BUILDSCRIPTDIR}/vivokey-codes
VERSION=$(awk 'match($0, /^### Version +([0-9]+\.[0-9]+\.[0-9])+ *$/, m) {print m[1]}' ${SRC}/README.md)
PKGBUILD=${PKGSRC}-${VERSION}-0_all
PKG=${PKGBUILD}.deb

# Create a fresh skeleton package build directory
rm -rf ${PKGBUILD}
cp -a ${PKGSRC} ${PKGBUILD}

# Create empty directory structure
mkdir -p ${PKGBUILD}/usr/bin
mkdir -p ${PKGBUILD}/usr/share/icons
mkdir -p ${PKGBUILD}/etc/xdg/autostart
mkdir -p ${PKGBUILD}/usr/share/applications

# Populate the package build directory with the source files
install -m 644 ${SRC}/README.md ${PKGBUILD}/usr/share/doc/vivokey-codes
install -m 644 ${SRC}/LICENSE ${PKGBUILD}/usr/share/doc/vivokey-codes

install -m 755 ${SRC}/vivokey_codes.py ${PKGBUILD}/usr/bin/vivokey_codes
install -m 644 ${SRC}/vivokey_codes.png ${PKGBUILD}/usr/share/icons
install -m 644 ${SRC}/vivokey_codes.desktop ${PKGBUILD}/etc/xdg/autostart
install -m 644 ${SRC}/vivokey_codes.desktop ${PKGBUILD}/usr/share/applications

# Set the version in the control file
sed -i "s/^Version:.*\$/Version: ${VERSION}/" ${PKGBUILD}/DEBIAN/control

# Fixup permissions
find ${PKGBUILD} -type d -exec chmod 755 {} \;
chmod 644 ${PKGBUILD}/DEBIAN/control
chmod 644 ${PKGBUILD}/usr/share/doc/vivokey-codes/copyright

# Build the .deb package
fakeroot dpkg -b ${PKGBUILD} ${PKG}
