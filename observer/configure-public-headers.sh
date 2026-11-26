#!/bin/sh
set -eu

source_directory="$1"
include_directory="$2"

sed \
    -e 's|@GENERATE_WARNING@||' \
    -e 's|@INT_TYPES_HEADER@|#include <inttypes.h>|' \
    -e 's|@U\{0,1\}INT[0-9]*_DEF@||' \
    -e 's|@DEFINE_SF64_PREFIX@|#define _SF64_PREFIX "l"|' \
    -e 's|@DEFINE_SF32_PREFIX@|#define _SF32_PREFIX ""|' \
    "$source_directory/clamav-types.h.in" > "$include_directory/clamav-types.h"

sed \
    -e 's|@GENERATE_WARNING@||' \
    -e 's|@PACKAGE_VERSION@|1.5.4|' \
    -e 's|@PACKAGE_VERSION_NUM@|0x010504|' \
    -e 's|@LIBCLAMAV_VERSION@|12.1.0|' \
    -e 's|@LIBCLAMAV_VERSION_NUM@|0x0d0001|' \
    -e 's|@LIBFRESHCLAM_VERSION@|4.0.0|' \
    -e 's|@LIBFRESHCLAM_VERSION_NUM@|0x040000|' \
    "$source_directory/clamav-version.h.in" > "$include_directory/clamav-version.h"

cp "$source_directory/libclamav/clamav.h" "$include_directory/clamav.h"

if grep -n '@[A-Z0-9_]*@' "$include_directory"/*.h; then
    echo "configure-public-headers: a placeholder above was left unconfigured" >&2
    exit 1
fi
