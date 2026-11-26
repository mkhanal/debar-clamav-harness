#!/bin/sh
set -eu

reference_image="clamav/clamav-debian:1.5.4@sha256:cce3e1a43ae2bb40e11335c52c0e1e98273b12fa3d587e617f63a6907cc4b70b"
repository="$(cd "$(dirname "$0")/.." && pwd)"
toolchain_image="${BUILDER_TOOLCHAIN_IMAGE:-$(cat "$repository/toolchain-image")}"

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <empty work directory> (sample: EXTENDED_SAMPLE, LOGICAL_SAMPLE, SAMPLE_SEED, SAMPLE_TARGET, BOUNDARY_SAMPLE)" >&2
    exit 2
fi
mkdir -p "$1"
work_directory="$(cd "$1" && pwd)"
chmod 777 "$work_directory"

"$repository/builder/build-inputs.sh" "$work_directory"

docker run --rm --entrypoint clamscan \
    --volume "$work_directory:/work" "$reference_image" \
    --allmatch --no-summary --disable-cache --recursive /work/sample/inputs \
    > "$work_directory/scan-output.txt" || [ "$?" -eq 1 ]

docker run --rm \
    --volume "$work_directory:/work" \
    "$toolchain_image" /work/target/release/builder check \
        --manifest /work/sample/manifest.tsv \
        --scan-output /work/scan-output.txt \
        --failures /work/failures.tsv
