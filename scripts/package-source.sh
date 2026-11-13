#!/bin/sh
set -eu

usage() {
    printf 'Usage: %s TAG [OUTPUT_DIR]\n' "${0##*/}" >&2
    exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
ref=$1
case "$ref" in
    -*|*..*|*\ *) printf 'Invalid tag/ref: %s\n' "$ref" >&2; exit 2 ;;
esac

repo_root=$(git rev-parse --show-toplevel)
git -C "$repo_root" rev-parse --verify --quiet "refs/tags/$ref^{commit}" >/dev/null || {
    printf 'Tag does not exist: %s\n' "$ref" >&2
    exit 1
}

output_dir=${2:-"$repo_root/target/release-artifacts"}
mkdir -p "$output_dir"
case "$output_dir" in
    /*) ;;
    *) output_dir="$PWD/$output_dir" ;;
esac
archive="$output_dir/persona-$ref.tar.gz"
manifest="$output_dir/SHA256SUMS"
[ ! -e "$archive" ] && [ ! -e "$manifest" ] || {
    printf 'Refusing to overwrite existing release artifacts in %s\n' "$output_dir" >&2
    exit 1
}

temporary_tar="$output_dir/.persona-$ref.tar.$$"
temporary_archive="$archive.tmp.$$"
temporary_manifest="$manifest.tmp.$$"
trap 'rm -f "$temporary_tar" "$temporary_archive" "$temporary_manifest"' EXIT HUP INT TERM

git -C "$repo_root" archive --format=tar --prefix="persona-$ref/" "refs/tags/$ref" > "$temporary_tar"
gzip -n < "$temporary_tar" > "$temporary_archive"
(
    cd "$output_dir"
    shasum -a 256 "${temporary_archive##*/}" | sed "s|${temporary_archive##*/}|${archive##*/}|" > "$temporary_manifest"
)
mv "$temporary_archive" "$archive"
mv "$temporary_manifest" "$manifest"
rm -f "$temporary_tar"
printf 'Archive: %s\nChecksums: %s\n' "$archive" "$manifest"
