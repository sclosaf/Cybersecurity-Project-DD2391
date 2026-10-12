#!/usr/bin/env bash
set -uo pipefail

DATASET_DIR="datasets"
VOLUME_SIZE="90m"
MAX_SIZE=$((90 * 1024 * 1024))

total=0
success=0
failed=0
too_large=0
skipped=0

while IFS= read -r -d '' file; do
    archive="${file}.7z"
    ((total += 1))

    if [[ -f "${archive}.001" ]]; then
        echo "SKIP Existing multi-volume archive: ${archive}.001"
        ((skipped += 1))
        continue
    fi

    echo
    echo "[$total] Compressing: $file"

    tmpdir=$(mktemp -d) || {
        echo "ERROR Cannot create temporary directory"
        ((failed += 1))
        continue
    }

    tmp_archive="${tmpdir}/$(basename "$archive")"

    if ! 7z a -t7z -mx=5 "-v${VOLUME_SIZE}" \
        "$tmp_archive" "$file" -bsp1; then
        echo "ERROR Compression failed: $file"
        rm -rf -- "$tmpdir"
        ((failed += 1))
        continue
    fi

    shopt -s nullglob
    parts=("$tmp_archive".[0-9]*)
    shopt -u nullglob

    if ((${#parts[@]} == 0)); then
        echo "ERROR No archive volumes generated: $file"
        rm -rf -- "$tmpdir"
        ((failed += 1))
        continue
    fi

    if ! 7z t "${tmp_archive}.001" >/dev/null; then
        echo "ERROR Verification failed: $file"
        rm -rf -- "$tmpdir"
        ((failed += 1))
        continue
    fi

    part_count=${#parts[@]}
    oversized=0

    for part in "${parts[@]}"; do
        size=$(stat -c '%s' "$part")

        if ((size >= MAX_SIZE)); then
            echo "LARGE $part ($(du -h "$part" | cut -f1))"
            oversized=1
        fi
    done

    install_failed=0

    for part in "${parts[@]}"; do
        suffix="${part#"$tmp_archive"}"

        if ! mv -- "$part" "${archive}${suffix}"; then
            echo "ERROR Could not install volume: $part"
            install_failed=1
            break
        fi
    done

    rm -rf -- "$tmpdir"

    if ((install_failed)); then
        echo "ERROR Installation incomplete: $file"
        ((failed += 1))
        continue
    fi

    if ((oversized)); then
        ((too_large += 1))
        echo "WARNING Some volumes exceed the size limit: $file"
    else
        echo "OK Created $part_count volumes for $file"
    fi

    ((success += 1))

done < <(
    find "$DATASET_DIR" -type f \
        \( -iname '*.pcap' -o -iname '*.pcapng' \
           -o -iname '*.cap' -o -iname '*.csv' \) \
        -print0
)

echo
echo "Summary:"
echo "Files found:                  $total"
echo "Archives created:             $success"
echo "Failed:                       $failed"
echo "Archives with large volumes:  $too_large"
echo "Skipped existing archives:    $skipped"
